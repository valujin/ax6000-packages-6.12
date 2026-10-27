# SDK 20250408: wappd/map/map_1905.c fill_sec_info accepts WPA2PSK|SAE;
# mapd/wts_bss_info_config contains separate mixed FH and BH rows.
# 1905daemon/src/file_io.c maps the two role columns to BH bit6/FH bit5.
# _1905_lib_io.c assigns matching rows in bss_config_priority order.
# Keep this library sourced: credentials never become external command argv.

mesh_auth_code() {
  case "$1" in psk2) printf '0x0020' ;; sae-mixed) printf '0x0060' ;; *) return 1 ;; esac
}

mesh_validate_credentials() {
  [ "$#" = 3 ] || return 1
  case "$1$2" in *[![:print:]]*) return 1 ;; esac
  [ "${#1}" -ge 1 ] && [ "${#1}" -le 32 ] && [ "${#2}" -ge 8 ] && [ "${#2}" -le 63 ] || return 1
  mesh_auth_code "$3" >/dev/null
}

mesh_write_bss() {
  [ "$#" = 9 ] || return 1
  local output="$1" ssid24="$2" key24="$3" auth24="$4" ssid5="$5" key5="$6" auth5="$7" bh_ssid="$8" bh_key="$9"
  local band index=1 ssid key auth escaped_ssid escaped_key escaped_bh escaped_bhkey
  mesh_validate_credentials "$ssid24" "$key24" "$auth24" &&
    mesh_validate_credentials "$ssid5" "$key5" "$auth5" &&
    mesh_validate_credentials "$bh_ssid" "$bh_key" psk2 || return 1
  escaped_bh=$(printf '%s' "$bh_ssid" | sed 's/\\/\\\\/g; s/ /\\ /g')
  escaped_bhkey=$(printf '%s' "$bh_key" | sed 's/\\/\\\\/g; s/ /\\ /g')
  (umask 077; : > "$output") || return 1
  chmod 600 "$output" || return 1
  printf '#ucc_bss_info\n' > "$output" || return 1
  for band in 8x 11x 12x; do
    if [ "$band" = 8x ]; then ssid=$ssid24; key=$key24; auth=$auth24; else ssid=$ssid5; key=$key5; auth=$auth5; fi
    auth=$(mesh_auth_code "$auth") || return 1
    escaped_ssid=$(printf '%s' "$ssid" | sed 's/\\/\\\\/g; s/ /\\ /g')
    escaped_key=$(printf '%s' "$key" | sed 's/\\/\\\\/g; s/ /\\ /g')
    printf '%s,ff:ff:ff:ff:ff:ff %s %s %s 0x0008 %s 0 1 hidden-N 4095 N/A N/A\n' "$index" "$band" "$escaped_ssid" "$auth" "$escaped_key" >> "$output" || return 1
    index=$((index + 1))
    printf '%s,ff:ff:ff:ff:ff:ff %s %s 0x0020 0x0008 %s 1 0 hidden-Y 4095 N/A N/A\n' "$index" "$band" "$escaped_bh" "$escaped_bhkey" >> "$output" || return 1
    index=$((index + 1))
  done
}
