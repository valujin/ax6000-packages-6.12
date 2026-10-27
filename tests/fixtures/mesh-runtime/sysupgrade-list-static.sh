# SPDX-License-Identifier: GPL-2.0-only
# Exact selector from OpenWrt package/base-files/files/sbin/sysupgrade,
# native source ae65e1de69971b5a2e3cf7e39390ee93f274d488.
# Full source SHA256 e0869c54bc74344cf6f9911e94980a3446b09782929d42e00269aedad0e37c80.
list_static_conffiles() {
	local filter=$1

	find $(sed -ne '/^[[:space:]]*$/d; /^#/d; p' \
		/etc/sysupgrade.conf /lib/upgrade/keep.d/* 2>/dev/null) \
		\( -type f -o -type l \) $filter 2>/dev/null
}
