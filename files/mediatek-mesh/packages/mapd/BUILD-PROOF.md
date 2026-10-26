# SDK 20250408 userspace verification

Verified 2026-10-27 against the recommended source commit
`ae65e1de69971b5a2e3cf7e39390ee93f274d488`, AArch64 Cortex-A53 musl,
GCC 14.3.0 and its staged OpenSSL 3 libraries. These are cross-build and ABI
checks; no router, wireless backhaul, roaming, or interoperability test was run.

The four archives pinned by the adjacent recipes were extracted into fresh
private scratch directories. Each compatibility patch applied with
`patch --batch --fuzz=0 -p1`. The patched contents matched the reviewed sources.
Builds ran serially with a 2 GiB process address-space limit and used the
existing toolchain/staging directories read-only. All four builds passed:

| Package | Targets checked | ELF results |
|---|---|---|
| wapp | upstream default | `wapp`, `wappctrl`, AArch64 |
| 1905daemon | upstream default | `p1905_managerd`, `1905ctrl`, `libeth_1905ops.so`, AArch64 |
| libmapd | upstream default | `libmapd_interface_client.so`, AArch64 |
| mapd | `mapd mapd_cli` | both AArch64; optional sample and standalone steering omitted |

Build inputs were `make -j1`, the recommended `aarch64-openwrt-linux-musl-`
CC/AR/RANLIB, `TOPDIR` pointing to scratch, and these settings:

```
CONFIG_SUPPORT_OPENWRT=y
CONFIG_MAP_R2_SUPPORT=y
CONFIG_MAP_R3_SUPPORT=y
CONFIG_MTK_MAP_R2_6E_SUPPORT=y
CONFIG_MTK_MAP_R3_6E_SUPPORT=y
CONFIG_MTK_DFS_SLAVE_SUPPORT=y
SWTICH_DSA_ARCH=y
PLANTFORM_DISABLE_GENL_NETLINK=y
```

CFLAGS included `-O2 -DCONFIG_SUPPORT_OPENWRT -D_GNU_SOURCE -fcommon`,
target staging includes, and GCC 14 compatibility warning overrides from the
recipes. WAPP used `-DASSOC_REQ_LEN_MAX=ASSOC_REQ_LEN` and a private UAPI copy.
libmapd used `-DSUPPORT_MULTI_AP -DMAP_R2 -DMAP_R3 -DMAP_6E_SUPPORT`.
LDFLAGS selected the recommended target staging libraries and rpath-link.
The recipe feature flags select the vendor SDK layouts; this dual-band device
has no 6 GHz radio.

WAPP consumes the actual mt_wifi 7.6.7.3 driver header, SHA256
`821fa92e0b2f044928af64e420a4f1735635e7567f312add971c9d715da13898`.
The stale kernel-exported header is left unchanged. Compile-time assertions
check the wire structures: `map_vendor_ie=26`, scan BSS record `=126`,
`wapp_scan_info=6`, `wapp_event=248`, `wapp_client_info=95` bytes.

`verify-blob-abi.py BUILD_DIR/mapd` compared all shared named structure/union
sizes, ordinary member offsets, and normalized bitfield offsets against the
seven loose proprietary objects and the seven members of the two linked
archives. Every comparison passed (236–253 named layouts per object).
The archive members differ from the loose objects, so both were inspected.
Required layouts include `own_1905_device=342840`, `mapd_global=342960`,
`_1905_map_device=1072`, and `radio_info_db=1488` bytes. Source assertions also
check the client-array boundary and `DfsSlaveEn` offset. These detect the
otherwise linkable but wrong 100-client and non-6E variants.

ELF dependency inspection found libc/libgcc for all outputs, OpenSSL and
libkvcutil for WAPP, the packaged ethernet library for p1905_managerd, and
libmapd_interface_client for mapd_cli. Recipes include those dependencies.
Native OpenWrt package/image assembly and on-device validation remain separate
integration checks; this evidence does not claim they have completed.
