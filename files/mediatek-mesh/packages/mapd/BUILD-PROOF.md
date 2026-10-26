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

## Native driver compile and wire ABI follow-up

A private copy of the prepared Linux 6.12.108 kernel and already-patched
mt_wifi 7.6.7.3 source was built with the recommended GCC 14.3.0 cross
compiler. The pinned driver recipe's complete `PKG_KCONFIG` mapping was
reproduced from the recommended configuration, with `CONFIG_MAP_SUPPORT`,
`CONFIG_MAP_R2_VER_SUPPORT`, `CONFIG_MAP_R3_VER_SUPPORT`,
`CONFIG_MAP_R2_6E_SUPPORT`, `CONFIG_MAP_R3_6E_SUPPORT`, and
`CONFIG_DFS_SLAVE_SUPPORT` set to `y`. The build used `make -j1`, a 2 GiB process address-space
limit, and the recommended dependency symbol tables read-only. All driver
objects were rebuilt in scratch. `MODPOST` and linking passed for both
`mt_wifi.ko` and `mtk_warp_proxy.ko`; both are AArch64 modules with vermagic
`6.12.108 SMP mod_unload aarch64`.

This actual compilation corrected an earlier assumption: the native
`mt_wifi_ap/Makefile` does not consume the `MAP_MLO_UPLINK` flag from
`os/linux/config_ap.mk`. The persistent source patch therefore adds
`EXTRA_CFLAGS += -DMAP_MLO_UPLINK` inside the native Makefile's
`CONFIG_MAP_SUPPORT` block. The newly enabled DFS code also needed its
`UpdateBeaconHandler` early return changed from `return NDIS_STATUS_SUCCESS;`
to `return;`, because that function returns `VOID`. These exact two source
changes were present in the successful private build.

A small driver translation unit used the actual saved native compiler
arguments, changing only source/output paths and debug-information emission.
Its DWARF was compared with the final WAPP object: all 73 shared named
WAPP-header record sizes/member offsets/bitfields and all 123 shared protocol
enum values matched. This checks the actual driver definitions, including
MAP R2/R3, MAP 6E/R3 6E, DFS and the explicit MLO uplink wire-format flag;
header identity alone was not treated as sufficient ABI evidence.

These checks compile and inspect modules; they do not load them or establish
wireless, roaming, or hardware interoperability results. Native OpenWrt
package/image assembly remains a separate integration check.
