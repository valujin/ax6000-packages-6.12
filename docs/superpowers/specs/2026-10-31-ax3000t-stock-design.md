# Xiaomi AX3000T stock firmware

User requested a build for MediaTek MT7981 RD03/RD23 with stock layout and explicitly confirmed our MediaTek EasyMesh interface must support joining AX6000. Use the existing recommended ImmortalWrt 25.12 / Linux 6.12.108 source and vendor 7.6.7.3 driver, with MT7981 chip/firmware configuration. APK, existing recommended router/VPN UI, Argon and Russian translations remain; ASU and built-in Tailscale remain excluded.

Native cached source build is selected because the stock initramfs factory artifact is unavailable in ImageBuilder and MT7986 vendor binaries are incompatible. Produce stock sysupgrade.bin, initramfs-factory.ubi, initramfs-kernel.bin, SHA256 checksums, a reproducible config/provenance record and concise installation notes. Do not replace U-Boot or flash any existing router.

Adapt hardware identity and DAT/radio paths centrally in Mesh; preserve AX6000 behavior and its MU-MIMO fix. Agent/controller native daemons must be built against the MT7981 driver ABI. Managed guest traffic-separation support remains proof-gated; existing AX6000 hardware evidence cannot authorize AX3000T. Do not embed AX6000 kernel/vendor repositories or an installer claiming this is an AX6000 image.

Build in an isolated local copy, preserving prior source/SDK and running services. Native build and artifact validation prove the delivered build, not hardware boot or RF interoperability; report any untested hardware limitations plainly.
