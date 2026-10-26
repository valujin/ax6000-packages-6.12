# MediaTek EasyMesh for the recommended AX6000 firmware

The user requested the proprietary MediaTek Mesh implementation and a convenient LuCI interface, and confirmed that all nodes will be Redmi AX6000 running our firmware. Only recommended ImmortalWrt 25.12 / Linux 6.12 / APK remains enabled, with ASU absent and Tailscale package-only.

Use the matched MediaTek 2025 Wi-Fi SDK userspace stack (wapp, mapd, IEEE 1905 daemon, libmapd) with the actual mt_wifi 7.6.7.3 driver ABI. The existing exported Linux WAPP header is stale: compare and compile against the driver header and its feature flags. Do not substitute 802.11s or label band steering alone as Mesh.

Expose Network → MediaTek Mesh with disabled-by-default controller/agent roles, wired/wireless backhaul, daemon status, onboarding, and disable/restore controls. Use existing wireless SSID and credentials, reject unsupported radio/bridge/encryption configurations with specific guidance. Additional nodes must have DHCP serving disabled and distinct management addresses before activation; do not silently change WAN, firewall or LAN addressing.

Own startup and shutdown with procd; do not run the legacy vendor startup script that rewrites network/firewall. Preserve wireless configuration before enabling, coordinate daemon-owned credentials with mtwifi-cfg-ucode on reload, and restore on disable. Protect generated credentials, restrict RPC actions and avoid arbitrary commands. Preserve upstream notices. Pin every external input and verify downloaded hashes.

Implementation: (1) matched packages and ABI/cross-build checks; (2) narrow tested mtwifi UCI/DAT ownership patch; (3) lifecycle and RPC; (4) LuCI; (5) source/profile/native image verification; (6) independent review, bounded tests, CI and recommended firmware build. Hardware onboarding/roaming tests require two physical devices and must be reported separately from build/test results.
