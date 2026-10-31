# MediaTek Mesh source and native image requirements

The standard Wireless page extension is built into the existing
`luci-mod-network` package. The addon does not install or replace that package's
files. The authenticated `patches/luci-wireless-mesh.patch` covers its page,
read-only RPC ACL and package Makefile, with exact source preimage/postimage
hashes and the immutable LuCI feed pin in `luci-wireless-manifest.json`.

The patched core package has the literal native version
`26.249.28459~d6167ea-r2`:

```make
PKG_VERSION:=26.249.28459~d6167ea
PKG_RELEASE:=2
```

Both assignments are required. The pinned `luci.mk` ignores `PKG_RELEASE` for
its default Git-derived package version when `PKG_VERSION` is absent. The
literal version is independent of Git availability, source timestamps and
producer location, and is greater than the old native package version
`26.249.28459~d6167ea` under the trusted APK comparator.

A final native generation must apply the authenticated patch in its isolated
producer checkout, refresh package metadata, and explicitly clean/reprepare and
rebuild `luci-mod-network` before generating images and the SDK. Its build
directory has a fixed package name, so a release change alone is insufficient
evidence that an old prepared tree or APK was replaced. Use the native
producer's package clean/compile targets; never clean or write the retained SDK
or a running build. Verify the genuine APK's name/version/control and its actual
installed minified page and verbatim ACL. All three layout images must contain
the new version and exact postimages. `mediatek_mesh.expected()` enforces the
version and image files; the existing native minifier check enforces JS bytes.

`luci-mod-network` belongs to the existing protected native dependency closure.
Keep that protection and exact world pins. Existing firmware retains its old
pin and does not acquire this changed core through a supplemental feed upgrade.
Publish this change through a newly verified native generation with its own
producer identity, images, core APK, regenerated SDK baseline and protected
package pins. Do not relabel an old archive, rewrite old receipts, unpin the
installed core, or claim that an existing feed/SDK accepts this changed package.
A backed-up hardware-test page overlay is test evidence only; final publication
requires the genuine rebuilt core APK and new native proof.

The runtime recognizes Xiaomi AX3000T stock-layout (`xiaomi,mi-router-ax3000t`) and the existing Redmi AX6000 variants. It verifies the MediaTek l1profile chip and both DAT paths before use and checks radio identities during setup. The AX3000T uses MT7981 DATs; the AX6000 uses MT7986 DATs. Mesh is disabled initially. Managed guest traffic separation remains restricted to the packet-tested AX6000 capability and is not established on AX3000T. Physical pairing and interoperability require hardware validation.
