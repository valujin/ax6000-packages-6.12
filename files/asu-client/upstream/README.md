These files are unmodified GPL-2.0 source from the pinned ImmortalWrt feeds.
`provenance.json` records each upstream repository, commit, path and byte hash.
The helper verifies these exact preimages before applying its narrow client patch.
A feed update that changes an affected file requires a reviewed preimage update;
unknown or partially patched source fails closed. Russian translations remain
those in the same pinned `luci-app-attendedsysupgrade/po/ru` source directory.
The resulting package release is incremented to `2.ax6000asu2` in both the LuCI
application and `attendedsysupgrade-common`.

The 6.12 client reads the existing APK-capable `rpc-sys.packagelist` RPC with
`all=true`. It does not run APK commands in the browser or convert an OPKG
installation. Runtime database presence must agree with the root-owned cohort
metadata. The source package manager is sent separately from the selected target
identity; a server can therefore reject old clients lacking this assertion.
