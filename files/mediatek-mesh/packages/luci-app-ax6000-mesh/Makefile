include $(TOPDIR)/rules.mk

PKG_VERSION:=20261027
PKG_RELEASE:=6
PKG_LICENSE:=GPL-2.0-only
LUCI_TITLE:=MediaTek EasyMesh for Redmi AX6000
LUCI_DEPENDS:=+luci-base +luci-mod-network +ax6000-mesh
LUCI_EXTRA_DEPENDS:=luci-mod-network (>=26.249.28459~d6167ea-r2), ax6000-mesh (>=1-r9)
LUCI_PKGARCH:=all

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
