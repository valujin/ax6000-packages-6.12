include $(TOPDIR)/rules.mk

PKG_NAME:=ax6000-mesh
PKG_VERSION:=1
PKG_RELEASE:=2

ifneq ($(wildcard $(TOPDIR)/ax6000-baseline/manifest.json),)
# Keep the authenticated native module at runtime without rebuilding it in SDKs.
MAPFILTER_EXTRA_DEPENDS:=kmod-mapfilter (=6.12.108.3.0.1.2-r1)
else
MAPFILTER_DEPENDS:=+kmod-mapfilter
endif

include $(INCLUDE_DIR)/package.mk

define Package/ax6000-mesh
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AX6000 MediaTek EasyMesh service
  DEPENDS:=+mapd +datconf +wireless-tools +uci +rpcd +jshn +libubox $(MAPFILTER_DEPENDS) +coreutils-timeout +coreutils-stat +ip-full +jsonfilter
  EXTRA_DEPENDS:=$(MAPFILTER_EXTRA_DEPENDS)
endef

define Package/ax6000-mesh/conffiles
/etc/config/ax6000_mesh
endef

define Build/Compile
endef

define Package/ax6000-mesh/install
	$(CP) ./files/* $(1)/
	$(INSTALL_BIN) ./files/etc/init.d/* $(1)/etc/init.d/
	$(INSTALL_BIN) ./files/usr/libexec/ax6000-mesh-* $(1)/usr/libexec/
	$(INSTALL_BIN) ./files/usr/bin/* $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/libexec/rpcd/ax6000.mesh $(1)/usr/libexec/rpcd/ax6000.mesh
endef

$(eval $(call BuildPackage,ax6000-mesh))
