include $(TOPDIR)/rules.mk

PKG_NAME:=ax6000-mesh
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ax6000-mesh
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AX6000 MediaTek EasyMesh service
  DEPENDS:=+mapd +datconf +wireless-tools +uci +rpcd +jshn +libubox +kmod-mapfilter +coreutils-timeout +ip-full
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
