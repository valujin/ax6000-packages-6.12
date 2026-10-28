# Vendor SDK 20250408 components; see SOURCE-NOTICE for licensing evidence.
include $(TOPDIR)/rules.mk

PKG_NAME:=mapd
PKG_VERSION:=3.0.2.0
PKG_RELEASE:=3
PKG_SOURCE_VERSION:=6eca4331
PKG_SOURCE:=mapd-6eca4331.tar.bz2
PKG_SOURCE_URL:=https://raw.githubusercontent.com/immortalwrt-mt798x/immortalwrt/a3f94baa4ea053130be796915ad9ff2fa5fcf567/dl
PKG_HASH:=39ab37cb347d372e352ade03181bc9c23429d4d849d32acbdff00973547d7e18
PKG_BUILD_DIR:=$(BUILD_DIR)/mapd
PKG_BUILD_DEPENDS:=wapp 1905daemon libmapd
PKG_BUILD_PARALLEL:=0
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

TARGET_CFLAGS += -DCONFIG_SUPPORT_OPENWRT -D_GNU_SOURCE -fcommon -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types
MAKE_FLAGS += CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y CONFIG_MTK_MAP_R2_6E_SUPPORT=y CONFIG_MTK_MAP_R3_6E_SUPPORT=y CONFIG_MTK_DFS_SLAVE_SUPPORT=y

define Package/mapd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MediaTek mapd for the AX6000 vendor driver
  DEPENDS:=+libgcc +wapp +1905daemon +libmapd
endef

# Build only the daemons used by the managed runtime.
MAKE_FLAGS += -j1
MAKE_PATH:=.

define Build/Compile
	$(call Build/Compile/Default,mapd mapd_cli)
endef

define Package/mapd/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/ax6000-mesh/vendor
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mapd $(PKG_BUILD_DIR)/mapd_cli $(1)/usr/bin/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wts_bss_info_config $(PKG_BUILD_DIR)/mapd_default.cfg $(PKG_BUILD_DIR)/mapd_user.cfg $(1)/usr/share/ax6000-mesh/vendor/
	$(INSTALL_DIR) $(1)/usr/share/licenses/mapd
	$(INSTALL_DATA) ./SOURCE-NOTICE $(1)/usr/share/licenses/mapd/
endef

$(eval $(call BuildPackage,mapd))
