# Vendor SDK 20250408 components; see SOURCE-NOTICE for licensing evidence.
include $(TOPDIR)/rules.mk

PKG_NAME:=libmapd
PKG_VERSION:=3.0.2.0
PKG_RELEASE:=1
PKG_SOURCE_VERSION:=0132d199
PKG_SOURCE:=libmapd-0132d199.tar.bz2
PKG_SOURCE_URL:=https://raw.githubusercontent.com/immortalwrt-mt798x/immortalwrt/a3f94baa4ea053130be796915ad9ff2fa5fcf567/dl
PKG_HASH:=d325b4a8dc2bf44bd3bd639a0c300380c0a6240f407807f8f2eea80d006c8dba
PKG_BUILD_DIR:=$(BUILD_DIR)/libmapd
PKG_BUILD_DEPENDS:=
PKG_BUILD_PARALLEL:=0
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

TARGET_CFLAGS += -DCONFIG_SUPPORT_OPENWRT -D_GNU_SOURCE -fcommon -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types
MAKE_FLAGS += CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y CONFIG_MTK_MAP_R2_6E_SUPPORT=y CONFIG_MTK_MAP_R3_6E_SUPPORT=y CONFIG_MTK_DFS_SLAVE_SUPPORT=y

define Package/libmapd
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MediaTek libmapd for the AX6000 vendor driver
  DEPENDS:=+libgcc
endef

TARGET_CFLAGS += $(FPIC) -DSUPPORT_MULTI_AP -DMAP_R2 -DMAP_R3 -DMAP_6E_SUPPORT

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/include $(1)/usr/lib
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/include/mapd_interface_ctrl.h $(1)/usr/include/
	$(CP) $(PKG_BUILD_DIR)/libmapd_interface_client.so* $(1)/usr/lib/
endef

define Package/libmapd/install
	$(INSTALL_DIR) $(1)/usr/lib $(1)/usr/share/licenses/libmapd
	$(CP) $(PKG_BUILD_DIR)/libmapd_interface_client.so* $(1)/usr/lib/
	$(INSTALL_DATA) ./SOURCE-NOTICE $(1)/usr/share/licenses/libmapd/
endef

$(eval $(call BuildPackage,libmapd))
