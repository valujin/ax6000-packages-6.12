# Vendor SDK 20250408 components; see SOURCE-NOTICE for licensing evidence.
include $(TOPDIR)/rules.mk

PKG_NAME:=1905daemon
PKG_VERSION:=3.0.2.0
PKG_RELEASE:=1
PKG_SOURCE_VERSION:=35234223
PKG_SOURCE:=1905daemon-35234223.tar.bz2
PKG_SOURCE_URL:=https://raw.githubusercontent.com/immortalwrt-mt798x/immortalwrt/a3f94baa4ea053130be796915ad9ff2fa5fcf567/dl
PKG_HASH:=82f7cc4ad5731e750f87c9a4ad19a39d2456bb8fec0cf79bf4b3f3ccb4f14795
PKG_BUILD_DIR:=$(BUILD_DIR)/1905daemon
PKG_BUILD_DEPENDS:=wapp

ifneq ($(wildcard $(TOPDIR)/ax6000-baseline/manifest.json),)
# Keep the authenticated native module at runtime without rebuilding it in SDKs.
MAPFILTER_EXTRA_DEPENDS:=kmod-mapfilter (=6.12.108.3.0.1.2-r1)
else
MAPFILTER_DEPENDS:=+kmod-mapfilter
endif
PKG_BUILD_PARALLEL:=0
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

TARGET_CFLAGS += -DCONFIG_SUPPORT_OPENWRT -D_GNU_SOURCE -fcommon -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types
MAKE_FLAGS += CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y CONFIG_MTK_MAP_R2_6E_SUPPORT=y CONFIG_MTK_MAP_R3_6E_SUPPORT=y CONFIG_MTK_DFS_SLAVE_SUPPORT=y

define Package/1905daemon
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MediaTek 1905daemon for the AX6000 vendor driver
  DEPENDS:=+libgcc +wapp +libnl-tiny +libopenssl +ip-bridge $(MAPFILTER_DEPENDS)
  EXTRA_DEPENDS:=$(MAPFILTER_EXTRA_DEPENDS)
endef

MAKE_FLAGS += SWTICH_DSA_ARCH=y PLANTFORM_DISABLE_GENL_NETLINK=y
TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include/libnl-tiny
TARGET_LDFLAGS += -lnl-tiny -lm

define Package/1905daemon/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/lib $(1)/usr/share/ax6000-mesh/vendor
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/p1905_managerd $(PKG_BUILD_DIR)/1905ctrl $(1)/usr/bin/
	$(CP) $(PKG_BUILD_DIR)/ethernet/libeth_1905ops.so* $(1)/usr/lib/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/1905d.cfg $(PKG_BUILD_DIR)/ethernet_cfg.txt $(PKG_BUILD_DIR)/1905_dpp_keys.txt $(1)/usr/share/ax6000-mesh/vendor/
	$(INSTALL_DIR) $(1)/usr/share/licenses/1905daemon
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE ./SOURCE-NOTICE $(1)/usr/share/licenses/1905daemon/
endef

$(eval $(call BuildPackage,1905daemon))
