# Vendor SDK 20250408 components; see SOURCE-NOTICE for licensing evidence.
include $(TOPDIR)/rules.mk

PKG_NAME:=wappd
PKG_VERSION:=3.0.2.0
PKG_RELEASE:=6
PKG_SOURCE_VERSION:=80ca5724
PKG_SOURCE:=wappd-80ca5724.tar.bz2
PKG_SOURCE_URL:=https://raw.githubusercontent.com/immortalwrt-mt798x/immortalwrt/a3f94baa4ea053130be796915ad9ff2fa5fcf567/dl
PKG_HASH:=73fa8995533e701d3d5774faa92d274497f99e1a37c81ce445f25a959b4b7462
PKG_BUILD_DIR:=$(BUILD_DIR)/wappd
ifneq ($(wildcard $(TOPDIR)/ax6000-baseline/manifest.json),)
# The authenticated SDK carries the exact native ABI, not external driver source.
PKG_BUILD_DEPENDS:=datconf
# EXTRA_DEPENDS keeps the authenticated runtime requirement without an SDK
# compile edge into the protected native vendor module.
WAPP_DRIVER_EXTRA_DEPENDS:=kmod-mt_wifi (=6.12.108.7.6.7.3-r2)
WAPP_DRIVER_UAPI=$(TOPDIR)/ax6000-baseline/mesh-uapi/wapp_cmm_type.h
WAPP_OID_UAPI=$(TOPDIR)/ax6000-baseline/mesh-uapi/mt_wlan_cmm_oid.h
else
PKG_BUILD_DEPENDS:=mt_wifi datconf
WAPP_DRIVER_DEPENDS:=+kmod-mt_wifi
WAPP_DRIVER_UAPI=$(KERNEL_BUILD_DIR)/mt_wifi/mt_wifi/embedded/include/wapp/wapp_cmm_type.h
WAPP_OID_UAPI=$(LINUX_DIR)/include/uapi/linux/wapp/mt_wlan_cmm_oid.h
endif
PKG_BUILD_PARALLEL:=0
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

TARGET_CFLAGS += -DCONFIG_SUPPORT_OPENWRT -D_GNU_SOURCE -fcommon -Wno-error=implicit-function-declaration -Wno-error=incompatible-pointer-types
MAKE_FLAGS += CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_R2_SUPPORT=y CONFIG_MAP_R3_SUPPORT=y CONFIG_MTK_MAP_R2_6E_SUPPORT=y CONFIG_MTK_MAP_R3_6E_SUPPORT=y CONFIG_MTK_DFS_SLAVE_SUPPORT=y

define Package/wapp
  SECTION:=net
  CATEGORY:=Network
  TITLE:=MediaTek wapp for the AX6000 vendor driver
  DEPENDS:=+libgcc $(WAPP_DRIVER_DEPENDS) +libkvcutil +libopenssl +libuci
  EXTRA_DEPENDS:=$(WAPP_DRIVER_EXTRA_DEPENDS)
endef

# The kernel-exported WAPP header is stale in the pinned firmware tree.
# Read the actual compiled driver header into this package only.
define Build/Prepare
	$(call Build/Prepare/Default)
	echo "821fa92e0b2f044928af64e420a4f1735635e7567f312add971c9d715da13898  $(WAPP_DRIVER_UAPI)" | sha256sum -c -
	echo "a11e84592439326bb7d6cc6cc8e4dd1eec4f570b6c31e0bce041039c5ddae5b9  $(WAPP_OID_UAPI)" | sha256sum -c -
	$(INSTALL_DIR) $(PKG_BUILD_DIR)/driver-uapi
	$(CP) $(WAPP_DRIVER_UAPI) $(PKG_BUILD_DIR)/driver-uapi/
	$(CP) $(WAPP_OID_UAPI) $(PKG_BUILD_DIR)/driver-uapi/
endef

TARGET_CFLAGS += -DASSOC_REQ_LEN_MAX=ASSOC_REQ_LEN
MAKE_FLAGS += UAPD_INCLUDE_PATH=$(PKG_BUILD_DIR)/driver-uapi

define Build/InstallDev
	$(INSTALL_DIR) $(1)/usr/lib
	$(CP) $(PKG_BUILD_DIR)/libwapp_usr_intf_client.a $(1)/usr/lib/
	$(INSTALL_DIR) $(1)/usr/include/mediatek/wapp/include $(1)/usr/include/mediatek/wapp/wapp_usr_intf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/include/*.h $(1)/usr/include/mediatek/wapp/include/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/wapp_usr_intf/*.h $(1)/usr/include/mediatek/wapp/wapp_usr_intf/
endef

define Package/wapp/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/usr/share/ax6000-mesh/vendor
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wapp $(PKG_BUILD_DIR)/wappctrl $(1)/usr/bin/
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/config_and_icon_files/wapp_ap_ra0.conf $(PKG_BUILD_DIR)/config_and_icon_files/wapp_ap_rax0.conf $(1)/usr/share/ax6000-mesh/vendor/
	$(INSTALL_DIR) $(1)/usr/share/licenses/wapp
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE ./SOURCE-NOTICE $(1)/usr/share/licenses/wapp/
endef

$(eval $(call BuildPackage,wapp))
