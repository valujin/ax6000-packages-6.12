# Matching MediaTek SDK 20250408 source; see SOURCE-NOTICE.
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=mapfilter
PKG_VERSION:=3.0.1.2
PKG_RELEASE:=1
PKG_SOURCE_VERSION:=96f2afed
PKG_SOURCE:=mapfilter-96f2afed.tar.bz2
PKG_SOURCE_URL:=https://raw.githubusercontent.com/immortalwrt-mt798x/immortalwrt/a3f94baa4ea053130be796915ad9ff2fa5fcf567/dl
PKG_HASH:=3928c6614b84e74f1f1762cee61de8e422299e792f5f363dc369dfc0ed0f1714
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/mapfilter
PKG_BUILD_PARALLEL:=0
PKG_LICENSE:=GPL-2.0

include $(INCLUDE_DIR)/package.mk

define KernelPackage/mapfilter
  SUBMENU:=Network Support
  TITLE:=MediaTek EasyMesh bridge filter and netlink endpoint
  DEPENDS:=@TARGET_mediatek_filogic
  KCONFIG:=CONFIG_BRIDGE=y CONFIG_NETFILTER=y CONFIG_NETFILTER_FAMILY_BRIDGE=y CONFIG_VLAN_8021Q=y
  FILES:=$(PKG_BUILD_DIR)/mapfilter.ko
endef

define KernelPackage/mapfilter/description
 MediaTek EasyMesh netlink protocol 26 and bridge hooks required by
 p1905_managerd and mapd. Loaded by the mesh service when enabled.
endef

define Build/Compile
	+$(KERNEL_MAKE) M="$(PKG_BUILD_DIR)" \
		CONFIG_SUPPORT_OPENWRT=y CONFIG_MAP_FILTER_SUPPORT=m modules
endef

define KernelPackage/mapfilter/install
	$(INSTALL_DIR) $(1)/usr/share/licenses/mapfilter
	$(INSTALL_DATA) ./SOURCE-NOTICE $(1)/usr/share/licenses/mapfilter/
endef

$(eval $(call KernelPackage,mapfilter))
