include $(TOPDIR)/rules.mk

PKG_NAME:=NetworkTrafficMonitor
PKG_VERSION:=0.0.1
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/NetworkTrafficMonitor
	CATEGORY:=Default Category
	TITLE:=Title NetworkTrafficMonitor
	DEPENDS:=+libpcap +libpthread +libsqlite3
endef

define Package/NetworkTrafficMonitor/description
	If you can't figure out what this program does, you're probably
	brain-dead and need immediate medical attention.
endef

define Build/Prepare
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/NetworkTrafficMonitor/install
	$(INSTALL_DIR) $(1)/usr/bin  
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/NetworkTrafficMonitor $(1)/usr/bin/  
endef

$(eval $(call BuildPackage,NetworkTrafficMonitor))
