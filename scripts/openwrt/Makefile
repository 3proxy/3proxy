#
# Copyright (C) 2026 3proxy.org
#
# This is free software, licensed under the BSD 3-Clause License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=3proxy
PKG_VERSION:=0.9.9.0
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
# A trailing ? tells the download helper the URL is complete and PKG_SOURCE
# must not be appended to it.
PKG_SOURCE_URL:=https://codeload.github.com/3proxy/3proxy/tar.gz/refs/tags/$(PKG_VERSION)?
PKG_HASH:=5af253fa734f61af6d5fe3790022130a14caf25bfce24a6aefd415797d351dd3

PKG_MAINTAINER:=Vladimir Dubrovin <vlad@3proxy.org>
PKG_LICENSE:=BSD-3-Clause
PKG_LICENSE_FILES:=copying
PKG_CPE_ID:=cpe:/a:3proxy:3proxy

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/3proxy
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=tiny free proxy server
  URL:=https://3proxy.org/
  DEPENDS:=+libopenssl +libpcre2
endef

define Package/3proxy/description
  3proxy is a tiny free proxy server supporting HTTP, HTTPS, FTP, SOCKS v4/v4a/v5,
  POP3, SMTP, IMAP, TCP and UDP port mapping, with access control, bandwidth
  limiting and traffic accounting.
endef

define Package/3proxy/conffiles
/etc/config/3proxy
endef

# Makefile.Linux appends to CFLAGS and LDFLAGS internally; the target flags have
# to be added rather than substituted, or the defines it relies on are lost.
define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) -f Makefile.Linux \
		CC="$(TARGET_CC)" \
		EXTRA_CFLAGS="$(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		EXTRA_LDFLAGS="$(TARGET_LDFLAGS)" \
		PLUGINS=
endef

define Package/3proxy/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/3proxy $(1)/usr/bin/3proxy
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/3proxy.config $(1)/etc/config/3proxy
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/3proxy.init $(1)/etc/init.d/3proxy
endef

$(eval $(call BuildPackage,3proxy))
