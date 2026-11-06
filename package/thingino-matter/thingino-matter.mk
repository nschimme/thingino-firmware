################################################################################
#
# thingino-matter
#
################################################################################

THINGINO_MATTER_VERSION = 090d61185d81d33d5ec38e9781875e03f1b9afc2
THINGINO_MATTER_SITE = https://github.com/esp-dev/matter-c/archive/$(THINGINO_MATTER_VERSION)
THINGINO_MATTER_SOURCE = thingino-matter-$(THINGINO_MATTER_VERSION).tar.gz
THINGINO_MATTER_LICENSE = Apache-2.0
THINGINO_MATTER_LICENSE_FILES = LICENSE

THINGINO_MATTER_DEPENDENCIES = thingino-core thingino-jct thingino-agent

ifeq ($(BR2_PACKAGE_MBEDTLS),y)
THINGINO_MATTER_DEPENDENCIES += mbedtls
else ifeq ($(BR2_PACKAGE_THINGINO_MBEDTLS),y)
THINGINO_MATTER_DEPENDENCIES += thingino-mbedtls
endif

# Build standalone pure C99 Matter node with system mbedTLS and disable warnings-as-errors
THINGINO_MATTER_CONF_OPTS = \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="-Wno-error=maybe-uninitialized -Wno-error" \
	-DMATTER_BUILD_RUNTIME=ON

# Post-install hook: install SysV init scripts, defaults, CLI, and WebUI plugin
define THINGINO_MATTER_INSTALL_TARGET_CMDS
	# Stage defaults for merge by thingino-core
	$(INSTALL) -D -m 0644 $(THINGINO_MATTER_PKGDIR)/files/thingino-matter.json \
		$(TARGET_DIR)/usr/share/thingino-defaults/50-matter.json

	# Install matter-node binary as matterd
	if [ -f $(@D)/build/matter-node ]; then \
		$(INSTALL) -D -m 0755 $(@D)/build/matter-node \
			$(TARGET_DIR)/usr/sbin/matterd; \
	elif [ -f $(@D)/matter-node ]; then \
		$(INSTALL) -D -m 0755 $(@D)/matter-node \
			$(TARGET_DIR)/usr/sbin/matterd; \
	fi

	# Install CLI helpers and init scripts
	$(INSTALL) -D -m 0755 $(THINGINO_MATTER_PKGDIR)/files/matterctl \
		$(TARGET_DIR)/usr/sbin/matterctl
	$(INSTALL) -D -m 0755 $(THINGINO_MATTER_PKGDIR)/files/matter-event \
		$(TARGET_DIR)/usr/sbin/matter-event
	$(INSTALL) -D -m 0755 $(THINGINO_MATTER_PKGDIR)/files/S94matter \
		$(TARGET_DIR)/etc/init.d/S94matter
	$(INSTALL) -D -m 0755 $(THINGINO_MATTER_PKGDIR)/files/S96matter_discovery \
		$(TARGET_DIR)/etc/init.d/S96matter_discovery

	# Web UI plugin
	$(INSTALL) -D -m 0644 $(THINGINO_MATTER_PKGDIR)/files/matter.webui.json \
		$(TARGET_DIR)/var/www/a/plugins/matter.webui.json
	$(INSTALL) -D -m 0644 $(THINGINO_MATTER_PKGDIR)/files/www/config-matter.html \
		$(TARGET_DIR)/var/www/config-matter.html
	$(INSTALL) -D -m 0644 $(THINGINO_MATTER_PKGDIR)/files/www/a/config-matter.js \
		$(TARGET_DIR)/var/www/a/config-matter.js
	$(INSTALL) -D -m 0755 $(THINGINO_MATTER_PKGDIR)/files/www/x/json-config-matter.cgi \
		$(TARGET_DIR)/var/www/x/json-config-matter.cgi
endef

$(eval $(cmake-package))
