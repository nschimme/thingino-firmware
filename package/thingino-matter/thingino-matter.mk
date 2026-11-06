THINGINO_MATTER_SITE_METHOD = local
THINGINO_MATTER_SITE = $(THINGINO_MATTER_PKGDIR)/files
THINGINO_MATTER_LICENSE = MIT
THINGINO_MATTER_DEPENDENCIES = thingino-core thingino-jct thingino-agent

ifeq ($(BR2_PACKAGE_MBEDTLS),y)
THINGINO_MATTER_DEPENDENCIES += mbedtls
THINGINO_MATTER_CFLAGS += -DHAVE_MBEDTLS
THINGINO_MATTER_LDFLAGS += -lmbedcrypto
else ifeq ($(BR2_PACKAGE_THINGINO_MBEDTLS),y)
THINGINO_MATTER_DEPENDENCIES += thingino-mbedtls
THINGINO_MATTER_CFLAGS += -DHAVE_MBEDTLS
THINGINO_MATTER_LDFLAGS += -lmbedcrypto
endif

define THINGINO_MATTER_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(THINGINO_MATTER_CFLAGS) \
		-o $(@D)/matterd $(@D)/matterd.c \
		$(TARGET_LDFLAGS) $(THINGINO_MATTER_LDFLAGS)
endef

define THINGINO_MATTER_INSTALL_TARGET_CMDS
	# Defaults staged for merge by thingino-core
	$(INSTALL) -D -m 0644 $(THINGINO_MATTER_PKGDIR)/files/thingino-matter.json \
		$(TARGET_DIR)/usr/share/thingino-defaults/50-matter.json

	# Daemon, CLI and Event Notifier
	$(INSTALL) -D -m 0755 $(@D)/matterd \
		$(TARGET_DIR)/usr/sbin/matterd
	$(INSTALL) -D -m 0755 $(@D)/matterctl \
		$(TARGET_DIR)/usr/sbin/matterctl
	$(INSTALL) -D -m 0755 $(@D)/matter-event \
		$(TARGET_DIR)/usr/sbin/matter-event
	$(INSTALL) -D -m 0755 $(@D)/S94matter \
		$(TARGET_DIR)/etc/init.d/S94matter

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

$(eval $(generic-package))
