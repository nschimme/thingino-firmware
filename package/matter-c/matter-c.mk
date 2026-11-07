################################################################################
#
# matter-c
#
################################################################################

MATTER_C_VERSION = 090d61185d81d33d5ec38e9781875e03f1b9afc2
MATTER_C_SITE = https://github.com/esp-dev/matter-c/archive/$(MATTER_C_VERSION)
MATTER_C_SOURCE = matter-c-$(MATTER_C_VERSION).tar.gz
MATTER_C_LICENSE = Apache-2.0
MATTER_C_LICENSE_FILES = LICENSE
MATTER_C_INSTALL_STAGING = YES
MATTER_C_INSTALL_TARGET = NO

ifeq ($(BR2_PACKAGE_MBEDTLS),y)
MATTER_C_DEPENDENCIES += mbedtls
else ifeq ($(BR2_PACKAGE_THINGINO_MBEDTLS),y)
MATTER_C_DEPENDENCIES += thingino-mbedtls
endif

# Build core static libraries (libmatter.a) with system mbedTLS
MATTER_C_CONF_OPTS = \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="-Wno-error=maybe-uninitialized -Wno-error" \
	-DMATTER_BUILD_RUNTIME=ON

define MATTER_C_INSTALL_STAGING_CMDS
	find $(@D) -name "libmatter.a" -exec $(INSTALL) -D -m 0644 {} $(STAGING_DIR)/usr/lib/libmatter.a \;
	find $(@D) -name "libmatter_runtime.a" -exec $(INSTALL) -D -m 0644 {} $(STAGING_DIR)/usr/lib/libmatter_runtime.a \;
	mkdir -p $(STAGING_DIR)/usr/include/matter
	cp -r $(@D)/main/apps/matter/* $(STAGING_DIR)/usr/include/matter/
endef

$(eval $(cmake-package))
