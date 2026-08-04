################################################################################
#
# dcentos-deploy-path
#
################################################################################

DCENTOS_DEPLOY_PATH_VERSION = 1.0.0
DCENTOS_DEPLOY_PATH_SITE = $(BR2_EXTERNAL_DCENTOS_PATH)/packages/dcentos-deploy-path/src
DCENTOS_DEPLOY_PATH_SITE_METHOD = local
DCENTOS_DEPLOY_PATH_LICENSE = GPL-3.0+
DCENTOS_DEPLOY_PATH_LICENSE_FILES = dcentos-deploy-path.c

define DCENTOS_DEPLOY_PATH_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(@D)/dcentos-deploy-path $(@D)/dcentos-deploy-path.c
endef

define DCENTOS_DEPLOY_PATH_INSTALL_TARGET_CMDS
	install -D -m 0755 $(@D)/dcentos-deploy-path \
		$(TARGET_DIR)/usr/libexec/dcentos/dcentos-deploy-path
endef

$(eval $(generic-package))
