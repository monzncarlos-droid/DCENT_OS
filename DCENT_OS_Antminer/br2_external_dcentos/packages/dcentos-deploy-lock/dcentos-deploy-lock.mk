################################################################################
#
# dcentos-deploy-lock
#
################################################################################

DCENTOS_DEPLOY_LOCK_VERSION = 1.0.0
DCENTOS_DEPLOY_LOCK_SITE = $(BR2_EXTERNAL_DCENTOS_PATH)/packages/dcentos-deploy-lock/src
DCENTOS_DEPLOY_LOCK_SITE_METHOD = local
DCENTOS_DEPLOY_LOCK_LICENSE = GPL-3.0+
DCENTOS_DEPLOY_LOCK_LICENSE_FILES = dcentos-deploy-lock.c

define DCENTOS_DEPLOY_LOCK_BUILD_CMDS
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(@D)/dcentos-deploy-lock $(@D)/dcentos-deploy-lock.c
endef

define DCENTOS_DEPLOY_LOCK_INSTALL_TARGET_CMDS
	install -D -m 0755 $(@D)/dcentos-deploy-lock \
		$(TARGET_DIR)/usr/libexec/dcentos/dcentos-deploy-lock
endef

$(eval $(generic-package))

