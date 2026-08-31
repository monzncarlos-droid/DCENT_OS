#!/bin/sh
# Product wrapper; shared builder enforces the management-only mutation policy.
exec "${BR2_EXTERNAL_DCENTOS_PATH}/board/amlogic/am3-s21/post-build.sh" "$@"
