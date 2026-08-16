#!/bin/sh
# Product wrapper; capability implementation and identity whitelist are shared.
exec "${BR2_EXTERNAL_DCENTOS_PATH}/board/amlogic/am3-s21/post-build.sh" "$@"
