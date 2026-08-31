#!/bin/sh
# Product wrapper; shared builder emits a non-installable package-only artifact.
exec "${BR2_EXTERNAL_DCENTOS_PATH}/board/amlogic/am3-s21/post-image.sh" "$@"
