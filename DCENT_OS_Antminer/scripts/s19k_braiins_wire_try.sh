#!/bin/sh
# RETIRED: this legacy helper lacked the v6 content-bound identity, daemon
# custody, cooling, watchdog, reset, and terminal SafeOff transaction.

set -eu
printf '%s\n' \
  'REFUSE: legacy S19k wire-try is retired; use scripts/dcentrald_s19k_tmp_deploy.sh with a pinned known_hosts file' >&2
exit 64
