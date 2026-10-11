#!/usr/bin/env bash
set -euo pipefail
mountpoint -q /srv/veyport
findmnt -n -o OPTIONS /srv/veyport | tr ',' '\n' | grep -qx sync
