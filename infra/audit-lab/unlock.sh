#!/usr/bin/env bash
# Run on controller after reboot, using the corresponding private local LUKS key.
set -euo pipefail
guest=${1:?guest IP required}
key=${2:?private controller key path required}
[[ "$guest" =~ ^10\.10\.1\.(59|60|61|62|63|64)$ ]] || exit 1
ssh -i "$HOME/.ssh/yiucloud" "cloud-user@$guest" 'sudo install -m600 /dev/null /run/veyport-unlock.key; sudo tee /run/veyport-unlock.key >/dev/null' < "$key"
mount_options=nodev,nosuid
[[ "$guest" == 10.10.1.62 ]] && mount_options=sync,nodev,nosuid
ssh -i "$HOME/.ssh/yiucloud" "cloud-user@$guest" "sudo bash -s -- $mount_options" <<'EOF'
set -euo pipefail
trap 'rm -f /run/veyport-unlock.key' EXIT
if [[ ! -e /dev/mapper/veyport-services ]]; then
  cryptsetup open --key-file /run/veyport-unlock.key /var/lib/veyport-lab/services.luks veyport-services
fi
mountpoint -q /srv/veyport || mount -o "$1" /dev/mapper/veyport-services /srv/veyport
if [[ "$1" == sync,nodev,nosuid ]]; then
  mount -o remount,sync,nodev,nosuid /srv/veyport
  findmnt -n -o OPTIONS /srv/veyport | tr ',' '\n' | grep -qx sync
fi
EOF
