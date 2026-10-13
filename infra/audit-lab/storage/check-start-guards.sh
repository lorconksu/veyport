#!/usr/bin/env bash
# Explicitly run with sudo on the authorized new archive guest only.
set -euo pipefail
[[ $(hostname) == audit-store-lab ]] || exit 1
units='nginx veyport-seaweed-s3 veyport-seaweed-filer veyport-seaweed-volume veyport-seaweed-master postgresql@16-audit'
mountpoint -q /srv/veyport
/usr/local/sbin/veyport-archive-volume-check
systemctl stop $units
restore() {
  mountpoint -q /srv/veyport || mount -o sync,nodev,nosuid /dev/mapper/veyport-services /srv/veyport
  mount -o remount,sync,nodev,nosuid /srv/veyport
  systemctl reset-failed
  systemctl start $units
}
trap restore EXIT
mount -o remount,async,nodev,nosuid /srv/veyport
if /usr/local/sbin/veyport-archive-volume-check; then
  echo 'FAIL helper accepted asynchronous mount'; exit 1
fi
if systemctl start veyport-seaweed-master; then
  echo 'FAIL daemon accepted asynchronous mount'; exit 1
fi
systemctl stop veyport-seaweed-master
echo 'PASS archive start rejected asynchronous mount'
mount -o remount,sync,nodev,nosuid /srv/veyport
umount /srv/veyport
systemctl reset-failed veyport-seaweed-master
systemctl start veyport-seaweed-master
if systemctl is-active --quiet veyport-seaweed-master; then
  echo 'FAIL daemon started without encrypted mount'; exit 1
fi
[[ -z $(find /srv/veyport -mindepth 1 -maxdepth 1 -print -quit) ]]
echo 'PASS daemon skipped absent encrypted mount; no plaintext service files created'
