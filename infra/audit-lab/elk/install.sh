#!/usr/bin/env bash
set -euo pipefail
[[ $(hostname) == elk-lab ]]
mountpoint -q /srv/veyport
export DEBIAN_FRONTEND=noninteractive
chmod 711 /srv/veyport
install -d -m711 /srv/veyport/logs
chmod 711 /srv/veyport/config /srv/veyport/data /srv/veyport/spool
for package in elasticsearch kibana logstash; do
  installed=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || true)
  if [[ ${installed#*:} != 9.5.5 && ${installed#*:} != 9.5.5-1 ]]; then
    dpkg -i "/var/tmp/${package}-9.5.5-amd64.deb" >/srv/veyport/config/"${package}-installation.log" 2>&1
  fi
  installed=$(dpkg-query -W -f='${Version}' "$package")
  [[ ${installed#*:} == 9.5.5 || ${installed#*:} == 9.5.5-1 ]]
  systemctl stop "$package" || true
  if [[ ! -L /etc/$package ]]; then
    mv "/etc/$package" "/srv/veyport/config/$package"
    ln -s "/srv/veyport/config/$package" "/etc/$package"
  fi
  install -d -m700 -o "$package" -g "$package" /srv/veyport/data/"$package" /srv/veyport/logs/"$package"
  install -d -m750 -o root -g "$package" /srv/veyport/config/"$package"/tls
done
install -d -m700 -o logstash -g logstash /srv/veyport/spool/logstash
install -d -m700 -o elasticsearch -g elasticsearch /srv/veyport/spool/elasticsearch
cat > /usr/local/sbin/veyport-elk-volume-check <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mountpoint -q /srv/veyport
[[ $(findmnt -rn -o SOURCE /srv/veyport) == /dev/mapper/veyport-services ]]
EOF
chmod 755 /usr/local/sbin/veyport-elk-volume-check
for service in elasticsearch kibana logstash; do
  install -d -m755 /etc/systemd/system/"$service".service.d
  cat > /etc/systemd/system/"$service".service.d/veyport.conf <<EOF
[Unit]
ConditionPathIsMountPoint=/srv/veyport
[Service]
ExecStartPre=/usr/local/sbin/veyport-elk-volume-check
UMask=0077
MemorySwapMax=0
LimitCORE=0
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectHome=true
PrivateTmp=true
RestrictNamespaces=true
LockPersonality=true
EOF
done
printf '\n[Service]\nEnvironment=ES_TMPDIR=/srv/veyport/spool/elasticsearch\n' >> /etc/systemd/system/elasticsearch.service.d/veyport.conf
printf 'vm.max_map_count=1048576\n' > /etc/sysctl.d/90-veyport-elasticsearch.conf
sysctl -q -p /etc/sysctl.d/90-veyport-elasticsearch.conf
systemctl daemon-reload
