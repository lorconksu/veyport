#!/usr/bin/env bash
set -euo pipefail
[[ $(hostname) == audit-ingest-lab ]]
mountpoint -q /srv/veyport
chmod 711 /srv/veyport/spool
id veyport-redactor >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin veyport-redactor
install -d -m700 -o veyport-redactor -g veyport-redactor /srv/veyport/redactor /srv/veyport/spool/redactor
cat > /etc/systemd/system/veyport-audit-export.service <<'EOF'
[Unit]
Description=Veyport privileged archive redactor and bounded search replay
After=network-online.target veyport-audit-ingest.service
ConditionPathIsMountPoint=/srv/veyport
[Service]
User=veyport-redactor
Group=veyport-redactor
UMask=0077
ExecStartPre=/usr/local/sbin/veyport-receipt-volume-check
ExecStart=/usr/local/bin/veyport-audit-export --config /srv/veyport/redactor/config.json
Environment=TMPDIR=/srv/veyport/spool/redactor
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/srv/veyport/spool/redactor
RestrictNamespaces=true
LockPersonality=true
MemorySwapMax=0
MemoryMax=256M
LimitCORE=0
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable veyport-audit-export >/dev/null
