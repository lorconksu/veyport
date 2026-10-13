#!/usr/bin/env bash
# Explicit audit-ingest-lab only; secret files are supplied by the controller.
set -euo pipefail
[[ $(hostname) == audit-ingest-lab ]]
mountpoint -q /srv/veyport
id veyport-receipt >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin veyport-receipt
chmod 711 /srv/veyport
install -d -m700 -o veyport-receipt -g veyport-receipt /srv/veyport/receipt /srv/veyport/spool/receipt
cat > /usr/local/sbin/veyport-receipt-volume-check <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mountpoint -q /srv/veyport
[[ $(findmnt -rn -o SOURCE /srv/veyport) == /dev/mapper/veyport-services ]]
EOF
chmod 755 /usr/local/sbin/veyport-receipt-volume-check
cat > /etc/systemd/system/veyport-audit-ingest.service <<'EOF'
[Unit]
Description=Veyport independent qualified archive receipt service
After=network-online.target
ConditionPathIsMountPoint=/srv/veyport
[Service]
User=veyport-receipt
Group=veyport-receipt
UMask=0077
ExecStartPre=/usr/local/sbin/veyport-receipt-volume-check
ExecStart=/usr/local/bin/veyport-audit-ingest --config /srv/veyport/receipt/config.json
Environment=TMPDIR=/srv/veyport/spool/receipt
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateDevices=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/srv/veyport/spool/receipt
RestrictNamespaces=true
LockPersonality=true
MemorySwapMax=0
MemoryMax=768M
LimitCORE=0
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable veyport-audit-ingest >/dev/null
