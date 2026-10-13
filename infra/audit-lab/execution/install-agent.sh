#!/usr/bin/env bash
# Only the enrolled isolated target VM; synthetic OS identity is test-only.
set -euo pipefail
[[ $(hostname) == audit-target-lab ]]
[[ $(uname -m) == x86_64 ]]
mountpoint -q /srv/veyport
[[ $(findmnt -rn -o SOURCE /srv/veyport) == /dev/mapper/veyport-services ]]
[[ $(dmsetup info -c --noheadings -o uuid /dev/mapper/veyport-services) == *CRYPT-* ]]
[[ ! -e /etc/veyport/agent.conf ]]
install -d -m700 /srv/veyport/config/execution-agent /srv/veyport/config/execution-agent/tls /srv/veyport/spool/agent-input /srv/veyport/spool/agent-dropzone
install -d -m755 /usr/local/lib/veyport-lab
if ! id lab_synthetic_officer >/dev/null 2>&1; then
  useradd --create-home --shell /bin/sh lab_synthetic_officer
  passwd --lock lab_synthetic_officer >/dev/null
fi
cat > /usr/local/sbin/veyport-lab-volume-check <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mountpoint -q /srv/veyport
[[ $(findmnt -rn -o SOURCE /srv/veyport) == /dev/mapper/veyport-services ]]
[[ $(dmsetup info -c --noheadings -o uuid /dev/mapper/veyport-services) == *CRYPT-* ]]
EOF
chmod 755 /usr/local/sbin/veyport-lab-volume-check
cat > /etc/systemd/system/veyport-lab-agent.service <<'EOF'
[Unit]
Description=Enrolled target for isolated synthetic Veyport execution
After=network-online.target
ConditionPathIsMountPoint=/srv/veyport
[Service]
User=root
UMask=0077
EnvironmentFile=/srv/veyport/config/execution-agent/enrollment.env
Environment=VEYPORT_EXECUTION_SPOOL_DIR=/srv/veyport/spool/agent-input
ExecStartPre=/usr/local/sbin/veyport-lab-volume-check
ExecStart=/usr/local/lib/veyport-lab/veyport-agent --hub 10.10.1.59:9090 --token ${VEYPORT_LAB_REGISTRATION_TOKEN} --ca-pin ${VEYPORT_LAB_CA_PIN} --config /srv/veyport/config/execution-agent/agent.conf --cert-dir /srv/veyport/config/execution-agent/tls --dropzone-dir /srv/veyport/spool/agent-dropzone
NoNewPrivileges=true
MemorySwapMax=0
LimitCORE=0
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
sync -f /srv/veyport
systemctl daemon-reload
systemctl enable veyport-lab-agent >/dev/null
