#!/usr/bin/env bash
set -euo pipefail
[[ $(hostname) == audit-keys-lab ]] || exit 1
mountpoint -q /srv/veyport || { echo 'Unlock encrypted service volume first'; exit 1; }
[[ -x /usr/local/bin/bao ]] || { echo 'Pinned bao binary must be installed first'; exit 1; }
systemctl stop veyport-openbao || true
id -u veyport-openbao >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin veyport-openbao
chmod 711 /srv/veyport /srv/veyport/data
mkdir -p /srv/veyport/data/openbao
cat > /srv/veyport/config/openbao.hcl <<'EOF'
ui = false
api_addr = "https://10.10.1.63:8200"
cluster_addr = "https://127.0.0.1:8201"
storage "raft" {
  path = "/srv/veyport/data/openbao"
  node_id = "audit-keys-lab"
}
listener "tcp" {
  address = "10.10.1.63:8200"
  cluster_address = "127.0.0.1:8201"
  tls_cert_file = "/srv/veyport/tls/server.crt"
  tls_key_file = "/srv/veyport/tls/server.key"
  tls_min_version = "tls12"
}
EOF
chown -R veyport-openbao:veyport-openbao /srv/veyport/config /srv/veyport/tls /srv/veyport/data/openbao
chmod 700 /srv/veyport/config /srv/veyport/tls /srv/veyport/data/openbao
chmod 600 /srv/veyport/config/openbao.hcl
cat > /etc/systemd/system/veyport-openbao.service <<'EOF'
[Unit]
Description=Veyport lab independent OpenBao key service
After=network-online.target
ConditionPathIsMountPoint=/srv/veyport
[Service]
User=veyport-openbao
Group=veyport-openbao
CapabilityBoundingSet=
AmbientCapabilities=
ProtectHome=true
PrivateDevices=true
RestrictNamespaces=true
LockPersonality=true
ExecStart=/usr/local/bin/bao server -config=/srv/veyport/config/openbao.hcl
UMask=0077
MemorySwapMax=0
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/srv/veyport
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl reset-failed veyport-openbao || true
systemctl enable --now veyport-openbao
systemctl restart veyport-openbao
systemctl is-active veyport-openbao
