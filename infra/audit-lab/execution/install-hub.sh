#!/usr/bin/env bash
# Only the isolated synthetic hub VM; no staging or receipt service changes.
set -euo pipefail
[[ $(hostname) == veyport-lab ]]
[[ $(uname -m) == x86_64 ]]
mountpoint -q /srv/veyport
[[ $(findmnt -rn -o SOURCE /srv/veyport) == /dev/mapper/veyport-services ]]
[[ $(dmsetup info -c --noheadings -o uuid /dev/mapper/veyport-services) == *CRYPT-* ]]
owner=/srv/veyport/config/lab-execution-owner
if [[ -f $owner ]]; then
  [[ $(cat "$owner") == isolated-synthetic-execution-lab-v1 ]]
else
  [[ ! -e /srv/veyport/data/veyport-isolated.db ]]
  printf '%s\n' isolated-synthetic-execution-lab-v1 > "$owner"
  chmod 600 "$owner"
fi
for cert in ca.crt server.crt server.key; do
  [[ -f /srv/veyport/tls/$cert && ! -L /srv/veyport/tls/$cert ]]
done
install -d -m700 /srv/veyport/config/audit-runtime /srv/veyport/config/execution-security /srv/veyport/spool/hub-input /srv/veyport/backup/execution
install -d -m755 /usr/local/lib/veyport-lab
if ! command -v nginx >/dev/null; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nginx >/dev/null
  systemctl disable --now nginx >/dev/null 2>&1
fi
cat > /usr/local/sbin/veyport-lab-volume-check <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mountpoint -q /srv/veyport
[[ $(findmnt -rn -o SOURCE /srv/veyport) == /dev/mapper/veyport-services ]]
[[ $(dmsetup info -c --noheadings -o uuid /dev/mapper/veyport-services) == *CRYPT-* ]]
EOF
chmod 755 /usr/local/sbin/veyport-lab-volume-check
cat > /srv/veyport/config/lab-https.conf <<'EOF'
user www-data;
worker_processes 1;
pid /run/veyport-lab-https.pid;
error_log /dev/null;
events { worker_connections 128; }
http {
  access_log off;
  client_max_body_size 1m;
  server {
    listen 10.10.1.59:8443 ssl;
    server_name 10.10.1.59;
    ssl_certificate /srv/veyport/tls/server.crt;
    ssl_certificate_key /srv/veyport/tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
      proxy_pass http://127.0.0.1:8080;
      proxy_set_header Host 10.10.1.59:8443;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_http_version 1.1;
      proxy_buffering off;
      proxy_read_timeout 60s;
    }
  }
}
EOF
chmod 600 /srv/veyport/config/lab-https.conf
cat > /etc/systemd/system/veyport-lab-hub.service <<'EOF'
[Unit]
Description=Isolated synthetic Veyport execution hub
After=network-online.target
ConditionPathIsMountPoint=/srv/veyport
[Service]
User=root
UMask=0077
ExecStartPre=/usr/local/sbin/veyport-lab-volume-check
ExecStart=/usr/local/lib/veyport-lab/veyport-hub --addr 127.0.0.1:8080 --db /srv/veyport/data/veyport-isolated.db --grpc-addr 10.10.1.59:9090 --grpc-external-addr 10.10.1.59:9090 --ssh-addr 10.10.1.59:2222 --security-state-dir /srv/veyport/config/execution-security --audit-runtime-config /srv/veyport/config/audit-runtime/runtime.json --execution-spool-dir /srv/veyport/spool/hub-input
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/srv/veyport/data /srv/veyport/config/execution-security /srv/veyport/spool/hub-input
MemorySwapMax=0
LimitCORE=0
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/veyport-lab-https.service <<'EOF'
[Unit]
Description=Explicit-CA HTTPS for isolated synthetic Veyport REST
After=network-online.target veyport-lab-hub.service
ConditionPathIsMountPoint=/srv/veyport
[Service]
ExecStartPre=/usr/local/sbin/veyport-lab-volume-check
ExecStartPre=/usr/sbin/nginx -t -c /srv/veyport/config/lab-https.conf
ExecStart=/usr/sbin/nginx -c /srv/veyport/config/lab-https.conf -g "daemon off;"
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
systemctl enable veyport-lab-hub veyport-lab-https >/dev/null
