#!/usr/bin/env bash
set -euo pipefail
[[ $(hostname) == audit-store-lab ]] || exit 1
mountpoint -q /srv/veyport || exit 1
mount -o remount,sync,nodev,nosuid /srv/veyport
cat > /usr/local/sbin/veyport-archive-volume-check <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mountpoint -q /srv/veyport
findmnt -n -o OPTIONS /srv/veyport | tr ',' '\n' | grep -qx sync
EOF
chmod 755 /usr/local/sbin/veyport-archive-volume-check
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=600 install -y -qq postgresql-16 nginx > /var/log/veyport-storage-packages.log
systemctl stop nginx || true
systemctl stop postgresql@16-main || true
chmod 711 /srv/veyport /srv/veyport/data
if ! pg_lsclusters -h | awk '{print $2}' | grep -qx audit; then
  pg_createcluster 16 audit --datadir /srv/veyport/data/postgres --port 5433 --start
fi
sed -i "s/^listen_addresses.*/listen_addresses = '127.0.0.1'/" /etc/postgresql/16/audit/postgresql.conf
pg_conftool 16 audit set fsync on
pg_conftool 16 audit set synchronous_commit on
pg_conftool 16 audit set full_page_writes on
mkdir -p /etc/systemd/system/postgresql@16-audit.service.d
cat > /etc/systemd/system/postgresql@16-audit.service.d/veyport-lab.conf <<'EOF'
[Unit]
ConditionPathIsMountPoint=/srv/veyport
[Service]
MemorySwapMax=0
ExecStartPre=/usr/local/sbin/veyport-archive-volume-check
EOF
systemctl daemon-reload
pg_ctlcluster 16 audit restart
# Private generated password is provided in encrypted config by the controller.
python3 - <<'PY'
import pathlib,subprocess,json
password=json.loads(pathlib.Path('/srv/veyport/config/postgres-secret.json').read_text())['password']
sql="CREATE USER seaweed WITH PASSWORD '"+password+"'; CREATE DATABASE seaweed OWNER seaweed;"
if subprocess.run(['sudo','-u','postgres','psql','-p','5433','-tAc',"SELECT 1 FROM pg_roles WHERE rolname='seaweed'"],capture_output=True,text=True).stdout.strip() != '1':
 subprocess.run(['sudo','-u','postgres','psql','-p','5433','-v','ON_ERROR_STOP=1'],input=sql,text=True,check=True,stdout=subprocess.DEVNULL)
PY
systemctl stop veyport-seaweed-s3 veyport-seaweed-filer veyport-seaweed-volume veyport-seaweed-master || true
id -u veyport-seaweed >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin veyport-seaweed
mkdir -p /srv/veyport/data/{master,volume}
chown -R veyport-seaweed:veyport-seaweed /srv/veyport/config /srv/veyport/tls /srv/veyport/data/master /srv/veyport/data/volume
chmod 700 /srv/veyport/config /srv/veyport/tls /srv/veyport/data/master /srv/veyport/data/volume
for service in master volume filer s3; do
  case "$service" in
    master) args='master -ip=127.0.0.1 -ip.bind=127.0.0.1 -mdir=/srv/veyport/data/master -volumeSizeLimitMB=1024 -defaultReplication=000' ;;
    volume) args='volume -ip=127.0.0.1 -ip.bind=127.0.0.1 -port=8080 -mserver=127.0.0.1:9333 -dir=/srv/veyport/data/volume -max=20 -fileSizeLimitMB=32' ;;
    filer) args='filer -ip=127.0.0.1 -ip.bind=127.0.0.1 -master=127.0.0.1:9333 -port=8888 -iam=false -exposeDirectoryData=false' ;;
    s3) args='s3 -ip.bind=127.0.0.1 -filer=127.0.0.1:8888 -port=8334 -config=/srv/veyport/config/s3.json -iam=false -port.iceberg=0 -port.lance=0 -allowDeleteBucketNotEmpty=false -autoCreateBucket=false -concurrentUploadLimitMB=64' ;;
  esac
  cat > "/etc/systemd/system/veyport-seaweed-$service.service" <<EOF
[Unit]
Description=Veyport lab SeaweedFS $service
After=network-online.target postgresql@16-audit.service
ConditionPathIsMountPoint=/srv/veyport
[Service]
User=veyport-seaweed
Group=veyport-seaweed
CapabilityBoundingSet=
AmbientCapabilities=
ProtectHome=true
PrivateDevices=true
RestrictNamespaces=true
LockPersonality=true
WorkingDirectory=/srv/veyport/config
ExecStartPre=/usr/local/sbin/veyport-archive-volume-check
ExecStart=/usr/local/bin/weed $args
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
done
systemctl daemon-reload
systemctl enable --now veyport-seaweed-master veyport-seaweed-volume veyport-seaweed-filer veyport-seaweed-s3
systemctl restart veyport-seaweed-master veyport-seaweed-volume veyport-seaweed-filer veyport-seaweed-s3
# Persist the required data fsync policy in synchronous filer metadata. Shell
# reports command errors on stderr, so inspect both streams before proceeding.
for attempt in $(seq 1 30); do
  if timeout 8 bash -c "printf 'fs.configure -locationPrefix=/buckets/ -fsync=true -volumeGrowthCount=1 -apply\\n' | /usr/local/bin/weed shell -filer=127.0.0.1:8888 -master=127.0.0.1:9333" > /run/veyport-fsync-policy.log 2>&1 && ! grep -q 'error:' /run/veyport-fsync-policy.log; then
    break
  fi
  (( attempt < 30 )) || { echo 'Filer durable-write policy could not be applied'; exit 1; }
  sleep 1
done
rm /run/veyport-fsync-policy.log
rm -f /etc/nginx/sites-enabled/default
mkdir -p /srv/veyport/spool/nginx
chown www-data:www-data /srv/veyport/spool/nginx
chmod 711 /srv/veyport/spool
cat > /etc/nginx/sites-available/veyport-s3 <<'EOF'
server {
  listen 10.10.1.62:8333 ssl;
  server_name audit-store-lab;
  ssl_certificate /srv/veyport/tls/server.crt;
  ssl_certificate_key /srv/veyport/tls/server.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  client_max_body_size 32m;
  client_body_temp_path /srv/veyport/spool/nginx/body;
  proxy_temp_path /srv/veyport/spool/nginx/proxy;
  access_log off;
  location / {
    proxy_pass http://127.0.0.1:8334;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header Connection "";
    proxy_request_buffering off;
    proxy_buffering off;
    proxy_read_timeout 60s;
  }
}
EOF
ln -sf /etc/nginx/sites-available/veyport-s3 /etc/nginx/sites-enabled/veyport-s3
mkdir -p /etc/systemd/system/nginx.service.d
cat > /etc/systemd/system/nginx.service.d/veyport-lab.conf <<'EOF'
[Unit]
ConditionPathIsMountPoint=/srv/veyport
[Service]
MemorySwapMax=0
ExecStartPre=/usr/local/sbin/veyport-archive-volume-check
EOF
nginx -t
systemctl daemon-reload
systemctl enable --now nginx
sudo -u postgres psql -p5433 -tAc 'SHOW fsync; SHOW synchronous_commit; SHOW full_page_writes;'
