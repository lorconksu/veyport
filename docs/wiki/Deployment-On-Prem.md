# On-Premises Deployment Guide

| Field | Value |
|-------|-------|
| **Deployment Target** | On-premises / self-hosted |
| **Required Ports** | 443 (HTTPS), 9443 (gRPC/TLS) |
| **Minimum Resources** | 1 vCPU, 512 MB RAM, 4 GB disk |
| **Estimated Cost** | Hardware-dependent (no licensing fees) |

This guide covers deploying Veyport Hub and agents on your own infrastructure using Docker Compose (recommended) or bare-metal binaries.

---

## Prerequisites

### Docker Deployment

- Docker Engine 24+ and Docker Compose v2+
- A Linux server (amd64 or arm64)
- A domain name with DNS pointing to your server (for production TLS)

### Bare-Metal Deployment

- Go 1.26+
- Node.js 25+
- Make
- GCC and libc6-dev (for CGO/SQLite compilation)
- A Linux server (amd64 or arm64)

---

## Option A: Docker Compose Deployment (Recommended)

### 1. Download and configure

```bash
# Download the compose file
curl -O https://raw.githubusercontent.com/lorconksu/veyport/main/docker-compose.yml
```

The default `docker-compose.yml`:

```yaml
services:
  veyport:
    image: yiucloud/veyport:${VEYPORT_VERSION:-latest}
    container_name: veyport
    ports:
      - "8081:8081"            # HTTP - web UI and REST API
      - "127.0.0.1:9090:9090" # gRPC - agents connect via reverse proxy
    volumes:
      - veyport-data:/data    # SQLite DB and persistent state
    restart: unless-stopped

volumes:
  veyport-data:
```

### 2. Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VEYPORT_VERSION` | `latest` | Docker image tag (e.g., `vX.Y.Z`) |

Pin to a specific version for reproducible deployments:

```bash
export VEYPORT_VERSION=vX.Y.Z
docker compose up -d
```

### 3. Start the Hub

```bash
docker compose up -d
```

The Hub starts on port 8081 (HTTP) and 9090 (gRPC). Open `http://localhost:8081` to create the initial admin account and configure 2FA.

### 4. Stop / restart

```bash
# Stop
docker compose down

# Restart
docker compose restart

# View logs
docker compose logs -f veyport
```

### 5. Data persistence

The SQLite database is stored at `/data/veyport.db` inside the container, persisted via the `veyport-data` named Docker volume. This volume survives container restarts and image upgrades.

---

## Option B: Bare-Metal Deployment

### 1. Build from source

```bash
git clone https://github.com/lorconksu/veyport.git
cd veyport
make build
```

This produces a single self-contained binary at `bin/veyport` with the frontend embedded.

### 2. Install the binary

```bash
# Create a dedicated user
useradd --system --no-create-home --shell /usr/sbin/nologin veyport

# Create directories
mkdir -p /opt/veyport/bin /var/lib/veyport

# Copy the binary
cp bin/veyport /opt/veyport/bin/veyport
chmod +x /opt/veyport/bin/veyport

# Set ownership
chown -R veyport:veyport /opt/veyport /var/lib/veyport
```

### 3. Create a systemd service

Create `/etc/systemd/system/veyport.service`:

```ini
[Unit]
Description=Veyport Hub
After=network.target

[Service]
Type=simple
User=veyport
Group=veyport
WorkingDirectory=/opt/veyport
ExecStart=/opt/veyport/bin/veyport \
  --addr 127.0.0.1:8081 \
  --grpc-addr 0.0.0.0:9090 \
  --db /var/lib/veyport/veyport.db \
  --agent-bin-dir /opt/veyport/agent-bins
Restart=on-failure
RestartSec=5s

# Harden the service
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/veyport /opt/veyport/agent-bins
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 4. Enable and start

```bash
systemctl daemon-reload
systemctl enable veyport
systemctl start veyport
systemctl status veyport
```

### 5. SQLite permissions

The `veyport` system user must have read/write access to both the database file and its parent directory (SQLite creates WAL and SHM files alongside the main database):

```bash
chown veyport:veyport /var/lib/veyport/
chmod 750 /var/lib/veyport/
```

### Hub CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | HTTP listen address and port |
| `--grpc-addr` | `:9090` | gRPC listen address for agent connections |
| `--db` | `veyport.db` | Path to the SQLite database file |
| `--agent-bin-dir` | `` | Directory containing agent binaries served via `/install/{os}/{arch}` |
| `--require-mtls` | `false` | Require agents to present valid mTLS certificates |
| `--grpc-external-addr` | `` | External gRPC address shown in install commands |

---

## Reverse Proxy Setup

A reverse proxy is required for production deployments to provide TLS termination for both HTTPS (port 443) and gRPC (port 9443 or multiplexed on 443).

For detailed reverse proxy configuration (Traefik, Nginx, Caddy), see [[Proxy-Configuration]].

### Port mapping summary

```mermaid
flowchart LR
    Client["Browser / Agent"] -->|443 HTTPS| Proxy["Reverse Proxy<br/>(Traefik, Nginx, etc.)"]
    Proxy -->|8081 HTTP| Hub["Veyport Hub"]
    Proxy -->|9090 h2c| HubGRPC["Veyport Hub<br/>(gRPC)"]
```

| External Port | Internal Port | Protocol | Purpose |
|---------------|---------------|----------|---------|
| 443 | 8081 | HTTPS -> HTTP | Web UI and REST API |
| 443 (path-based) or 9443 | 9090 | HTTPS -> h2c (HTTP/2) | Agent gRPC connections |

---

## TLS/SSL Certificate Setup

### Let's Encrypt with Certbot (standalone)

If you are not using Traefik (which handles certificates automatically), use Certbot:

```bash
# Install certbot
apt-get install -y certbot

# Obtain a certificate (stop any service on port 80 first)
certbot certonly --standalone -d veyport.example.com

# Certificates are stored at:
#   /etc/letsencrypt/live/veyport.example.com/fullchain.pem
#   /etc/letsencrypt/live/veyport.example.com/privkey.pem
```

### Auto-renewal

Certbot installs a systemd timer by default. Verify it is active:

```bash
systemctl status certbot.timer
```

### Using certificates with Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name veyport.example.com;

    ssl_certificate     /etc/letsencrypt/live/veyport.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/veyport.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

For full proxy configurations including gRPC routing, see [[Proxy-Configuration]].

---

## Agent Installation

Deploy agents on each managed server using the one-command install script served by the Hub.

### One-command install

```bash
curl -sSL https://<hub>/install.sh | sudo bash -s -- \
  --token '<token>' \
  --hub '<host>:9443' \
  --url 'https://<hub>'
```

Replace `<hub>` with your Hub domain, `<token>` with the registration token from the Hub UI, and `<host>:9443` with the gRPC endpoint (use port 443 if gRPC is multiplexed via path-based routing).

The install script will:
1. Detect OS and CPU architecture
2. Auto-detect and replace existing installations
3. Download the correct agent binary from the Hub
4. Write configuration to `/etc/veyport/agent.conf`
5. Install and enable a systemd service
6. Verify successful registration with the Hub

### Network requirements

| Direction | Protocol | Port | Notes |
|-----------|----------|------|-------|
| Agent -> Hub | gRPC (HTTP/2) | 9090 (direct) or 443/9443 (via proxy) | Must be reachable from agent host |
| Hub -> Agent | None | -- | Agents always dial out; Hub never initiates |

Browser terminal sessions use the same outbound agent stream as file browsing and log tailing. No inbound SSH or terminal port is opened on managed servers. For LDAP-backed terminal access configuration, see [[Deployment#ldap-login-and-terminal-access]].

### TLS auto-detection

The agent infers connection security from the hub address:
- **Hostname** (e.g., `veyport.example.com:443`) -- TLS enabled
- **IP address** (e.g., `192.168.1.10:9090`) -- insecure (no TLS)

---

## Backup and Restore

Veyport uses SQLite with WAL mode. The database is a single file that can be safely copied while the Hub is running.

### Create a backup

```bash
# Docker
docker exec veyport sqlite3 /data/veyport.db \
  ".backup /data/backup-$(date +%Y%m%d).db"

# Copy the backup out of the container
docker cp veyport:/data/backup-$(date +%Y%m%d).db ./

# Bare-metal
sqlite3 /var/lib/veyport/veyport.db \
  ".backup /var/lib/veyport/backup-$(date +%Y%m%d).db"
```

### Automated daily backup (cron)

```bash
# Add to crontab
0 2 * * * docker exec veyport sqlite3 /data/veyport.db ".backup /data/backup-$(date +\%Y\%m\%d).db"
```

### Restore from backup

```bash
# Docker: stop the Hub, replace the database, restart
docker compose down
docker run --rm -v veyport-data:/data -v $(pwd):/backup alpine \
  cp /backup/backup-20260401.db /data/veyport.db
docker compose up -d

# Bare-metal: stop the Hub, replace the database, restart
systemctl stop veyport
cp /var/lib/veyport/backup-20260401.db /var/lib/veyport/veyport.db
chown veyport:veyport /var/lib/veyport/veyport.db
systemctl start veyport
```

Store backups off-host. The database contains all user accounts, server registrations, and audit logs.

---

## Updating / Upgrading

### Docker

```bash
# Pull the latest image (or a specific version)
docker compose pull

# Recreate the container with the new image
docker compose up -d
```

Migrations run automatically on startup. The data volume is preserved across upgrades.

### Bare-metal

```bash
# Build the new binary
cd /path/to/veyport-source
git pull
make build

# Deploy
scp bin/veyport user@yourserver:/opt/veyport/bin/veyport.new
ssh user@yourserver 'mv /opt/veyport/bin/veyport.new /opt/veyport/bin/veyport && systemctl restart veyport'
```

Migrations run automatically on startup.

---

## Verify Installation

After deployment, verify the Hub is running correctly:

```bash
# Check the web UI is accessible
curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/login
# Expected: 200

# Check the gRPC port is listening
ss -tlnp | grep 9090
# Expected: LISTEN on 0.0.0.0:9090

# If behind a reverse proxy, check the external endpoint
curl -s -o /dev/null -w "%{http_code}" https://veyport.example.com/login
# Expected: 200

# Check Docker container health
docker compose ps
docker compose logs --tail=20 veyport
```

Open the Hub in a browser, create the initial admin account, enable 2FA, and register your first agent to confirm end-to-end connectivity.
