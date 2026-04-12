# AeroDocs Deployment Guide

> **TL;DR**
> - **What:** Docker-first deployment with a single `docker-compose.yml`; bare-metal binary also available
> - **Who:** The person deploying AeroDocs Hub and agents
> - **Why:** One file to download, one command to run - no cloning, no building
> - **Where:** Hub on a central server (Docker or bare-metal); agents on each managed server
> - **When:** `curl` the compose file, `docker compose up -d`, open the browser
> - **How:** Docker Compose (primary) or build from source (contributors)

## Prerequisites

- Docker and Docker Compose (v2+)
- A Linux server (amd64 or arm64)
- A domain name pointing to your server (for production use with TLS)

---

## Quick Start with Docker

```bash
# Download the compose file
curl -O https://raw.githubusercontent.com/lorconksu/aerodocs/main/docker-compose.yml

# Start AeroDocs
docker compose up -d
```

The Hub starts on port 8081 (HTTP) and 9090 (gRPC). Open `http://localhost:8081` in your browser to create the initial admin account and set up 2FA. Then run the one-liner shown in the UI on each server you want to manage.

That's it. No cloning, no building, no dependencies.

---

## Docker Compose Configuration

The default `docker-compose.yml`:

```yaml
services:
  aerodocs:
    image: yiucloud/aerodocs:latest
    container_name: aerodocs
    ports:
      - "8081:8081"   # HTTP - web UI and REST API
      - "9090:9090"   # gRPC - agent connections
    volumes:
      - aerodocs-data:/data   # SQLite DB and persistent state
    restart: unless-stopped

volumes:
  aerodocs-data:
```

### Configuration details

| Setting | Value | Notes |
|---------|-------|-------|
| Image | `yiucloud/aerodocs:latest` | Pin to a specific tag (e.g. `yiucloud/aerodocs:vX.Y.Z`) for reproducible deployments |
| HTTP port | `8081` | Web UI and REST API |
| gRPC port | `9090` | Agent connections - must be reachable by agents |
| Data volume | `aerodocs-data` mounted at `/data` | Contains the SQLite database (`/data/aerodocs.db`) and all persistent state |
| Binary path | `/app/aerodocs` | The Hub binary inside the container |

### Pinning a version

Replace `latest` with a specific version tag to avoid unexpected upgrades:

```yaml
image: yiucloud/aerodocs:vX.Y.Z
```

---

## Running Behind Traefik

### Docker Compose with Traefik labels

If Traefik is also running in Docker, add labels to the AeroDocs service. Create a `docker-compose.traefik.yml`:

```yaml
services:
  aerodocs:
    image: yiucloud/aerodocs:latest
    container_name: aerodocs
    volumes:
      - aerodocs-data:/data
    restart: unless-stopped
    labels:
      # HTTP router - web UI and REST API
      - "traefik.enable=true"
      - "traefik.http.routers.aerodocs.rule=Host(`aerodocs.example.com`)"
      - "traefik.http.routers.aerodocs.entrypoints=websecure"
      - "traefik.http.routers.aerodocs.tls.certresolver=letsencrypt"
      - "traefik.http.routers.aerodocs.service=aerodocs"
      - "traefik.http.services.aerodocs.loadbalancer.server.port=8081"

      # gRPC router - agent connections (path prefix matches the proto package)
      - "traefik.http.routers.aerodocs-grpc.rule=Host(`aerodocs.example.com`) && PathPrefix(`/aerodocs.v1.`)"
      - "traefik.http.routers.aerodocs-grpc.entrypoints=websecure"
      - "traefik.http.routers.aerodocs-grpc.tls.certresolver=letsencrypt"
      - "traefik.http.routers.aerodocs-grpc.service=aerodocs-grpc"
      - "traefik.http.services.aerodocs-grpc.loadbalancer.server.port=9090"
      - "traefik.http.services.aerodocs-grpc.loadbalancer.server.scheme=h2c"
    networks:
      - traefik

volumes:
  aerodocs-data:

networks:
  traefik:
    external: true
```

No port mappings are needed when Traefik handles routing - traffic flows through the Docker network.

### Bare-metal Traefik (file provider)

If Traefik runs outside Docker, use a file provider config. Create `/etc/traefik/dynamic/aerodocs.yml`:

```yaml
http:
  routers:
    # HTTP and REST API traffic
    aerodocs:
      rule: "Host(`aerodocs.example.com`)"
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: aerodocs

    # gRPC traffic from agents (path prefix matches the proto package)
    aerodocs-grpc:
      rule: "Host(`aerodocs.example.com`) && PathPrefix(`/aerodocs.v1.`)"
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: aerodocs-grpc

  services:
    aerodocs:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8081"

    # h2c (cleartext HTTP/2) is required for gRPC backends without TLS
    aerodocs-grpc:
      loadBalancer:
        servers:
          - url: "h2c://127.0.0.1:9090"
```

Make sure your main `traefik.yml` has the file provider enabled:

```yaml
providers:
  file:
    directory: /etc/traefik/dynamic
    watch: true
```

Traefik handles TLS termination (Let's Encrypt). The Hub sees plain HTTP on port 8081 and cleartext gRPC (h2c) on port 9090. The `PathPrefix('/aerodocs.v1.')` matcher routes agent gRPC connections correctly because gRPC uses the proto package path as the HTTP/2 `:path` header.

---

## Agent Deployment

Agents are lightweight Go binaries deployed on each managed server. They dial out to the Hub's gRPC port - no inbound firewall rules are needed on the agent host.

### One-command install (recommended)

The Hub serves an install script and the agent binaries. On the managed server, run:

```bash
curl -sSL https://aerodocs.example.com/install.sh | sudo bash -s -- \
  --token <REGISTRATION_TOKEN> \
  --hub aerodocs.example.com:443
```

The script will:
1. Detect the OS and CPU architecture
2. **Auto-detect an existing installation** - if `aerodocs-agent` is already installed and has a valid `agent.conf`, the script calls `aerodocs-agent --self-unregister` to remove the old server entry from the Hub before proceeding
3. Download the correct agent binary from `/install/{os}/{arch}`
4. Write the configuration to `/etc/aerodocs/agent.conf`
5. Install and enable a systemd service for the agent
6. **Verify registration** - after starting the agent service, the script checks that the agent successfully registered with the Hub before reporting success

#### Piped vs. manual execution

| Mode | Behaviour |
|------|-----------|
| Piped from `curl` (non-interactive) | Automatically replaces any existing installation without prompting |
| Run as a script manually (interactive terminal) | Prompts **[R]eplace / [K]eep** if an existing installation is detected; exits with a non-zero status if the user selects Keep |

### Manual install

If you prefer not to pipe to bash:

```bash
# Download the binary (example: linux/amd64)
curl -Lo /usr/local/bin/aerodocs-agent \
  https://aerodocs.example.com/install/linux/amd64
chmod +x /usr/local/bin/aerodocs-agent

# Run directly
/usr/local/bin/aerodocs-agent \
  --hub aerodocs.example.com:443 \
  --token <REGISTRATION_TOKEN>
```

### Agent configuration file

After first registration, the agent writes its assigned `server_id` and `hub_url` to:

```
/etc/aerodocs/agent.conf
```

Example contents (JSON):

```json
{
  "server_id": "550e8400-e29b-41d4-a716-446655440000",
  "hub_url": "aerodocs.example.com:443"
}
```

On restart, the agent loads this file and reconnects without needing the registration token again.

### Agent systemd service

The install script creates `/etc/systemd/system/aerodocs-agent.service`:

```ini
[Unit]
Description=AeroDocs Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aerodocs-agent \
  --hub aerodocs.example.com:443 \
  --token <REGISTRATION_TOKEN>
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### Agent flags

| Flag | Description |
|------|-------------|
| `--hub <addr>` | Hub gRPC address (e.g. `aerodocs.example.com:443` or `192.168.1.10:9090`) |
| `--token <token>` | One-time registration token obtained from the Hub when creating a server record |
| `--self-unregister` | Calls `DELETE /api/servers/{id}/self-unregister` on the Hub to remove the current server entry, then exits. Used by the install script before re-installing to clean up the old registration. Requires a valid `agent.conf` with a known `server_id`. |

### TLS auto-detection

The agent infers the connection security mode from the hub address:
- **Hostname** (e.g. `aerodocs.example.com:443`) - TLS enabled
- **IP address** (e.g. `192.168.1.10:9090`) - insecure (no TLS)

### Reconnect behavior

The agent reconnects with **exponential backoff** - starting at 1 second and capping at 60 seconds. On each reconnect it re-sends a `Register` message so the Hub updates sysinfo and resets connection state.

### Network requirements

| Direction | Protocol | Port | Notes |
|-----------|----------|------|-------|
| Agent - Hub | gRPC (HTTP/2) | 9090 (or 443 via Traefik) | Must be reachable from agent host |
| Hub - Agent | None | - | Agents always dial out; Hub never initiates |

---

## mTLS Configuration (v1.1)

As of v1.1, the Hub supports mutual TLS (mTLS) for gRPC connections from agents. This provides cryptographic identity verification beyond the initial registration token.

### How it works

1. **Automatic CA generation** -- On first boot, the Hub generates an ECDSA P-256 Certificate Authority. No manual certificate management is required.
2. **Agent certificates issued during registration** -- When an agent registers, the Hub signs a client certificate (12-hour validity) and sends it to the agent over the gRPC stream.
3. **In-stream renewal** -- Agents automatically renew their certificates at the 6-hour mark (50% lifetime), with no downtime or reconnection.
4. **Agent cert storage** -- Client certificates and keys are stored at `/etc/aerodocs/tls/` on each agent host.

### Enabling mandatory mTLS

By default, mTLS is optional for backward compatibility. Agents that support mTLS will use it; older agents continue to work without it.

To enforce mTLS for all agent connections, add the `--require-mtls` flag:

```bash
# Docker: add to the command in docker-compose.yml
command: ["--require-mtls"]

# Bare-metal: add to the ExecStart line in the systemd unit
ExecStart=/opt/aerodocs/bin/aerodocs \
  --addr 127.0.0.1:8081 \
  --grpc-addr 0.0.0.0:9090 \
  --db /var/lib/aerodocs/aerodocs.db \
  --agent-bin-dir /opt/aerodocs/agent-bins \
  --require-mtls
```

### Upgrading existing agents

Existing agents deployed before v1.1 do not have mTLS certificates. To upgrade them:

1. Re-register the agent (unregister from the Hub UI, then re-run the install script with a new token)
2. The new agent will automatically receive an mTLS certificate during registration
3. Once all agents are re-registered, enable `--require-mtls` on the Hub

### Certificate locations (agent)

| File | Path | Description |
|------|------|-------------|
| Client cert | `/etc/aerodocs/tls/client.crt` | Agent's certificate signed by Hub CA |
| Client key | `/etc/aerodocs/tls/client.key` | Agent's private key (never leaves the machine) |
| CA cert | `/etc/aerodocs/tls/ca.crt` | Hub CA certificate for verifying the Hub |

---

## Cookie-Based Authentication (v1.1)

As of v1.1, the web UI uses **httpOnly cookies** for JWT token storage instead of localStorage. This change is fully automatic -- no configuration is needed.

- Tokens are set as `HttpOnly`, `Secure`, `SameSite=Strict` cookies
- CSRF protection uses a double-submit cookie pattern (handled by the frontend automatically)
- Non-browser clients (scripts, CLI tools) can still use `Authorization: Bearer <token>` headers
- The refresh token cookie is scoped to `/api/auth/refresh` to limit exposure

No action is required from operators. The cookie auth is active by default when upgrading to v1.1.

---

## LXC Container Deployment

AeroDocs can be deployed in a Proxmox LXC container as a lightweight alternative to a full VM. This is useful for home lab and small-team deployments.

### Setup steps

1. **Create an unprivileged LXC container** (Debian/Ubuntu) with at least 512 MB RAM and 4 GB disk.
2. **Install Docker** inside the container (requires the `keyctl` and `nesting` features enabled on the LXC).
3. **Deploy with Docker Compose** using the same `docker-compose.yml` as any other deployment.
4. **Configure Traefik** on the host or a separate LXC to reverse-proxy HTTPS traffic to the container's IP.

### Example: Proxmox LXC with Traefik

If Traefik runs on a separate LXC and AeroDocs runs in another container at `192.0.2.10`:

```yaml
# /etc/traefik/dynamic/aerodocs.yml on the Traefik host
http:
  routers:
    aerodocs:
      rule: "Host(`aerodocs.example.com`)"
      entryPoints: [websecure]
      tls:
        certResolver: letsencrypt
      service: aerodocs
    aerodocs-grpc:
      rule: "Host(`aerodocs.example.com`) && PathPrefix(`/aerodocs.v1.`)"
      entryPoints: [websecure]
      tls:
        certResolver: letsencrypt
      service: aerodocs-grpc
  services:
    aerodocs:
      loadBalancer:
        servers:
          - url: "http://192.0.2.10:8081"
    aerodocs-grpc:
      loadBalancer:
        servers:
          - url: "h2c://192.0.2.10:9090"
```

In the AeroDocs container, bind the HTTP and gRPC ports to `0.0.0.0` so Traefik can reach them across the LXC network.

---

## DNS Setup

Point your domain's A record (and AAAA for IPv6) to the public IP of the server running Traefik.

```
aerodocs.example.com.  IN  A  203.0.113.10
```

Traefik will automatically obtain a Let's Encrypt certificate on first request once the DNS record propagates.

---

## Database Management

AeroDocs uses SQLite with WAL mode. The database is a single file.

- **Docker:** The database lives at `/data/aerodocs.db` inside the container, persisted via the `aerodocs-data` named volume.
- **Bare-metal:** The database path is set via the `--db` flag (default: `aerodocs.db`).

**Auto-migrations**: On every startup, the Hub checks for and applies any unapplied migration files. No manual schema management is needed after upgrades.

**Backups**: SQLite's WAL mode makes it safe to copy the database file while the Hub is running. To take a consistent snapshot:

```bash
# Docker - use docker exec to run sqlite3 inside the container
docker exec aerodocs sqlite3 /data/aerodocs.db ".backup /data/backup-$(date +%Y%m%d).db"

# Bare-metal
sqlite3 /var/lib/aerodocs/aerodocs.db ".backup /var/lib/aerodocs/backup-$(date +%Y%m%d).db"
```

Store backups off-host. The database contains all user accounts, server registrations, and audit logs.

---

## CLI Break-Glass: Emergency TOTP Reset

If an admin is locked out (lost their authenticator app), use the `admin reset-totp` command directly on the server hosting the Hub. This requires shell access to the machine - it cannot be triggered via the web UI.

```bash
# If running via Docker
docker exec aerodocs /app/aerodocs admin reset-totp --username <username> --db /data/aerodocs.db

# If running as a bare-metal binary
./bin/aerodocs admin reset-totp --username <username> --db /var/lib/aerodocs/aerodocs.db
```

This will:
1. Clear the user's TOTP secret and mark TOTP as disabled
2. Generate a new temporary password
3. Print the temporary password to stdout

The user must set up TOTP again on their next login. The operation is recorded in the audit log.

**If the database is locked (bare-metal only):**

```bash
systemctl stop aerodocs
./bin/aerodocs admin reset-totp --username admin --db /var/lib/aerodocs/aerodocs.db
systemctl start aerodocs
```

In practice the Hub does not hold exclusive locks on the database (WAL mode), so running the command while the service is live is usually safe.

---

## Updating / Redeploying

### Docker (recommended)

```bash
docker compose pull
docker compose up -d
```

New migrations (if any) run automatically on startup.

### Bare-metal

1. Build the new binary from source (`make build`)
2. Copy the binary to the server:
   ```bash
   scp bin/aerodocs user@yourserver:/opt/aerodocs/bin/aerodocs.new
   ```
3. Swap the binary and restart:
   ```bash
   mv /opt/aerodocs/bin/aerodocs.new /opt/aerodocs/bin/aerodocs
   systemctl restart aerodocs
   ```
4. New migrations (if any) run automatically on startup.

---

## Building from Source

For contributors or those who prefer running a bare-metal binary.

### Prerequisites

- Go 1.26+
- Node.js 25+
- Make

### Build

```bash
git clone https://github.com/lorconksu/aerodocs.git
cd aerodocs
make build
```

The `make build` target runs three steps in sequence:

1. `build-web` - Runs `npm run build` inside `web/`, producing `web/dist/`
2. `embed-web` - Copies `web/dist/` to `hub/web/dist/` so it's picked up by `go:embed`
3. `build-hub` - Compiles `hub/cmd/aerodocs/` into `bin/aerodocs`

The output is a single self-contained binary at `bin/aerodocs`. No Node.js, no separate web server, no external dependencies at runtime.

### Running the binary

```bash
./bin/aerodocs [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | HTTP listen address and port |
| `--grpc-addr` | `:9090` | gRPC listen address for agent connections |
| `--db` | `aerodocs.db` | Path to the SQLite database file |
| `--agent-bin-dir` | `` | Directory containing agent binaries served via `/install/{os}/{arch}` |
| `--require-mtls` | `false` | Require agents to present valid mTLS certificates (v1.1+) |
| `--grpc-external-addr` | `` | External gRPC address shown in install commands (e.g. `aerodocs.example.com:9443`). Overridable from the admin UI. |
| `--dev` | `false` | Enable development mode (permissive CORS, no embedded frontend served) |

**Example:**

```bash
./bin/aerodocs \
  --addr 127.0.0.1:8081 \
  --grpc-addr 0.0.0.0:9090 \
  --db /var/lib/aerodocs/aerodocs.db \
  --agent-bin-dir /opt/aerodocs/agent-bins
```

Bind HTTP to `127.0.0.1` (loopback only) when running behind a reverse proxy. The gRPC port (`9090`) must be reachable by agents - bind to `0.0.0.0` or the server's public interface.

On first run, migrations execute automatically and the database file is created. Navigate to your domain in a browser to complete initial setup.

### Systemd service

Create `/etc/systemd/system/aerodocs.service`:

```ini
[Unit]
Description=AeroDocs Hub
After=network.target

[Service]
Type=simple
User=aerodocs
Group=aerodocs
WorkingDirectory=/opt/aerodocs
ExecStart=/opt/aerodocs/bin/aerodocs \
  --addr 127.0.0.1:8081 \
  --grpc-addr 0.0.0.0:9090 \
  --db /var/lib/aerodocs/aerodocs.db \
  --agent-bin-dir /opt/aerodocs/agent-bins
Restart=on-failure
RestartSec=5s

# Harden the service
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/aerodocs /opt/aerodocs/agent-bins
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Create the user and directories
useradd --system --no-create-home --shell /usr/sbin/nologin aerodocs
mkdir -p /opt/aerodocs/bin /var/lib/aerodocs
cp bin/aerodocs /opt/aerodocs/bin/aerodocs
chown -R aerodocs:aerodocs /opt/aerodocs /var/lib/aerodocs

# Enable and start
systemctl daemon-reload
systemctl enable aerodocs
systemctl start aerodocs
systemctl status aerodocs
```
