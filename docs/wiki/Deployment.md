# Veyport Deployment Guide

> **TL;DR**
> - **What:** Docker-first deployment with a single `docker-compose.yml`; bare-metal binary also available
> - **Who:** The person deploying Veyport Hub and agents
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
curl -O https://raw.githubusercontent.com/lorconksu/veyport/main/docker-compose.yml

# Start Veyport
docker compose up -d
```

The Hub starts on port 8081 (HTTP) and 9090 (gRPC). Open `http://localhost:8081` in your browser to create the initial admin account and set up 2FA. Then run the one-liner shown in the UI on each server you want to manage.

That's it. No cloning, no building, no dependencies.

---

## Docker Compose Configuration

The default `docker-compose.yml`:

```yaml
services:
  veyport:
    image: yiucloud/veyport:latest
    container_name: veyport
    ports:
      - "8081:8081"   # HTTP - web UI and REST API
      - "9090:9090"   # gRPC - agent connections
    volumes:
      - veyport-data:/data   # SQLite DB and persistent state
    restart: unless-stopped

volumes:
  veyport-data:
```

### Configuration details

| Setting | Value | Notes |
|---------|-------|-------|
| Image | `yiucloud/veyport:latest` | Pin to a specific tag (e.g. `yiucloud/veyport:vX.Y.Z`) for reproducible deployments |
| HTTP port | `8081` | Web UI and REST API |
| gRPC port | `9090` | Agent connections - must be reachable by agents |
| Data volume | `veyport-data` mounted at `/data` | Contains the SQLite database (`/data/veyport.db`) and all persistent state |
| Binary path | `/app/veyport` | The Hub binary inside the container |

### Pinning a version

Replace `latest` with a specific version tag to avoid unexpected upgrades:

```yaml
image: yiucloud/veyport:vX.Y.Z
```

---

## Running Behind Traefik

### Docker Compose with Traefik labels

If Traefik is also running in Docker, add labels to the Veyport service. Create a `docker-compose.traefik.yml`:

```yaml
services:
  veyport:
    image: yiucloud/veyport:latest
    container_name: veyport
    volumes:
      - veyport-data:/data
    restart: unless-stopped
    labels:
      # HTTP router - web UI and REST API
      - "traefik.enable=true"
      - "traefik.http.routers.veyport.rule=Host(`veyport.example.com`)"
      - "traefik.http.routers.veyport.entrypoints=websecure"
      - "traefik.http.routers.veyport.tls.certresolver=letsencrypt"
      - "traefik.http.routers.veyport.service=veyport"
      - "traefik.http.services.veyport.loadbalancer.server.port=8081"

      # gRPC router - agent connections (path prefix matches the proto package)
      - "traefik.http.routers.veyport-grpc.rule=Host(`veyport.example.com`) && PathPrefix(`/veyport.v1.`)"
      - "traefik.http.routers.veyport-grpc.entrypoints=websecure"
      - "traefik.http.routers.veyport-grpc.tls.certresolver=letsencrypt"
      - "traefik.http.routers.veyport-grpc.service=veyport-grpc"
      - "traefik.http.services.veyport-grpc.loadbalancer.server.port=9090"
      - "traefik.http.services.veyport-grpc.loadbalancer.server.scheme=h2c"
    networks:
      - traefik

volumes:
  veyport-data:

networks:
  traefik:
    external: true
```

No port mappings are needed when Traefik handles routing - traffic flows through the Docker network.

### Bare-metal Traefik (file provider)

If Traefik runs outside Docker, use a file provider config. Create `/etc/traefik/dynamic/veyport.yml`:

```yaml
http:
  routers:
    # HTTP and REST API traffic
    veyport:
      rule: "Host(`veyport.example.com`)"
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: veyport

    # gRPC traffic from agents (path prefix matches the proto package)
    veyport-grpc:
      rule: "Host(`veyport.example.com`) && PathPrefix(`/veyport.v1.`)"
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
      service: veyport-grpc

  services:
    veyport:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:8081"

    # h2c (cleartext HTTP/2) is required for gRPC backends without TLS
    veyport-grpc:
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

Traefik handles TLS termination (Let's Encrypt). The Hub sees plain HTTP on port 8081 and cleartext gRPC (h2c) on port 9090. The `PathPrefix('/veyport.v1.')` matcher routes agent gRPC connections correctly because gRPC uses the proto package path as the HTTP/2 `:path` header.

---

## Agent Deployment

Agents are lightweight Go binaries deployed on each managed server. They dial out to the Hub's gRPC port - no inbound firewall rules are needed on the agent host.

### One-command install (recommended)

The Hub serves an install script and the agent binaries. On the managed server, run:

```bash
curl -sSL https://veyport.example.com/install.sh | sudo bash -s -- \
  --token <REGISTRATION_TOKEN> \
  --hub veyport.example.com:443
```

The script will:
1. Detect the OS and CPU architecture
2. **Auto-detect an existing installation** - if `veyport-agent` is already installed and has a valid `agent.conf`, the script calls `veyport-agent --self-unregister` to remove the old server entry from the Hub before proceeding
3. Download the correct agent binary from `/install/{os}/{arch}`
4. Write the configuration to `/etc/veyport/agent.conf`
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
curl -Lo /usr/local/bin/veyport-agent \
  https://veyport.example.com/install/linux/amd64
chmod +x /usr/local/bin/veyport-agent

# Run directly
/usr/local/bin/veyport-agent \
  --hub veyport.example.com:443 \
  --token <REGISTRATION_TOKEN>
```

### Agent configuration file

After first registration, the agent writes its assigned `server_id` and `hub_url` to:

```
/etc/veyport/agent.conf
```

Example contents (JSON):

```json
{
  "server_id": "550e8400-e29b-41d4-a716-446655440000",
  "hub_url": "veyport.example.com:443"
}
```

On restart, the agent loads this file and reconnects without needing the registration token again.

### Agent systemd service

The install script creates `/etc/systemd/system/veyport-agent.service`:

```ini
[Unit]
Description=Veyport Agent
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/veyport/agent.env
ExecStart=/bin/sh -eu -c 'if [ -f /etc/veyport/agent.conf ]; then exec /usr/local/bin/veyport-agent; else exec /usr/local/bin/veyport-agent --hub "$VEYPORT_HUB" --token "$VEYPORT_TOKEN" --ca-pin "$VEYPORT_HUB_CA_PIN"; fi'
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

### Agent flags

| Flag | Description |
|------|-------------|
| `--hub <addr>` | Hub gRPC address (e.g. `veyport.example.com:443` or `192.168.1.10:9090`) |
| `--token <token>` | One-time registration token obtained from the Hub when creating a server record |
| `--self-unregister` | Calls `DELETE /api/servers/{id}/self-unregister` on the Hub to remove the current server entry, then exits. Used by the install script before re-installing to clean up the old registration. Requires a valid `agent.conf` with a known `server_id`. |

### TLS auto-detection

The agent infers the connection security mode from the hub address:
- **Hostname** (e.g. `veyport.example.com:443`) - TLS enabled
- **IP address** (e.g. `192.168.1.10:9090`) - insecure (no TLS)

### Reconnect behavior

The agent reconnects with **exponential backoff** - starting at 1 second and capping at 60 seconds. On each reconnect it re-sends a `Register` message so the Hub updates sysinfo and resets connection state.

### Network requirements

| Direction | Protocol | Port | Notes |
|-----------|----------|------|-------|
| Agent - Hub | gRPC (HTTP/2) | 9090 (or 443 via Traefik) | Must be reachable from agent host |
| Hub - Agent | None | - | Agents always dial out; Hub never initiates |

---

## LDAP Login and Terminal Access

Veyport can authenticate users against LDAP and map LDAP groups to Veyport roles. LDAP is currently configured through the Hub `_config` table by an operator with database access.

### LDAP configuration keys

| Key | Purpose |
|-----|---------|
| `ldap.enabled` | Enables LDAP login when set to `true` |
| `ldap.url` | LDAP endpoint, such as `ldaps://freeipa.example.com:636` |
| `ldap.bind_dn` | Optional service account DN used for searches |
| `ldap.bind_password` | Service account password; encrypted `enc:` values are preferred |
| `ldap.user_base_dn` | Base DN for user searches |
| `ldap.group_base_dn` | Base DN for group searches |
| `ldap.user_search_filter` | User search filter, default `(uid={username})` |
| `ldap.group_search_filter` | Group search filter, default `(|(member={dn})(memberUid={username}))` |
| `ldap.username_attribute` | Username attribute, default `uid` |
| `ldap.email_attribute` | Email attribute, default `mail` |
| `ldap.external_id_attribute` | Stable external ID attribute, default `entryUUID` |
| `ldap.group_name_attribute` | Group display/name attribute, default `cn` |
| `ldap.start_tls` | Uses StartTLS with `ldap://` when set to `true` |
| `ldap.tls_server_name` | Optional TLS server name override |
| `ldap.ca_cert_pem` | Optional PEM CA bundle for LDAP server verification |
| `ldap.allow_insecure_transport` | Allows plaintext LDAP only for lab use |

LDAP transport is fail-closed by default. Use `ldaps://` or set `ldap.start_tls=true`; plaintext `ldap://` is rejected unless `ldap.allow_insecure_transport=true`.

### Default group mapping

| LDAP group | Veyport effect |
|------------|----------------|
| `veyport-admins` | Admin role |
| `veyport-auditors` | Auditor role |
| `veyport-viewers` | Viewer role |
| `veyport-terminal-users` | Marks the LDAP user as eligible for terminal access |

Terminal access has an additional server-level gate. LDAP terminal users must also have a root (`/`) path assignment on the specific server. Local non-admin users cannot open terminal sessions.

---

## mTLS Configuration (v1.1)

As of v1.1, the Hub supports mutual TLS (mTLS) for gRPC connections from agents. This provides cryptographic identity verification beyond the initial registration token.

### How it works

1. **Automatic CA generation** -- On first boot, the Hub generates an ECDSA P-256 Certificate Authority. No manual certificate management is required.
2. **Agent certificates issued during registration** -- When an agent registers, the Hub signs a client certificate (12-hour validity) and sends it to the agent over the gRPC stream.
3. **In-stream renewal** -- Agents automatically renew their certificates at the 6-hour mark (50% lifetime), with no downtime or reconnection.
4. **Agent cert storage** -- Client certificates and keys are stored at `/etc/veyport/tls/` on each agent host.

### Enabling mandatory mTLS

By default, mTLS is optional for backward compatibility. Agents that support mTLS will use it; older agents continue to work without it.

To enforce mTLS for all agent connections, add the `--require-mtls` flag:

```bash
# Docker: add to the command in docker-compose.yml
command: ["--require-mtls"]

# Bare-metal: add to the ExecStart line in the systemd unit
ExecStart=/opt/veyport/bin/veyport \
  --addr 127.0.0.1:8081 \
  --grpc-addr 0.0.0.0:9090 \
  --db /var/lib/veyport/veyport.db \
  --agent-bin-dir /opt/veyport/agent-bins \
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
| Client cert | `/etc/veyport/tls/client.crt` | Agent's certificate signed by Hub CA |
| Client key | `/etc/veyport/tls/client.key` | Agent's private key (never leaves the machine) |
| CA cert | `/etc/veyport/tls/ca.crt` | Hub CA certificate for verifying the Hub |

---

## Cookie-Based Authentication (v1.1)

As of v1.1, the web UI uses **httpOnly cookies** for JWT token storage instead of localStorage. This change is fully automatic -- no configuration is needed.

- Tokens are set as `HttpOnly`, `Secure`, `SameSite=Strict` cookies
- CSRF protection uses a double-submit cookie pattern (handled by the frontend automatically)
- Non-browser clients (scripts, CLI tools) can still use `Authorization: Bearer <token>` headers
- The refresh token cookie is scoped to `/api/auth/refresh` to limit exposure

No action is required from operators. The cookie auth is active by default when upgrading to v1.1.

---

## Machine Auth for Scripts

If you are automating Veyport from cron, CI, or a scanner, do not script a human username/password/TOTP flow. Use a dedicated service account plus a CLI-created API token instead.

### Create a dedicated token

```bash
# Docker deployment
docker exec veyport /app/veyport admin create-api-token \
  --username scanner \
  --name nightly-scan \
  --expires-in 720h \
  --db /data/veyport.db

# Bare-metal deployment
./bin/veyport admin create-api-token \
  --username scanner \
  --name nightly-scan \
  --expires-in 720h \
  --db /var/lib/veyport/veyport.db
```

Store the printed token in a root-only env file on the machine that runs the automation:

```bash
sudo install -m 600 /dev/null /opt/veyport/nightly-security-scan.env
sudo editor /opt/veyport/nightly-security-scan.env
```

Example contents:

```bash
VEYPORT_SCAN_BASE_URL=https://veyport.example.com
VEYPORT_API_TOKEN=adt_replace_me
SONAR_TOKEN=replace_me
CLAUDE_BIN=/home/wyiu/.local/bin/claude
```

The sample file is included in the repo at `scripts/nightly-security-scan.env.example`.

### Claude CLI auth for cron

The nightly scan also depends on Claude CLI itself being authenticated. For unattended jobs, prefer a long-lived Claude token on the scan host:

```bash
/home/wyiu/.local/bin/claude setup-token
```

If you prefer the normal browser-backed login flow, refresh it with:

```bash
/home/wyiu/.local/bin/claude auth login
```

The nightly scan script now performs a short preflight request before the full run and exits early with a clear error if Claude auth is stale.

---

## LXC Container Deployment

Veyport can be deployed in a Proxmox LXC container as a lightweight alternative to a full VM. This is useful for home lab and small-team deployments.

### Setup steps

1. **Create an unprivileged LXC container** (Debian/Ubuntu) with at least 512 MB RAM and 4 GB disk.
2. **Install Docker** inside the container (requires the `keyctl` and `nesting` features enabled on the LXC).
3. **Deploy with Docker Compose** using the same `docker-compose.yml` as any other deployment.
4. **Configure Traefik** on the host or a separate LXC to reverse-proxy HTTPS traffic to the container's IP.

### Example: Proxmox LXC with Traefik

If Traefik runs on a separate LXC and Veyport runs in another container at `192.0.2.10`:

```yaml
# /etc/traefik/dynamic/veyport.yml on the Traefik host
http:
  routers:
    veyport:
      rule: "Host(`veyport.example.com`)"
      entryPoints: [websecure]
      tls:
        certResolver: letsencrypt
      service: veyport
    veyport-grpc:
      rule: "Host(`veyport.example.com`) && PathPrefix(`/veyport.v1.`)"
      entryPoints: [websecure]
      tls:
        certResolver: letsencrypt
      service: veyport-grpc
  services:
    veyport:
      loadBalancer:
        servers:
          - url: "http://192.0.2.10:8081"
    veyport-grpc:
      loadBalancer:
        servers:
          - url: "h2c://192.0.2.10:9090"
```

In the Veyport container, bind the HTTP and gRPC ports to `0.0.0.0` so Traefik can reach them across the LXC network.

---

## DNS Setup

Point your domain's A record (and AAAA for IPv6) to the public IP of the server running Traefik.

```
veyport.example.com.  IN  A  203.0.113.10
```

Traefik will automatically obtain a Let's Encrypt certificate on first request once the DNS record propagates.

---

## Database Management

Veyport uses SQLite with WAL mode. The database is a single file.

- **Docker:** The database lives at `/data/veyport.db` inside the container, persisted via the `veyport-data` named volume.
- **Bare-metal:** The database path is set via the `--db` flag (default: `veyport.db`).

**Auto-migrations**: On every startup, the Hub checks for and applies any unapplied migration files. No manual schema management is needed after upgrades.

**Backups**: SQLite's WAL mode makes it safe to copy the database file while the Hub is running. To take a consistent snapshot:

```bash
# Docker - use docker exec to run sqlite3 inside the container
docker exec veyport sqlite3 /data/veyport.db ".backup /data/backup-$(date +%Y%m%d).db"

# Bare-metal
sqlite3 /var/lib/veyport/veyport.db ".backup /var/lib/veyport/backup-$(date +%Y%m%d).db"
```

Store backups off-host. The database contains all user accounts, server registrations, and audit logs.

---

## CLI Break-Glass: Emergency TOTP Reset

If an admin is locked out (lost their authenticator app), use the `admin reset-totp` command directly on the server hosting the Hub. This requires shell access to the machine - it cannot be triggered via the web UI.

```bash
# If running via Docker
docker exec veyport /app/veyport admin reset-totp --username <username> --db /data/veyport.db

# If running as a bare-metal binary
./bin/veyport admin reset-totp --username <username> --db /var/lib/veyport/veyport.db
```

This will:
1. Clear the user's TOTP secret and mark TOTP as disabled
2. Generate a new temporary password
3. Print the temporary password to stdout

The user must set up TOTP again on their next login. The operation is recorded in the audit log.

**If the database is locked (bare-metal only):**

```bash
systemctl stop veyport
./bin/veyport admin reset-totp --username admin --db /var/lib/veyport/veyport.db
systemctl start veyport
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
   scp bin/veyport user@yourserver:/opt/veyport/bin/veyport.new
   ```
3. Swap the binary and restart:
   ```bash
   mv /opt/veyport/bin/veyport.new /opt/veyport/bin/veyport
   systemctl restart veyport
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
git clone https://github.com/lorconksu/veyport.git
cd veyport
make build
```

The `make build` target runs three steps in sequence:

1. `build-web` - Runs `npm run build` inside `web/`, producing `web/dist/`
2. `embed-web` - Copies `web/dist/` to `hub/web/dist/` so it's picked up by `go:embed`
3. `build-hub` - Compiles `hub/cmd/veyport/` into `bin/veyport`

The output is a single self-contained binary at `bin/veyport`. No Node.js, no separate web server, no external dependencies at runtime.

### Running the binary

```bash
./bin/veyport [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | HTTP listen address and port |
| `--grpc-addr` | `:9090` | gRPC listen address for agent connections |
| `--db` | `veyport.db` | Path to the SQLite database file |
| `--agent-bin-dir` | `` | Directory containing agent binaries served via `/install/{os}/{arch}` |
| `--require-mtls` | `false` | Require agents to present valid mTLS certificates (v1.1+) |
| `--grpc-external-addr` | `` | External gRPC address shown in install commands (e.g. `veyport.example.com:9443`). Overridable from the admin UI. |
| `--dev` | `false` | Enable development mode (permissive CORS, no embedded frontend served) |

**Example:**

```bash
./bin/veyport \
  --addr 127.0.0.1:8081 \
  --grpc-addr 0.0.0.0:9090 \
  --db /var/lib/veyport/veyport.db \
  --agent-bin-dir /opt/veyport/agent-bins
```

Bind HTTP to `127.0.0.1` (loopback only) when running behind a reverse proxy. The gRPC port (`9090`) must be reachable by agents - bind to `0.0.0.0` or the server's public interface.

On first run, migrations execute automatically and the database file is created. Navigate to your domain in a browser to complete initial setup.

### Systemd service

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

Enable and start:

```bash
# Create the user and directories
useradd --system --no-create-home --shell /usr/sbin/nologin veyport
mkdir -p /opt/veyport/bin /var/lib/veyport
cp bin/veyport /opt/veyport/bin/veyport
chown -R veyport:veyport /opt/veyport /var/lib/veyport

# Enable and start
systemctl daemon-reload
systemctl enable veyport
systemctl start veyport
systemctl status veyport
```
