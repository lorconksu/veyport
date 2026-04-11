<p align="center">
  <img src="web/public/aerodoc-vertical.png" alt="AeroDocs" width="160" />
</p>

<p align="center">
  <strong>Secure remote file access and server operations from one web UI</strong><br>
  Browse files, stream logs, and move data across your servers from a self-hosted control plane built for small fleets.
</p>

<p align="center">
  <a href="https://github.com/lorconksu/aerodocs/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/lorconksu/aerodocs/ci.yml?branch=main&label=CI" alt="CI status" />
  </a>
  <a href="https://github.com/lorconksu/aerodocs/releases">
    <img src="https://img.shields.io/github/v/release/lorconksu/aerodocs?sort=semver&label=release" alt="Latest release" />
  </a>
  <img src="https://img.shields.io/badge/go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go 1.26+" />
  <img src="https://img.shields.io/badge/react-19-20232A?logo=react" alt="React 19" />
  <a href="https://github.com/lorconksu/aerodocs/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-0f766e" alt="License Apache 2.0" />
  </a>
</p>

<p align="center">
  <img src="docs/wiki/screenshots/dashboard.png" alt="AeroDocs Dashboard" width="800" />
</p>

## What is AeroDocs?

AeroDocs gives you secure, day-to-day access to your servers through one self-hosted web interface. Browse remote file systems, stream logs in real time, and transfer files without handing out SSH keys or bouncing between terminal sessions.

It runs as a single binary with no external dependencies. The Hub embeds the full React frontend and uses SQLite for storage, so setup stays lightweight: no separate database, no extra services, and no runtime sprawl. Deploy it once and connect your agents.

AeroDocs is built for home lab operators and small teams who need dependable access, clear audit trails, and tight operational control. Every action is logged, every user requires 2FA, and permissions are scoped per-server and per-path.

AeroDocs is open source software licensed under the Apache License 2.0. The
software license does not grant rights to the `AeroDocs` name or logos; see
[TRADEMARKS.md](TRADEMARKS.md) for branding rules and [CONTRIBUTING.md](CONTRIBUTING.md)
for issue and pull-request expectations.

## Features

- **Fleet Dashboard** — At-a-glance health overview of all connected servers with live status, search, and filtering
- **Real-time Log Tailing** — Live log streaming over SSE with server-side grep/filter, pause/resume, and terminal-like UI
- **Remote File Browser** — Browse remote file systems with syntax highlighting for 16 languages; resizable sidebar, refresh button, and binaries/forbidden paths shown but greyed out
- **Secure File Transfers (Dropzone)** — Admin-only drag-and-drop chunked file uploads to a quarantined staging directory on the target server
- **Email Notifications** — 8 configurable alert types (agent connect/disconnect, file uploads, login events, and more)
- **Audit Logging** — Immutable record of every action with 23 event types — who did what, when, and from where
- **2FA (TOTP)** — Mandatory TOTP-based two-factor authentication for all users, no exceptions
- **Role-Based Access** — Admin and Viewer roles with per-server, per-path permissions enforced at both Hub and Agent layers
- **mTLS Agent Communication** — Hub-issued 12-hour ECDSA P-256 client certificates with automatic in-stream renewal

## Architecture

AeroDocs uses a **Hub-and-Spoke** model. The Hub is the central server that hosts the web UI, REST API, and SQLite database. Agents are lightweight binaries deployed on each remote server, maintaining persistent gRPC streams back to the Hub.

![AeroDocs Architecture](docs/screenshots/aerodocs-architecture.png)

- **Hub** — Central Go server. Serves the web UI, exposes REST APIs, manages SQLite, and enforces all authentication and permissions. Runs HTTP on `:8081` and gRPC on `:9090`.
- **Agent** — Lightweight Go binary on each remote server. Maintains a persistent bidirectional gRPC stream to the Hub, executing file, log, and upload commands on demand.
- **Frontend** — React SPA embedded into the Hub binary via `go:embed`. Single-binary deployment with zero external dependencies.

For the full architecture breakdown, see [Architecture](docs/wiki/Architecture.md).

## Quick Start

```bash
# Download the compose file
curl -O https://raw.githubusercontent.com/lorconksu/aerodocs/main/docker-compose.yml

# Start AeroDocs
docker compose up -d
```

The Hub starts on port 8081 (HTTP) and 9090 (gRPC). Open `http://localhost:8081` to create the initial admin account and set up 2FA.

### Agent Installation

From the Hub web UI, click **Add Server** and run the generated install command on each target machine:

```bash
curl -fsSL https://<hub-address>/api/install.sh | sudo bash -s -- \
  --hub grpc://<hub-address>:9443 \
  --token <registration-token>
```

The agent installs as a systemd service, connects to the Hub over gRPC with mTLS, and appears on the dashboard within seconds.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Go 1.26+ |
| Frontend | React 19 + TypeScript + Vite + Tailwind CSS v4 |
| Database | SQLite (WAL mode, via `modernc.org/sqlite`, pure Go) |
| Hub-Agent | gRPC with bidirectional streaming + mTLS (ECDSA P-256) |
| Hub-Browser | REST + SSE (Server-Sent Events) |
| UI Components | shadcn/ui (heavily customized) + lucide-react icons |
| Syntax Highlighting | highlight.js (16 languages) |
| Markdown | react-markdown + remark-gfm + Mermaid diagrams |

## Security

| Area | Implementation |
|------|---------------|
| Password Hashing | bcrypt (cost 12) |
| Two-Factor Auth | TOTP with mandatory enrollment for all users |
| Session Tokens | JWT with httpOnly / Secure / SameSite=Strict cookies |
| CSRF Protection | Double-submit cookie pattern |
| Rate Limiting | Per-IP rate limiting on auth endpoints |
| XSS Protection | DOMPurify sanitization + Content Security Policy headers |
| Path Traversal | Server-side path canonicalization + symlink resolution |
| Sensitive Paths | Blocklist enforcement at both Hub and Agent layers |
| Agent Auth | mTLS with Hub-issued 12-hour ECDSA P-256 certificates |
| SMTP Credentials | AES-256-GCM encryption at rest |
| Token Blacklist | Persistent across restarts (SQLite-backed) |
| Session Invalidation | Password change invalidates all sessions |
| gRPC Limits | 256 KB max receive message size |
| Version Disclosure | Hidden from unauthenticated users |
| Cache-Control | `no-store` on all API responses |

## Documentation

- [Engineering Docs](docs/engineering/) — Architecture, deployment, security model, API reference, gRPC protocol
- [User Wiki](docs/wiki/) — End-user documentation and walkthroughs
- [API Reference](docs/engineering/api-reference.md) — Complete REST API endpoint documentation
- [Deployment Guide](docs/engineering/deployment.md) — Production deployment and reverse proxy setup
- [Security Model](docs/engineering/security-model.md) — Threat model and security controls

## License

AeroDocs is open source software licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for attribution details and [TRADEMARKS.md](TRADEMARKS.md) for name and branding rules.
