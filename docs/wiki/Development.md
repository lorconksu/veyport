# Veyport Development Guide

> **TL;DR**
> - **What:** Local development setup with Go backend + Vite frontend dev server
> - **Who:** Contributors and developers working on Veyport
> - **Why:** Hot-reload frontend, API proxy, full-stack local testing
> - **Where:** Two terminals: `make dev-hub` (Go on :8080) + `make dev-web` (Vite on :5173)
> - **When:** After cloning the repo and installing prerequisites (Go 1.26+, Node 25+, Make)
> - **How:** Vite proxies `/api` to Go backend; `make build` for production binary; `make test` for test suite

## Prerequisites

- Go 1.26+
- Node.js 25+
- Make
- Git

---

## Clone and Setup

```bash
git clone https://github.com/lorconksu/veyport.git
cd veyport

# Install frontend dependencies
cd web && npm install && cd ..
```

---

## Proto Generation

The agent-hub gRPC contract is defined in `proto/veyport/v1/agent.proto`. After modifying the proto file, regenerate the Go bindings.

**Prerequisites:**

```bash
# Install protoc (Protocol Buffers compiler)
# On Ubuntu/Debian:
apt install - y protobuf-compiler

# Install the Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

**Generate:**

```bash
make proto
```

This runs `protoc` with the `--go_out` and `--go-grpc_out` flags, writing generated files alongside the proto source.

---

## Running in Development

The development environment runs two processes - open two terminal windows.

**Terminal 1 - Hub (HTTP on :8080, gRPC on :9090):**

```bash
make dev-hub
```

This runs `go run ./cmd/veyport/ --dev --addr :8080 --grpc-addr :9090` from the `hub/` directory. The `--dev` flag enables permissive CORS so the Vite dev server can make cross-origin API requests, and disables serving the embedded frontend (Vite handles that instead). Both the HTTP API and gRPC agent listener start together.

**Terminal 2 - Vite dev server (UI on :5173):**

```bash
make dev-web
```

This runs `npm run dev` from the `web/` directory. Navigate to `http://localhost:5173` in your browser.

### Local LAN testing with login

When testing from another machine on the LAN, use HTTPS instead of plain HTTP:

```bash
make dev-web-lan
```

The Hub always sets `Secure` auth cookies. Browsers will not persist those cookies over `http://<lan-ip>:5173`, which makes login appear to loop even when the password is correct. The `dev-web-lan` target starts Vite on `0.0.0.0:5173` with a local self-signed certificate and proxies API requests to the running Hub. If a Hub is already listening on `127.0.0.1:8081`, that target is used; otherwise it falls back to `127.0.0.1:8080`. Override it explicitly with `VITE_API_PROXY_TARGET=http://127.0.0.1:<port> make dev-web-lan`.

Open the `https://<lan-ip>:5173/` URL shown by the command and accept the browser warning for the self-signed certificate.

On first run, you'll be directed to the setup page to create your admin account and configure TOTP.

### How the Vite proxy works

The Vite config in `web/vite.config.ts` includes a proxy rule:

```typescript
server: {
  proxy: {
    '/api': 'http://localhost:8080',
  },
},
```

Any request the browser makes to `/api/*` is forwarded by Vite to the Go Hub on port 8080. This means the browser always talks to `localhost:5173` (no CORS issues from the browser's perspective), and Vite silently proxies the API calls. In production there is no proxy - the Hub serves both the SPA and the API on the same port.

---

## Building for Production

```bash
make build
```

Output: `bin/veyport` - a single self-contained binary.

---

## Running Tests

```bash
make test
```

This runs the Go test suites for both the Hub and the Agent:

- `auth/` - JWT generation, validation, token type enforcement, bcrypt, TOTP
- `store/` - All store methods against a real in-memory SQLite database (including notification preferences and log)
- `server/` - HTTP handler tests using `httptest` (including SMTP, notification, and hub config handlers)
- `notify/` - SMTP client tests, template rendering, CRLF injection prevention, debounce logic
- `grpcserver/` - HeartbeatCoalescer tests, handler tests

### Agent tests

```bash
make test-agent
```

Runs `go test ./...` from the `agent/` directory.

### Frontend tests

```bash
cd web && npx vitest run
```

The CI pipeline also runs integration, smoke, and e2e suites on pull requests.

---

## Building the Agent

The agent is cross-compiled for the two supported targets:

```bash
make build-agent
```

This produces:
- `bin/veyport-agent-linux-amd64`
- `bin/veyport-agent-linux-arm64`

Place these in the Hub's `--agent-bin-dir` so they are served via `/install/{os}/{arch}`.

---

## Testing with a Local Agent

To exercise the full Hub + Agent stack locally:

**Terminal 1 - Start the Hub:**

```bash
./bin/veyport \
  --addr :8080 \
  --grpc-addr :9090 \
  --db test.db \
  --dev
```

**In the UI:**

1. Create a server record (Admin → Servers → Add Server).
2. Copy the registration token shown on the server detail page.

**Terminal 2 - Run the agent:**

```bash
./bin/veyport-agent-linux-amd64 \
  --hub localhost:9090 \
  --token <REGISTRATION_TOKEN>
```

The agent connects over insecure gRPC (no TLS - detected automatically because the hub address is an IP/localhost). The server status in the UI will change to `online` within a few seconds.

---

## Project Structure Walkthrough

```
veyport/
├── Makefile                    # Build orchestration
├── proto/
│   └── veyport/
│       └── v1/
│           └── agent.proto     # gRPC service definition for Hub-Agent communication
├── hub/
│   ├── embed.go                # go:embed directive pointing at web/dist
│   ├── go.mod / go.sum
│   ├── cmd/
│   │   └── veyport/
│   │       ├── main.go         # Flag parsing, wiring, graceful shutdown
│   │       └── admin.go        # CLI admin subcommands
│   └── internal/
│       ├── auth/
│       │   ├── jwt.go          # Token generation and validation
│       │   ├── password.go     # bcrypt helpers + password policy
│       │   └── totp.go         # TOTP secret generation + code verification
│       ├── ca/                 # Hub Certificate Authority for mTLS (ECDSA P-256)
│       ├── connmgr/            # Agent connection manager (active streams + SendMu)
│       ├── grpcserver/         # gRPC server, Connect handler, PendingRequests, LogSessions, HeartbeatCoalescer
│       ├── migrate/
│       │   ├── migrate.go      # Migration runner
│       │   └── migrations/     # Numbered .sql files (001_, 002_, ...)
│       ├── model/
│       │   ├── user.go         # User, request/response types
│       │   ├── server.go       # Server, request/response types
│       │   ├── audit.go        # AuditEntry, action constants
│       │   └── notification.go # Notification types, SMTP config, alert event definitions
│       ├── notify/
│       │   ├── notifier.go     # Notification dispatcher (debounce, priority queue, background worker)
│       │   ├── smtp.go         # SMTP client with TLS support and CRLF injection prevention
│       │   └── templates.go    # Email HTML templates and context rendering
│       ├── server/
│       │   ├── server.go       # Server struct, Init, SPA handler
│       │   ├── router.go       # Route registration
│       │   ├── middleware.go   # Auth middleware, rate limiter, CORS, logging
│       │   ├── respond.go      # respondJSON / respondError helpers
│       │   ├── handlers_auth.go
│       │   ├── handlers_servers.go
│       │   ├── handlers_users.go
│       │   ├── handlers_audit.go
│       │   ├── handlers_notifications.go  # SMTP config, notification preferences, notification log
│       │   ├── handlers_terminal.go       # Browser terminal session lifecycle
│       │   ├── ldap_auth.go               # LDAP bind/search authentication and group mapping
│       │   └── handlers_hub_config.go     # Hub settings (gRPC external address)
│       └── store/
│           ├── store.go        # Store struct, New(), DB pragma setup
│           ├── users.go        # User CRUD
│           ├── servers.go      # Server CRUD
│           ├── audit.go        # Audit log writes and queries
│           ├── config.go       # Key-value config store
│           └── notifications.go # Notification preferences and delivery log queries
├── agent/
│   ├── go.mod / go.sum
│   ├── cmd/
│   │   └── veyport-agent/
│   │       └── main.go         # Entry point: flags, config load/save, wiring
│   └── internal/
│       ├── client/             # gRPC stream client with reconnect backoff
│       ├── dropzone/           # Chunked file upload receiver
│       ├── filebrowser/        # Directory listing and file reading
│       ├── heartbeat/          # Periodic heartbeat sender (10s interval)
│       ├── logtailer/          # Poll-based file tailing with grep support
│       ├── terminal/           # PTY lifecycle, execution-user resolution, resize/input handling
│       └── sysinfo/            # CPU, memory, disk, uptime collection
└── web/
    ├── vite.config.ts
    ├── package.json
    └── src/
        ├── main.tsx            # React root
        ├── App.tsx             # Router setup
        ├── pages/              # One file per route
        ├── components/         # Shared UI components
        ├── hooks/              # Custom React hooks (API calls via TanStack Query)
        ├── layouts/            # Layout wrappers
        ├── lib/                # Utilities
        └── types/              # TypeScript type definitions
```

---

## Adding a New Feature

A typical full-stack feature (e.g. adding a new resource type) involves these steps:

### 1. Write a migration

Create a new numbered SQL file in `hub/internal/migrate/migrations/`:

```
007_create_my_resource.sql
```

```sql
CREATE TABLE my_resources (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

Migrations run automatically on the next startup. They are applied in filename order and never re-run.

### 2. Add a model

Add request/response structs to `hub/internal/model/`. Keep this package free of business logic - plain structs only.

```go
// hub/internal/model/my_resource.go
type MyResource struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    CreatedAt time.Time `json:"created_at"`
}

type CreateMyResourceRequest struct {
    Name string `json:"name"`
}
```

### 3. Add store methods

Add a new file to `hub/internal/store/` with the SQL queries:

```go
// hub/internal/store/my_resources.go
func (s *Store) CreateMyResource(name string) (*model.MyResource, error) { ... }
func (s *Store) GetMyResource(id string) (*model.MyResource, error) { ... }
func (s *Store) ListMyResources() ([]model.MyResource, error) { ... }
func (s *Store) DeleteMyResource(id string) error { ... }
```

Write tests in `my_resources_test.go` using the `testStore()` helper pattern from existing test files.

### 4. Add HTTP handlers

Create `hub/internal/server/handlers_my_resource.go`:

```go
func (s *Server) handleListMyResources(w http.ResponseWriter, r *http.Request) {
    resources, err := s.store.ListMyResources()
    if err != nil {
        respondError(w, http.StatusInternalServerError, "failed to list resources")
        return
    }
    respondJSON(w, http.StatusOK, resources)
}
```

### 5. Register routes

Add the routes to `hub/internal/server/router.go`:

```go
mux.Handle("GET /api/my-resources", loggingMiddleware(
    s.authMiddleware(auth.TokenTypeAccess, http.HandlerFunc(s.handleListMyResources)),
))
```

### 6. Add a frontend page

Create a new page in `web/src/pages/` and add the route in `web/src/App.tsx`. Use TanStack Query for data fetching (see existing pages for the pattern).

---

## Code Style and Conventions

### Go

- Standard `gofmt` formatting. Run `go fmt ./...` before committing.
- Errors are wrapped with `fmt.Errorf("context: %w", err)` and returned to callers. HTTP handlers convert errors to HTTP responses via `respondError`.
- No global state. Dependencies are injected via the `Server` struct and `Config`.
- All SQL queries are in the `store` package. Handlers must not construct SQL.
- Audit log entries should be written for all user-facing state changes. See `model.Audit*` constants for the naming pattern (`resource.action`).
- Terminal endpoints must remain browser-interactive only. Keep `interactiveOnly`, `terminalAccessOnly`, and the per-server root assignment check together when adding terminal behavior.

### TypeScript / React

- Strict TypeScript throughout (`strict: true` in tsconfig).
- TanStack Query manages all server state. Do not use `useEffect` + `useState` for data fetching.
- Components live in `src/components/`, pages in `src/pages/`. Pages are thin - extract reusable UI to components.
- Use the `@/` path alias for all imports within `src/`.

### Commits

Use conventional commit prefixes: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`.
