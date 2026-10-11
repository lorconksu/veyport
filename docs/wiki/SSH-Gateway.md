# SSH Gateway

> **TL;DR**

| Field | Value |
|---|---|
| **What** | Native `ssh` access to fleet servers, terminated at the Hub instead of connecting straight to each node |
| **Who** | Operators who already have `vey` (see [[CLI]]) and want a real terminal (full-screen editors, `htop`, window resize) instead of the browser terminal |
| **Why** | The Hub stays on the data path for every byte, so SSH sessions get the same audit trail, live authorization, and zero-agent-change guarantee as the web terminal — without requiring per-node SSH keys or `sshd` reachability |
| **Where** | A dedicated TCP port on the Hub (default `:2222`), separate from the HTTP/gRPC ports |
| **How** | `vey ssh-cert` to obtain a short-lived certificate, then `vey ssh <server>` (or a manually-constructed `ssh` command) to connect |

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Enrollment: `vey ssh-cert`](#enrollment-vey-ssh-cert)
4. [Connecting: `vey ssh <server>`](#connecting-vey-ssh-server)
   - [Which OS account runs the shell?](#which-os-account-runs-the-shell)
5. [No-PTY command mode](#no-pty-command-mode)
6. [The manual `ssh` form and the `user+server` login name](#the-manual-ssh-form-and-the-userserver-login-name)
7. [Host-key pinning](#host-key-pinning)
8. [Certificate lifetime and re-issuance](#certificate-lifetime-and-re-issuance)
9. [Not supported](#not-supported)
10. [Exit codes](#exit-codes)
11. [Sessions and administrator termination](#sessions-and-administrator-termination)
12. [Troubleshooting](#troubleshooting)
13. [Hub configuration](#hub-configuration)

---

## Overview

Veyport's SSH gateway lets an operator connect to a fleet server through the Hub instead of connecting to the node's own SSH daemon. Interactive `vey ssh <server>` opens a PTY; the feature-branch command form `vey ssh <server> -- '<command>'` submits one command without a PTY. The Hub authenticates the request, rechecks live authorization, prepares the target OS identity, and brokers execution over the enrolled agent's outbound gRPC stream.

That means:

- The Hub is on the execution path and records command lifecycle metadata. Under Enhanced, a command starts only after its intent is preserved by the external receipt authority and encrypted archive.
- Interactive PTY and no-PTY execution use separate protocol paths; command streams have bounded buffering and explicit results.
- Authorization and target identity are checked live. A valid SSH certificate does not grant terminal or command authority by itself.

The prototype identity is version `2.0.50-prototype.3` and immutable tag
`prototype-ssh-passthrough.3`; stable `2.0.49` does not include this feature.
Before installing, check the [prototype release page](https://github.com/lorconksu/veyport/releases/tag/prototype-ssh-passthrough.3)
for an actually published release and its required assets. If they are absent,
the prototype is unavailable. Use the Hub and CLI from the same source revision
with a compatible agent. Resolve the immutable OCI tag to its published digest
and verify the source revision.
Standard command execution has no external audit-service dependency. Enhanced
is opt-in and requires a qualified external receipt/archive configuration.

![Overview diagram](../screenshots/diagram-ssh-gateway-d1757e51.png)

## Prerequisites

- `vey` installed and a hub configured — quickest: `curl -fsSL https://<your-hub>/install/cli.sh | sh`, then `vey --hub https://<your-hub> login` (see [[CLI]] for details and manual install).
- An **interactive** `vey login` session. Certificate issuance is refused to API-token credentials — see [FR-002/SC-004 below](#enrollment-vey-ssh-cert).
- A native `ssh` client on your machine (OpenSSH or compatible). There is no bundled SSH client — `vey ssh` execs your system's `ssh`.
- The gateway must be enabled and reachable on the Hub you're connecting to (see [Hub configuration](#hub-configuration) and [Troubleshooting](#troubleshooting)).
- Linux and macOS clients. Windows clients are not supported in this release (see [Not supported](#not-supported-in-this-release)).

## Enrollment: `vey ssh-cert`

```bash
vey --hub https://hub.example.com ssh-cert
```

This provisions or refreshes your SSH credential:

1. Generates an ed25519 keypair locally if you don't already have one stored for this hub (re-running reuses the existing keypair — only the certificate is refreshed).
2. Fetches the gateway's host key (`GET /api/ssh/host-key`) and caches its fingerprint for pinning.
3. Requests a signed user certificate (`POST /api/ssh/certificates`), passing only your public key — the Hub derives the principal (your username) from your authenticated session; you cannot request a different identity.
4. Stores the private key, certificate, expiry, and host fingerprint alongside your existing `vey` credentials (same at-rest protection as your login session: OS keyring, or a `0600` file fallback).
5. Prints the resulting principal, expiry, gateway port, and host-key fingerprint.

| Property | Value |
|---|---|
| **Auth required** | Interactive `vey login` session only — an API token is refused with exit 3 before any network call |
| **Rate limit** | 10 issuance requests per minute per caller (`429` → exit 7) |
| **`--json` shape** | `{principal, expires_at, host_key_fingerprint, gateway_port}` |
| **Idempotent** | Yes — re-running refreshes the certificate and keeps the keypair |

**Why interactive-only?** SSH access is an operator capability, not something a script holding a long-lived API token should be able to reach for. The Hub enforces this server-side (`interactiveOnly` middleware); `vey ssh-cert` additionally refuses before making a request, so a misconfigured automation script fails fast and locally instead of hitting a rate limit or leaving a refusal in the audit log.

```bash
$ vey --hub https://hub.example.com ssh-cert
Signed cert for alice, valid until 2026-08-06T20:14:03Z
Gateway port: 2222
Host key fingerprint: SHA256:AbCdEf...
```

## Connecting: `vey ssh <server>`

```bash
vey --hub https://hub.example.com ssh web01
```

`vey ssh` is a thin, safe wrapper around your native `ssh` client:

1. Checks that you have a stored, unexpired certificate; if not, it explains and points you to `vey ssh-cert`.
2. Resolves `<server>` the same way `vey servers get` does — a unique name or ID; an ambiguous name lists the candidates; an unknown server is a clean not-found error.
3. Builds a temporary host-verification file from the cached gateway fingerprint (no blind trust-on-first-use prompt).
4. Execs your operator's actual `ssh` binary with the certificate, the resolved `user+server` login name, and pinned host verification — it never edits your `~/.ssh/config`.
5. Propagates the `ssh` client's exit status back to your shell.

You get a full interactive PTY: full-screen editors, pagers, `htop`, and window resizing all work, because the Hub relays raw terminal bytes and `window-change` events end-to-end over the same channel the web terminal uses.

## No-PTY command mode

```bash
vey ssh web01 -- 'uname -a'
# Standard profile only: Enhanced rejects arbitrary nonempty stdin.
printf 'hello\n' | vey ssh web01 -- 'cat'
```

Everything after `--` must be exactly one command-string argument. The CLI invokes
OpenSSH directly; it does not execute the command through a local shell or join
multiple arguments. It disables PTY allocation and interactive authentication.
Without redirected input, stdin is EOF. Standard mode streams redirected stdin.

In Enhanced mode the hub collects all stdin before preparation and admission.
Only exact `bash -s`, `/bin/bash -s`, `sh -s`, or `/bin/sh -s` forms accept
nonempty stdin. The whole script is limited to 16 MiB and 120 seconds, and is
verified before any process starts. Other Enhanced commands must receive empty
stdin. Script arguments and mixed script/data input are not supported. Standard
accepts arbitrary streamed stdin.

Stdout and stderr are separate binary-safe streams; their individual order is
preserved, with no promised total ordering between the two. Remote exit status is
propagated through SSH. Exit 255 can overlap a remote exit with a native SSH
failure. Do not automatically retry after a connection loss or uncertain result.
Browser refresh does not cancel a command; cancellation or live authority
revocation does. Remote output is not archived as command evidence.

Enhanced evidence covers the exact submitted command or complete supported
script, not every internal shell instruction, downloaded program, child-process
action, or remote output. Command execution is not a sandbox and does not provide
full host process telemetry.

## Which OS account runs the shell?

Your Veyport username authenticates you to the gateway. It does not automatically
become the Linux username on the target VM. Both SSH and browser terminal sessions
use the same authorization decision and agent PTY manager:

- **Local admins** inherit the agent's OS account. The standard installer runs the
  agent as root, so `whoami` in the shell reports `root`. This is the current design.
- **LDAP admins and authorized LDAP users** run as their mapped LDAP username on
  the target host. The host must resolve that account; lookup failure refuses the
  shell rather than falling back to root.

`vey ssh` has no option to select an arbitrary Linux user. A root (`/`) path
assignment grants terminal eligibility to an authorized LDAP user; it does not
restrict commands inside the shell to a filesystem subtree. The shell follows its
OS account's permissions. See [[Architecture]] for the execution identity table.

## The manual `ssh` form and the `user+server` login name

`vey ssh` is a convenience wrapper — everything it does can also be done with a plain `ssh` command, which is useful for scripting or when `vey` isn't installed on the machine you're connecting from:

```bash
ssh -p 2222 alice+web01@hub.example.com
```

The SSH gateway addresses both **who you are** and **which server you want** in a single login name, since the SSH protocol only carries one username per connection and the gateway does not support `ProxyJump`. The login name is split on the **first** `+`:

| Part | Meaning |
|---|---|
| Left of the first `+` | Your veyport username. It must equal a principal on the certificate you present — the gateway checks `cert principal == left part`. |
| Right of the first `+` | The target server's name or ID, resolved the same way `vey servers get` resolves it. |

Because the split is on the *first* `+`, a **server name** may safely contain a `+`, but a **veyport username** may not — a username containing `+` cannot be split unambiguously and is not supported for SSH access. Affected users must use the web terminal instead. A login name with no `+` at all is rejected with an explanatory SSH banner pointing back at this format.

`vey ssh web01` is exactly equivalent to constructing this manual form using your cached certificate and host key.

## Host-key pinning

The gateway presents a stable ed25519 host key that survives Hub restarts and upgrades — it is never silently regenerated. If the stored host key ever becomes unusable (corrupted, undecryptable), the gateway disables its listener entirely rather than serve a changed identity; the rest of the Hub keeps running.

Fetch the current fingerprint at any time:

```bash
curl -H "Authorization: Bearer <token>" https://hub.example.com/api/ssh/host-key
```

or read it back from your last `vey ssh-cert` run:

```bash
vey --hub https://hub.example.com ssh-cert --json | jq -r .host_key_fingerprint
```

`vey ssh-cert` caches this fingerprint and `vey ssh` uses it to pre-configure host verification, so you are never prompted with a blind trust-on-first-use ("the authenticity of host ... can't be established") prompt the way a fresh manual `ssh` connection normally would be. If you connect manually, pass the fingerprint to your client's own pinning mechanism (for example a scoped `known_hosts` entry) instead of accepting on trust.

## Certificate lifetime and re-issuance

Certificates are short-lived — **~12 hours by default**, tunable per hub (see [Hub configuration](#hub-configuration)). A few properties worth knowing:

- The certificate binds a single principal: your username, and only your username. The Hub derives it from your authenticated session; there is no way to request a certificate for someone else.
- There is **no revocation** mechanism for issued certificates in this release. The short TTL plus fresh, per-connection authorization against live account/permission state is the accepted mitigation — see the engineering security model for the full rationale.
- A certificate expiring **mid-session does not drop that session**; only new connection attempts are re-checked against the certificate's validity, which matches standard SSH behavior.
- Re-run `vey ssh-cert` any time to refresh — it keeps your existing keypair and simply asks the Hub for a new certificate. There's no reason not to re-run it liberally; it's cheap and rate-limited generously (10/min).

## Not supported

The gateway does not provide these features:

| Capability | Behavior |
|---|---|
| `scp` / `sftp` | Refused — the `subsystem` channel request is rejected |
| Port forwarding (`-L` / `-R` / dynamic `-D`) | Refused — forwarding channel/global requests are rejected |
| SSH agent forwarding (`-A`) | Refused — `auth-agent-req` is rejected |
| Windows clients | Not tested or supported — use the web terminal instead |

Command mode accepts one SSH exec request per channel. PTY requests, arbitrary
environment variables, subsystems, forwarding, duplicate commands, and malformed
or oversized requests are refused. This is not a general-purpose remote SSH
server.

If you need any of these, use the existing [[Server Detail]] file browser/log tailer for file access, or the browser terminal for anything the interactive shell can't cover.

## Exit codes

`vey ssh-cert` and `vey ssh` use the same stable exit-code taxonomy as the rest of `vey` (see [[CLI]] for the full table):

| Code | Meaning for SSH commands |
|---|---|
| `0` | Success |
| `2` | Usage error, or an ambiguous server name for `vey ssh <server>` |
| `3` | Auth failure — API-token mode, no/expired stored certificate, or the Hub's interactive-only refusal |
| `5` | Unknown server for `vey ssh <server>` |
| `6` | Connectivity failure reaching the Hub or the gateway port |
| `7` | Rate-limited (`429`) on certificate issuance |
| *(varies)* | `vey ssh` propagates whatever exit status your native `ssh` client returns once a session is actually open |

## Sessions and administrator termination

As of feature 009, an open SSH gateway shell shows up alongside web and CLI sessions in the
Sessions views described in [[Settings]]: your own shells appear in "Your sessions" on the
Profile tab, and an admin sees any user's open shells (kind **SSH shell**, with the target server,
when it started, and when it was last active) in that user's **Sessions** panel on the Users tab.

An administrator can terminate a shell directly from that panel, and two broader actions close it
along with everything else: **Log out everywhere** (admin) and **Sign out other sessions** (the
shell's own owner). Disabling the account also closes it. In every case the shell closes within a
few seconds and the client sees an explanatory message on stderr before the connection ends:

```
veyport: session ended by an administrator
```

(or `veyport: account disabled`, `veyport: signed out everywhere`, depending on why), followed by
exit status `1`. This is audited as `ssh.session_closed` with detail `reason=forced` - see
[[Audit Logs]].

**Shells are not subject to the idle or absolute session timers** that apply to web and CLI
sessions (see [[Logging In]]). A long-running shell is bounded only by its certificate's ~12-hour
lifetime (above) and by explicit termination as described here - it does not go idle on its own
and does not expire at a fixed wall-clock time the way a web session does.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `vey ssh` says your certificate is missing or expired | No certificate issued yet, or the ~12h TTL has passed | Run `vey ssh-cert` |
| `permission denied` after a successful cert handshake | `AuthorizeTerminalExecution` denied you for this server right now — no terminal permission, no root (`/`) assignment, unknown server, or your account is disabled | Check your permissions on [[Settings]] / [[Server Detail]]; this is re-evaluated live and is intentionally not implied by having a valid certificate |
| `veyport: the SSH username must be <veyport-user>+<server>` banner | You connected without the `+server` suffix, or with a raw `ssh` command missing it | Use `vey ssh <server>`, or the manual form `ssh -p 2222 user+server@hub` |
| Connection refused / times out on port 2222 | The gateway is disabled, or the port is blocked by a firewall/proxy in front of the Hub | Confirm `ssh_gateway_enabled` and the reachability of the configured port; SSH is a raw TCP protocol and typically needs its own reverse-proxy route (a TLS-terminating HTTP proxy like Traefik does not carry it) |
| `vey ssh-cert` fails with an interactive-login error even though you're logged in | Your active credential is an API token (`VEYPORT_TOKEN` or a config `api_token`), which always wins over a stored interactive session | Unset the token for this invocation, or run `vey login` and don't set `VEYPORT_TOKEN` |
| "unknown server" / "ambiguous server name" / "server unavailable" | Target resolution failed — the name/ID doesn't exist, matches more than one server, or the target agent isn't currently connected | `vey servers list` / `vey servers get <server>` to check the name and online status |
| Host key changed warning | Should not happen — the gateway's host key is stable across restarts. If it does happen, treat it as a genuine warning and verify out-of-band before trusting the new key | Compare against `GET /api/ssh/host-key` from a trusted channel; do not just accept |

## Hub configuration

The gateway's port, whether it's enabled, and certificate TTL are administrator-tunable — there is no end-user flag for any of these:

| Setting | `_config` key | Default | Notes |
|---|---|---|---|
| Gateway enabled | `ssh_gateway_enabled` | `true` | When `false`, the port is never opened, and `POST /api/ssh/certificates` returns a clear "gateway disabled" error instead of an unusable certificate |
| Listen address | `ssh_addr` | `:2222` | Overridable per-run via the Hub's `--ssh-addr` flag; the `_config` value wins over the flag when both are set |
| Certificate TTL | `ssh_cert_ttl_hours` | `12` | Hours; applies to every certificate issued after the change, not retroactively |

An invalid or unparseable stored value falls back to the next level (DB → flag → hardcoded default) rather than failing Hub startup.

---

*Related: [[CLI]] for the full `vey` command reference and exit-code taxonomy, [[API Reference]] for the `/api/ssh/*` and session endpoint contracts, [[Server Detail]] for the browser-based terminal alternative, [[Settings]] for viewing and terminating sessions and shells, [[Audit Logs]] for reviewing `ssh.*` events.*
