# CLI command automation

This guide is for scripts and automation agents that need to inspect Veyport
or run one bounded command on a managed node. It covers the currently published
command-passthrough prototype. Check the [release page](https://github.com/lorconksu/veyport/releases)
before installing: the published prototype is Hub `2.0.50-prototype.9` / tag
`prototype-ssh-passthrough.9`, with CLI and agent prototype 9 artifacts. These
are prototype builds, not a stable or main-branch release. Verify target agent
compatibility from its current version and advertised execution support. Older
CLI prototype 6 builds are also compatible with the Hub. This
publication information is not new runtime qualification evidence for SSH
execution. See [[CLI]] and [[SSH Gateway]] for the full command surface and
gateway setup.

## Authentication and prerequisites

Command passthrough uses an SSH certificate from an operator's interactive
login. A human signs in with `vey login` (including TOTP) and obtains the
certificate with `vey ssh-cert`. An API token alone cannot sign in to issue
that certificate. Treat this as delegated operator access: scripts can use an
already-authenticated human CLI profile and certificate, but this is not an
unattended service-identity workflow. API tokens remain useful for supported
Hub API commands such as listing or resolving servers; they do not replace the
certificate or establish its operator identity. For the documented human
bootstrap, clear `VEYPORT_TOKEN` and configured token overrides so `vey login`
and `vey ssh-cert` use the interactive session. After issuing a certificate,
a permitted API token may authenticate eligible REST operations such as server
resolution; the token cannot create or renew the SSH certificate.

The human operator completes login and TOTP before handing work to an agent.
Keep API tokens, SSH private keys, passwords, and TOTP codes out of agent
prompts, logs, remote command strings, and script stdin. Enhanced mode preserves
the exact submitted command and supported script as evidence; scripts should
not embed secrets in those inputs.

```bash
vey --hub https://hub.example.com login
vey ssh-cert
vey --json servers list
```

The SSH client on the operator machine must include a native OpenSSH-compatible
`ssh` binary on `PATH`.

The session and SSH certificate are separate credentials with separate
lifetimes. A refresh token normally renews the session automatically; an
expired or revoked CLI session can require `vey login`. An
absent or expired SSH certificate requires `vey ssh-cert`; inspect its
`expires_at` value rather than assuming a fixed certificate lifetime. The
default CLI session idle limit is 45 minutes; browser sessions default to 15
minutes; the shared absolute session lifetime defaults to 12 hours. These do
not set a remote command's runtime limit. A command already accepted by the gateway may
continue if the CLI session later expires; live account and access revocation
remain separate controls. See [[Logging In]] for session policy and
[[SSH Gateway]] for certificate lifetime.

## Select a target and inspect its agent

Use `vey --json servers list` to collect IDs, names, status, agent version,
and the total count. The response is a page, so increment `--offset` by the
number of returned entries until the number collected reaches `total`; use
`--limit` to select a page size. `--json` is a global flag and must precede the
subcommand:

```bash
vey --json servers list --limit 100 --offset 0
vey --json servers get web01
```

`servers get` accepts a server ID or a unique name and returns the current
`agent_version`. Prefer a stable server ID once discovered. Check that the
node is online and that its agent version supports execution before submitting
a command. For an offline node, restore its agent service or connectivity
first. Upgrade an online agent only when its version lacks execution support,
using the supported deployment procedure; repeating the command will not fix
either condition.

The current prototype pairing above describes what has been published. It
does not establish that a particular Hub, CLI, or target has been updated or
qualified. Confirm versions in your environment before relying on this flow.

## Submit exactly one remote command

Quote the entire remote command as one argument after `--`:

```bash
vey ssh web01 -- 'hostname; id; uname -s'
```

The CLI passes that one command string to native OpenSSH. It does not run it in
your local shell or join multiple command arguments. The quoting above keeps
the local shell from interpreting semicolons or `$variables`; the remote
command shell interprets them. If a local variable is deliberately inserted,
expand it before invoking `vey`. In a remote command, quote `$NAME` so it is
expanded remotely, for example `vey ssh web01 -- 'printf "%s\n" "$HOSTNAME"'`.

Command mode has no PTY. Stdout and stderr pass through as separate byte
streams; stdin is EOF when it is a terminal, and redirected input is streamed
in Standard profile. There is no interactive prompt, terminal resize, editor,
or multi-command session in this mode. Use an interactive `vey ssh web01`
from a terminal for those workflows. An interactive shell requires a local
TTY.

The default remote working directory is the execution account's home directory
and is established separately for each command. A later `vey ssh` invocation
starts a new command and does not inherit a prior command's `cd`; use an
explicit `cd /path && ...` within the one command when needed. The remote
environment is constructed for the execution identity (`PATH`, `SHELL`,
`LANG`, `USER`, `LOGNAME`, and `HOME`); it does not inherit the caller's local
environment. Local Veyport administrators run as the agent's OS account (root
with the standard root-run agent). LDAP users run as their
mapped host account, which must exist on the node. Use `sudo -n` when a
specific privileged action is required and passwordless sudo is configured;
commands cannot answer a password prompt.

For example, an explicitly authorized service check can use a read-only
command and noninteractive sudo:

```bash
vey ssh web01 -- 'sudo -n systemctl status nginx --no-pager'
```

This depends on the operator's mapped OS account and the node's sudo policy.
Prefer narrow, reviewable operations; a broad package upgrade or destructive
maintenance command should follow your normal change and recovery process.

### Send a script on stdin

In Standard profile, arbitrary redirected stdin can be sent to a command. In
Enhanced profile, stdin must be empty except for a complete script submitted
with one of these exact commands: `bash -s`, `/bin/bash -s`, `sh -s`, or
`/bin/sh -s`. Enhanced mode collects and verifies the whole script before
starting it. The script limit is 16 MiB and the submission deadline is 120
seconds. Script arguments and mixed script/data stdin are unsupported.

Use a quoted heredoc delimiter so the local shell leaves `$REMOTE_NAME` for
the remote shell:

```bash
vey ssh web01 -- 'bash -s' <<'REMOTE_SCRIPT'
set -eu
printf 'remote host: %s\n' "$HOSTNAME"
id
REMOTE_SCRIPT
```

To insert a local value, expand it explicitly while constructing input, with
careful validation for the intended data format. Avoid interpolating
untrusted data into a shell program. For simple values, pass them through a
fixed script's stdin only in Standard profile; Enhanced mode does not accept
mixed script and data input.

## Capture results safely

For shell scripts, keep stdout and stderr separate and check the process exit
status. Exit values from the remote process overlap with SSH's own status
space; in particular, `255` may be a remote exit result or an SSH failure.
Veyport also uses nonzero CLI exit codes for local/auth/network errors. A lost
connection or timeout can therefore leave the remote outcome unknown. Do not
blindly retry commands with side effects. First inspect the node or the
execution record (`vey audit export` or the Hub's execution detail, if your
role permits it) and reconcile the operation's state.

The remote command is limited to 32 KiB and must be valid UTF-8 without NUL
bytes. `--json` controls JSON rendering for CLI-generated payloads and errors; it
does not wrap remote SSH stdout/stderr, turn a remote result into JSON, or
encode file bytes. `vey files cat` and SSH output remain raw bytes. CLI JSON
payloads go to stdout and errors go to stderr, though a few commands also emit
plain diagnostic text on stderr (for example, `servers list` prints its total).
Capture both streams when diagnosing failures.

Python example using an argument vector and `shell=False`:

```python
import subprocess

argv = ["vey", "ssh", "web01", "--", "printf '%s\\n' ready"]
try:
    result = subprocess.run(
        argv,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
        check=False,
    )
except subprocess.TimeoutExpired as exc:
    # The remote outcome is uncertain: inspect/reconcile before any retry.
    print("SSH client timed out; reconcile the remote operation before retrying")
    raise

print("exit:", result.returncode)
print("stdout:", result.stdout.decode("utf-8", errors="replace"))
print("stderr:", result.stderr.decode("utf-8", errors="replace"))
```

For shell callers, redirect both streams and preserve the exit status:

```bash
if vey ssh web01 -- 'hostname; id' >command.stdout 2>command.stderr; then
  rc=0
else
  rc=$?
fi
printf 'remote command status: %s\n' "$rc"
```

The redirections above are handled by the local shell and write local files.
Redirections inside the quoted remote command string, such as
`'id > /tmp/identity.txt'`, run on the remote host.

`shell=False` prevents Python from interpreting the argument vector in a local
shell. The final command is still a program string interpreted on the remote
host. Validate or allowlist dynamic values and quote them for the remote shell;
prefer fixed command templates.

The timeout above is a caller-side bound, not a server execution limit. It
does not prove the Hub stopped a command. The default maximum command runtime
is 60 minutes; execution policy can shorten that limit. The gateway's
execution timeout is independent of the caller timeout.
Choose a caller timeout that allows the expected operation to finish, and
reconcile unknown outcomes before retrying.

## Standard and Enhanced evidence

Standard command execution needs no external evidence service. It records
local audit metadata and streams arbitrary stdin through the command channel.

Enhanced execution requires its configured receipt and encrypted archive
services. Admission preserves the exact command string or the complete
supported stdin script before launch. For scripts, Enhanced collects input
until EOF, enforces the byte and time limits above, then verifies and admits
the captured script before execution. Other Enhanced commands must receive
empty stdin. Execution evidence can include the command or script hashes and
execution lifecycle details, but it does not include remote stdout/stderr,
every shell instruction, downloaded program, or child process. Command
execution is not a sandbox and is not full host process telemetry.

## Recovery and retry guidance

- Authentication refusal: restore the intended human login session, then
  renew the SSH certificate if it is missing or expired.
- Offline or unsupported node: verify its status and `agent_version`; follow
  the deployment's supported agent update procedure.
- Preparation/admission refusal: read stderr and inspect the execution detail
  or audit record before changing the command or retrying.
- Caller timeout, broken connection, or exit `255`: treat the result as
  unknown. Query current node state or its execution record and reconcile
  before retrying. Use an application-level idempotency key or a safe
  read-before-write design for operations that may need retries.

Related pages: [[CLI]], [[SSH Gateway]], [[Audit Logs]], [[Logging In]], and
[[Troubleshooting]].
