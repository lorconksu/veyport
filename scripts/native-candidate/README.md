# External native candidate qualification

The trusted coordinator deploys exact candidate OCI bytes, verifies their binding
and holds the deployment lease. This harness is a separately installed external
client: it does not import Hub implementation packages, start an in-process Hub,
or rebuild the candidate agent. Deployment and scanner policy remain independent.

Install reviewed copies of `run.py` and a static probe, owned by the operator and
outside the submitted candidate. Build the client from the existing Hub module,
which already pins its dependencies; no additional Go module is required:

```sh
cd hub
CGO_ENABLED=0 go build -trimpath -o "$PRIVATE/native-probe" \
  ../scripts/native-candidate/probe.go
```

Run the installed client on the candidate Docker host, with a root-owned private
configuration and fresh private work/output paths:

```sh
python3 /opt/veyport-native/run.py \
  --config "$PRIVATE/runtime.json" --output "$PRIVATE/native-report.json"
```

The coordinator supplies `candidate_id`, `revision`, `artifact_manifest_sha256`,
`version`, `hub_base_url`, `grpc_addr`, `ssh_addr`, `hub_container_id`,
`hub_image_id`, `hub_data_dir`, `agent_binary`, `cli_binary`, their
`agent_binary_sha256`/`cli_binary_sha256`, `agent_runtime_image`, `work_dir`,
`network`, `native_probe`, `hub_network_alias`, `hub_internal_grpc`,
`allow_disposable_database_faults: true` and `audit_profile: standard`.
Configuration must be a bounded private regular file. The harness creates the
work directory; it must not already exist.

The Hub must carry label `org.veyport.ssdf.candidate=<candidate_id>` and bind only
its fresh disposable database directory to `/data`. Its image revision and
Docker ID must match the coordinator's verified inputs. The single Docker bridge
must have `Internal=true`. The harness accepts loopback endpoints or the exact
current Hub container IP inspected on that bridge; it rejects other addresses
and disables environment HTTP proxies. Docker 29 can omit published ports on an
internal network, so directly using that inspected IP avoids a forwarding layer.
The Hub's `--grpc-external-addr candidate-hub:9090` must match the internal alias,
so normal CA/hostname verification works without disabling TLS verification.

The agent fixture uses an operator-pinned immutable Linux image with normal NSS
and shell tools. The Hub's minimal Wolfi image lacks `getent` and is insufficient
for a real agent execution node. Mount the verified public agent read-only into
the Linux fixture; the only other writable bind is its candidate state directory.
The fixture has no host namespaces, no privileged mode, a read-only root, a
bounded no-exec tmpfs, CPU/PID limits, 256 MiB RAM and matching memory-swap limit.
After dropping all capabilities it receives only SETUID/SETGID, for ordinary
execution credential enforcement inside its own container. Identity, mounts,
network, capabilities, limits and exact public binary hashes are checked again
before completion. The test agent container is removed even after failures.

Bootstrap uses the real registration, password, mandatory TOTP setup/enable,
account creation, SSH certificate issuance and node enrollment APIs. It creates
three synthetic MFA users: an administrator, a viewer, and a revocable operator.
No production authentication bypass or shared TOTP seed is introduced.

The required case policy is the fixed `REQUIRED` mapping in `run.py`: five gRPC
cases, twelve SSH cases, plus successful bootstrap. The gRPC cases actually call
the protected RPC: missing certificate must produce `Unauthenticated`, a valid
enrolled identity reaches attachment validation (`InvalidArgument`), and a
1 MiB message hits the server bound (`ResourceExhausted`). The foreign certificate
is explicitly sent rather than omitted through TLS acceptable-CA selection.
The enrollment listener separately gives an explicit invalid-token response.

SSH checks certificate/principal boundaries, viewer denial, blocked forwarding
and subsystems, binary stdin/stdout/stderr/EOF and exit status, UID enforcement,
client-loss cancellation and revocation of a previously authorized operator. A
live database trigger rejects only `execution.dispatched` audit inserts in this
candidate's disposable database. The command must fail; the trigger is removed
in `finally`; a recovered SSH command proves the denied marker never appeared.
The record reports required-audit admission exercised only when denial and
recovery both pass. The coordinator must reset the disposable dataset after an
interrupted harness; a retry never reuses an initialized Hub as a fresh fixture.

This prototype selects the application's default **Standard** auditing profile.
It records `enhanced_receipt_exercised: false`. It does not qualify encrypted
spool readiness or external enhanced receipts. Requesting another profile fails;
an enhanced runtime needs its real receipt fixture and separately reviewed case
policy. Existing enhanced source/integration tests remain complementary CI.

Reports bind source and candidate inventory, retain per-case status and private
diagnostics, and state the observed runtime identity. Missing/failed/duplicate
cases cannot qualify. The coordinator verifies those identities independently
and signs only its reduced disclosure-safe result. Keep raw work directories,
credentials, TOTP seeds, database copies, diagnostics and protocol results out of
public Actions artifacts and release attachments. Revoke/remove synthetic state
after diagnostics are retained; credentials are not evidence payloads.

The first full validation exercised all eighteen cases against released
`dfce2e6f584f27dec54f51be4992550bbf8d370a` (v2.0.57) on the local workspace Docker
daemon. This validates the harness; it is not evidence for the final PR revision
or a staging-host qualification. The coordinator must run the installed reviewed
tool against each immutable candidate before publication.
