#!/usr/bin/env python3
"""Exercise exact deployed candidate protocols in a disposable Docker network.

The trusted coordinator owns deployment, lease and artifact verification. This
client requires a fresh candidate, validates isolation again, creates synthetic
MFA accounts through HTTP, and never operates on normal staging resources.
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import struct
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

LABEL = "org.veyport.ssdf.candidate"
REQUIRED = {
    "native:grpc": {
        "grpc.enrolled-identity-reaches-protected-handler",
        "grpc.missing-client-certificate-rejected",
        "grpc.enrollment-listener-reachable-without-client-certificate",
        "grpc.foreign-client-certificate-rejected",
        "grpc.oversized-message-rejected",
    },
    "native:ssh": {
        "ssh.certificates-issued-to-mfa-sessions",
        "ssh.stdin-stdout-stderr-exit-status",
        "ssh.execution-user-enforced",
        "ssh.client-cancellation-terminates-work",
        "ssh.principal-substitution-rejected",
        "ssh.foreign-ca-certificate-rejected",
        "ssh.viewer-node-execution-denied",
        "ssh.forwarding-and-subsystems-denied",
        "ssh.disabled-account-execution-denied",
        "ssh.standard-audit-records-present",
        "ssh.required-audit-failure-denies-execution",
        "ssh.audit-recovery-verifies-denied-command-never-ran",
    },
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def command(arguments, **kwargs):
    return subprocess.check_output(arguments, stderr=subprocess.DEVNULL, timeout=kwargs.pop("timeout", 30), **kwargs)


def digest(path):
    with Path(path).open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def private_json(path, value):
    with Path(path).open("x", encoding="utf-8") as target:
        os.chmod(path, 0o600)
        json.dump(value, target, indent=2)
        target.write("\n")


def totp(secret, instant=None):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    raw = hmac.digest(key, struct.pack(">Q", int(instant if instant is not None else time.time()) // 30), "sha1")
    offset = raw[-1] & 15
    return f"{(int.from_bytes(raw[offset:offset + 4], 'big') & 0x7fffffff) % 1000000:06d}"


class Harness:
    def __init__(self, config):
        self.config = config
        self.work = Path(config["work_dir"])
        self.http = build_opener(ProxyHandler({}), NoRedirect)
        self.agent = None
        self.cases = []
        self.stage = "initialization"
        self.last_http_status = None

    def api(self, method, path, data=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = Request(self.config["hub_base_url"] + path, data=json.dumps(data).encode() if data is not None else None, headers=headers, method=method)
        try:
            with self.http.open(request, timeout=10) as response:
                if not 200 <= response.status < 300:
                    raise ValueError("candidate API refused operation")
                return json.loads(response.read(1 << 20))
        except HTTPError as error:
            self.last_http_status = error.code
            raise ValueError("candidate API refused operation: " + str(error.code)) from None

    def identity(self):
        config = self.config
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", config["candidate_id"]):
            raise ValueError("bounded candidate identity required")
        if not re.fullmatch(r"[0-9a-f]{40}", config["revision"]) or not re.fullmatch(r"[0-9a-f]{64}", config["artifact_manifest_sha256"]):
            raise ValueError("immutable candidate binding required")
        base = urlsplit(config["hub_base_url"])
        if base.scheme != "http" or base.path not in ("", "/"):
            raise ValueError("isolated loopback HTTP origin required")
        if config.get("audit_profile") != "standard" or config.get("allow_disposable_database_faults") is not True:
            raise ValueError("explicit Standard prototype and disposable audit fault authorization required")
        data_dir = Path(config["hub_data_dir"])
        if data_dir.is_symlink() or not data_dir.is_absolute() or not self.work.is_absolute() or self.work.is_symlink():
            raise ValueError("private real candidate directories required")
        info = json.loads(command(["docker", "inspect", config["hub_container_id"]]))[0]
        if not info["State"]["Running"] or info["Image"] != config["hub_image_id"] or info["Config"].get("Labels", {}).get(LABEL) != config["candidate_id"]:
            raise ValueError("candidate container identity mismatch")
        if info["Config"].get("Labels", {}).get("org.opencontainers.image.revision") != config["revision"]:
            raise ValueError("candidate image revision mismatch")
        mounts = [m for m in info["Mounts"] if m["Destination"] == "/data"]
        if len(mounts) != 1 or Path(mounts[0]["Source"]).resolve() != data_dir.resolve():
            raise ValueError("candidate database mount mismatch")
        network = json.loads(command(["docker", "network", "inspect", config["network"]]))[0]
        if not network["Internal"] or set(info["NetworkSettings"]["Networks"]) != {config["network"]}:
            raise ValueError("candidate network isolation missing")
        candidate_ip = info["NetworkSettings"]["Networks"][config["network"]]["IPAddress"]
        for endpoint in (config["hub_base_url"], "tcp://" + config["grpc_addr"], "tcp://" + config["ssh_addr"]):
            parsed = urlsplit(endpoint)
            if parsed.hostname is None or parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise ValueError("explicit candidate endpoints required")
            if not ipaddress.ip_address(parsed.hostname).is_loopback and parsed.hostname != candidate_ip:
                raise ValueError("endpoint is not the exact inspected candidate")
        for component in ("agent", "cli"):
            path = Path(config[component + "_binary"])
            if path.is_symlink() or digest(path) != config[component + "_binary_sha256"]:
                raise ValueError("candidate public binary mismatch")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", config["agent_runtime_image"]):
            raise ValueError("operator-pinned disposable Linux node image required")
        if self.agent:
            agent = json.loads(command(["docker", "inspect", self.agent]))[0]
            host = agent["HostConfig"]
            added = {c.removeprefix("CAP_") for c in host.get("CapAdd", [])}
            dropped = {c.removeprefix("CAP_") for c in host.get("CapDrop", [])}
            if agent["Image"] != config["agent_runtime_image"] or not agent["State"]["Running"] or agent["Config"].get("Labels", {}).get(LABEL) != config["candidate_id"]:
                raise ValueError("disposable node identity mismatch")
            if host.get("Privileged") or not host.get("ReadonlyRootfs") or host.get("PidMode") == "host" or added != {"SETUID", "SETGID"} or dropped != {"ALL"}:
                raise ValueError("disposable node privilege isolation changed")
            if host.get("Memory") != 256 << 20 or host.get("MemorySwap") != 256 << 20 or set(agent["NetworkSettings"]["Networks"]) != {config["network"]}:
                raise ValueError("disposable node resource/network isolation changed")
            binds = {m["Destination"]: m for m in agent["Mounts"] if m["Type"] == "bind"}
            if set(binds) != {"/state", "/usr/local/bin/veyport-agent"} or binds["/usr/local/bin/veyport-agent"]["RW"] or Path(binds["/usr/local/bin/veyport-agent"]["Source"]).resolve() != Path(config["agent_binary"]).resolve() or Path(binds["/state"]["Source"]).resolve() != self.work / "agent":
                raise ValueError("disposable node has unrelated or writable binary mounts")
        return {"hub_image_id": info["Image"], "hub_container_id": info["Id"],
                "agent_image_id": config["agent_runtime_image"], "agent_binary_sha256": digest(config["agent_binary"]),
                "candidate_label_verified": True, "private_mount_verified": True, "internal_network_verified": True}

    def enable_mfa(self, setup, password=None):
        secret = self.api("POST", "/api/auth/totp/setup", {}, setup)["secret"]
        body = {"code": totp(secret)}
        if password:
            body["new_password"] = password
        auth = self.api("POST", "/api/auth/totp/enable", body, setup)
        return auth["access_token"], secret

    def bootstrap(self):
        deadline = time.monotonic() + 30
        while True:
            try:
                initial_status = self.api("GET", "/api/auth/status")
                break
            except URLError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)
        if initial_status["initialized"] is not False:
            raise ValueError("refuse nonempty installation; fresh candidate dataset required")
        password = "Ssdf1!" + secrets.token_urlsafe(24)
        admin_name, viewer_name = "ssdf_admin", "ssdf_viewer"
        initial = self.api("POST", "/api/auth/register", {"username": admin_name, "email": "admin@ssdf.invalid", "password": password})
        admin_token, admin_totp = self.enable_mfa(initial["setup_token"])
        user = self.api("POST", "/api/users", {"username": viewer_name, "email": "viewer@ssdf.invalid", "role": "viewer"}, admin_token)
        first_login = self.api("POST", "/api/auth/login", {"username": viewer_name, "password": user["temporary_password"]})
        viewer_token, viewer_totp = self.enable_mfa(first_login["setup_token"], "Viewer1!" + secrets.token_urlsafe(24))
        operator = self.api("POST", "/api/users", {"username": "ssdf_operator", "email": "operator@ssdf.invalid", "role": "admin"}, admin_token)
        operator_login = self.api("POST", "/api/auth/login", {"username": "ssdf_operator", "password": operator["temporary_password"]})
        operator_token, operator_totp = self.enable_mfa(operator_login["setup_token"], "Operator1!" + secrets.token_urlsafe(24))
        policy = self.api("GET", "/api/audit-policy", token=admin_token)
        if policy.get("profile", policy.get("policy", {}).get("policy", {}).get("profile")) != "standard":
            raise ValueError("deployed audit profile does not match selected Standard policy")
        server = self.api("POST", "/api/servers", {"name": "ssdf-native-node"}, admin_token)
        pins = set(re.findall(r"--ca-pin '([0-9a-f]{64})'", server["install_command"]))
        if len(pins) != 1:
            raise ValueError("exact enrollment CA pin required")
        state = self.work / "agent"
        state.mkdir(mode=0o700)
        config = self.config
        # The operator-pinned Linux node supplies NSS/shell utilities. The
        # separately verified public agent is mounted read-only, never rebuilt.
        # Only SETUID/SETGID permit ordinary credential enforcement inside the
        # container; no host namespaces, devices or unrelated writable mounts.
        arguments = ["docker", "run", "--detach", "--name", "ssdf-native-agent-" + config["candidate_id"],
                     "--label", LABEL + "=" + config["candidate_id"], "--network", config["network"],
                     "--read-only", "--cap-drop=ALL", "--cap-add=SETUID", "--cap-add=SETGID", "--security-opt=no-new-privileges", "--pids-limit=128",
                     "--memory=256m", "--memory-swap=256m", "--cpus=1", "--user=0:0", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
                     "--mount", "type=bind,source=" + str(state) + ",target=/state",
                     "--mount", "type=bind,source=" + config["agent_binary"] + ",target=/usr/local/bin/veyport-agent,readonly",
                     "--entrypoint", "/usr/local/bin/veyport-agent", config["agent_runtime_image"],
                     "--hub", config["hub_internal_grpc"], "--ca-pin", pins.pop(),
                     "--token", server["registration_token"], "--config", "/state/agent.json", "--cert-dir", "/state/certs",
                     "--dropzone-dir", "/state/dropzone", "--allowed-paths", "/tmp"]
        self.agent = command(arguments).decode().strip()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            response = self.api("GET", "/api/servers/" + server["server"]["id"], token=admin_token)
            node = response.get("server", response)
            if node.get("status") == "online" and (state / "certs/client.crt").exists():
                break
            time.sleep(0.5)
        else:
            raise ValueError("candidate agent did not enroll")
        # Avoid racing the capability announcement after the heartbeat registry.
        time.sleep(1)
        probe_config = {**config, "admin_token": admin_token, "viewer_token": viewer_token,
                        "admin_name": admin_name, "viewer_name": viewer_name, "viewer_id": user["user"]["id"],
                        "operator_token": operator_token, "operator_name": "ssdf_operator", "operator_id": operator["user"]["id"],
                        "server_name": server["server"]["name"], "cert_dir": str(state / "certs"),
                        "grpc_server_name": config["hub_network_alias"]}
        private_json(self.work / "probe.json", probe_config)
        private_json(self.work / "synthetic-secrets.json", {"admin_totp": admin_totp, "viewer_totp": viewer_totp, "operator_totp": operator_totp})
        self.cases.append({"id": "bootstrap.synthetic-mfa-and-agent-enrollment", "status": "pass"})

    def phase(self, name):
        output = self.work / (name + ".json")
        with (self.work / (name + ".log")).open("xb") as log:
            subprocess.run([self.config["native_probe"], "--config", str(self.work / "probe.json"), "--output", str(output), "--phase", name], stdout=log, stderr=log, timeout=180, check=False)
        results = json.loads(output.read_text())
        if not isinstance(results, list) or not results:
            raise ValueError("complete native probe results required")
        self.cases.extend(results)

    def audit_fault(self):
        database = Path(self.config["hub_data_dir"]) / "veyport.db"
        if database.is_symlink() or not database.is_file():
            raise ValueError("real disposable candidate database required")
        # Refresh identity immediately before the only database mutation. Never
        # silently operate on another deployment after a lease/network change.
        self.identity()
        with sqlite3.connect(database, timeout=10) as connection:
            connection.execute("CREATE TRIGGER ssdf_required_audit_fault BEFORE INSERT ON audit_logs WHEN NEW.action='execution.dispatched' BEGIN SELECT RAISE(ABORT, 'disposable synthetic required audit failure'); END")
        try:
            self.phase("audit-outage")
        finally:
            with sqlite3.connect(database, timeout=10) as connection:
                connection.execute("DROP TRIGGER ssdf_required_audit_fault")
        self.phase("audit-recovery")

    def cleanup(self):
        if self.agent:
            command(["docker", "rm", "--force", self.agent])


def assess(config, cases, runtime):
    by_id = {}
    for case in cases:
        if not isinstance(case, dict) or case.get("status") not in ("pass", "fail") or case.get("id") in by_id:
            raise ValueError("invalid or duplicate native cases")
        by_id[case["id"]] = case["status"]
    scopes = []
    for scope, required in REQUIRED.items():
        complete = all(by_id.get(name) == "pass" for name in required) and by_id.get("bootstrap.synthetic-mfa-and-agent-enrollment") == "pass"
        scopes.append({"id": scope, "status": "completed" if complete else "failed",
                       "authenticated": complete, "coverage_complete": complete, "findings": []})
    complete = all(s["status"] == "completed" for s in scopes) and not any(v != "pass" for v in by_id.values()) and bool(runtime)
    return {"schema_version": 1, "candidate_id": config["candidate_id"], "revision": config["revision"],
            "artifact_manifest_sha256": config["artifact_manifest_sha256"], "status": "completed" if complete else "failed",
            "candidate_qualified": complete, "required_scopes": sorted(REQUIRED), "scopes": scopes,
            "cases": cases, "audit_profile": config["audit_profile"], "enhanced_receipt_exercised": False,
            "required_audit_admission_exercised": all(by_id.get(name) == "pass" for name in
                ("ssh.required-audit-failure-denies-execution", "ssh.audit-recovery-verifies-denied-command-never-ran")),
            "runtime": runtime, "completed_at": dt.datetime.now(dt.timezone.utc).isoformat()}


def run(config, output):
    destination = Path(output)
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("fresh private report path required before candidate mutation")
    harness = Harness(config)
    runtime = {}
    try:
        harness.work.mkdir(mode=0o700, parents=True, exist_ok=False)
        harness.stage = "initial-runtime-identity"
        runtime = harness.identity()
        harness.stage = "synthetic-bootstrap"
        harness.bootstrap()
        harness.stage = "protocols"
        harness.phase("protocols")
        harness.stage = "required-audit-outage"
        harness.audit_fault()
        harness.stage = "final-runtime-identity"
        if harness.identity() != runtime:
            raise ValueError("candidate identity changed during qualification")
        runtime.update(agent_container_id=harness.agent, agent_isolation_verified=True)
    except (ValueError, KeyError, OSError, sqlite3.Error, subprocess.SubprocessError) as error:
        harness.cases.append({"id": "harness.execution", "status": "fail", "stage": harness.stage,
                              "error_type": type(error).__name__, "last_http_status": harness.last_http_status})
    finally:
        try:
            harness.cleanup()
        except (OSError, subprocess.SubprocessError):
            harness.cases.append({"id": "harness.cleanup", "status": "fail"})
    report = assess(config, harness.cases, runtime)
    private_json(output, report)
    return report["candidate_qualified"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        config_path = Path(args.config)
        if config_path.is_symlink() or not config_path.is_file() or config_path.stat().st_mode & 0o077 or not 0 < config_path.stat().st_size <= 1 << 20:
            raise ValueError("private configuration required")
        raise SystemExit(0 if run(json.loads(config_path.read_text()), args.output) else 1)
    except (ValueError, KeyError, OSError, TypeError):
        parser.exit(1, "native candidate qualification failed; inspect private evidence\n")
