import base64
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import candidate
import evidence_manifest
import release_policy as policy
import risk_acceptance as risk

AT = dt.datetime(2026, 10, 31, 12, tzinfo=dt.timezone.utc)
REV = "a" * 40
HASH = "b" * 64


def report(findings=()):
    scopes = sorted(policy.SOURCE_SCOPES | policy.IMAGE_SCOPES | policy.NATIVE_SCOPES)
    return {"schema_version": 1, "candidate_id": "candidate-1", "revision": REV,
            "artifact_manifest_sha256": HASH, "status": "completed", "required_scopes": scopes,
            "scopes": [{"id": s, "status": "completed", "authenticated": True,
                        "coverage_complete": True, "findings": list(findings) if i == 0 else []} for i, s in enumerate(scopes)]}


def finding(severity="high", classification="unresolved"):
    return {"scanner": "snyk", "id": "F-1", "component": "hub", "version": "2.0.58",
            "severity": severity, "classification": classification, "first_seen": "2026-10-30T12:00:00Z"}


def record(scope="source:npm:tests/e2e"):
    return {"schema_version": 1, "id": "RA-0001", "findings": [{"scope": scope, **{k: v for k, v in finding().items() if k in ("scanner", "id", "component", "version")}}],
            "classification": "accepted-risk", "severity": "high", "reason": "Reviewable public-safe rationale", "compensating_controls": "Restricted access",
            "owner": "lorconksu", "authorized_approver": "lorconksu", "approval_time": "2026-10-31T11:00:00Z", "expires_at": "2026-11-01T12:00:00Z",
            "remediation_reference": "issue:123", "private_evidence_reference": "evidence:review-1"}


class FakeGitHub:
    def __init__(self, raw):
        self.raw = raw
        self.actor = {"id": 13374789, "login": "lorconksu", "type": "User"}
        self.run = {"id": 123, "repository": {"full_name": risk.REPOSITORY}, "actor": self.actor,
                    "triggering_actor": self.actor, "head_sha": REV, "head_branch": "main", "path": risk.WORKFLOW,
                    "event": "workflow_dispatch", "run_attempt": 1, "status": "completed", "conclusion": "success", "created_at": "2026-10-31T11:30:00Z"}
        self.approval = None
        self.env = {"deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}, "protection_rules": [{"type": "required_reviewers", "prevent_self_review": False,
                    "reviewers": [{"type": "User", "reviewer": self.actor}]}]}

    def content(self, path, revision):
        return self.raw if path.endswith(".md") else b"trusted implementation"

    def get(self, path, raw=False):
        if path == "":
            return {"full_name": risk.REPOSITORY, "default_branch": "main", "owner": self.actor}
        if path == "actions/runs/123":
            return self.run
        if path.startswith("compare/"):
            return {"status": "ahead"}
        if path == "environments/" + risk.ENVIRONMENT + "/deployment-branch-policies":
            return {"branch_policies": [{"name": "main", "type": "branch"}]}
        if path == "environments/" + risk.ENVIRONMENT:
            return self.env
        if path == "actions/runs/123/artifacts?per_page=100":
            return {"total_count": 1, "artifacts": [{"id": 1, "name": "ssdf-approval-RA-0001", "expired": False, "size_in_bytes": 1000}]}
        if path == "actions/artifacts/1/zip":
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("approval.json", risk.canonical(self.approval))
            return buffer.getvalue()
        raise AssertionError(path)


class RiskApprovalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "RA-0001.md"
        self.path.write_bytes(b"---\n" + risk.canonical(record()) + b"\n---\nReasoning for human review.\n")
        self.api = FakeGitHub(self.path.read_bytes())
        self.approval = risk.prepare(self.api, self.path, REV, risk.sha(self.path.read_bytes()), 123)
        self.api.approval = self.approval

    def test_exact_owner_workflow_approval(self):
        self.assertEqual(risk.verify(self.api, self.path, self.approval, AT)["id"], "RA-0001")

    def test_tamper_scope_expiry_and_source_are_rejected(self):
        for field, value in (("record_sha256", "c" * 64), ("scope_sha256", "c" * 64), ("expires_at", "2030-01-01T00:00:00Z"), ("record_revision", "d" * 40)):
            with self.subTest(field=field):
                changed = {**self.approval, field: value}
                # A different record revision with equal content remains allowed
                # only if that exact revision was the authenticated dispatch input.
                self.api.approval = self.approval
                with self.assertRaises(ValueError):
                    risk.verify(self.api, self.path, changed, AT)

    def test_changed_record_cannot_reuse_approval(self):
        self.path.write_bytes(self.path.read_bytes().replace(b"Restricted access", b"Expanded access"))
        with self.assertRaises(ValueError):
            risk.verify(self.api, self.path, self.approval, AT)

    def test_expired_approval(self):
        with self.assertRaises(ValueError):
            risk.verify(self.api, self.path, self.approval, AT + dt.timedelta(days=2))

    def test_rerun_automation_wrong_branch_and_fork_fail(self):
        for field, value in (("run_attempt", 2), ("event", "push"), ("head_branch", "feature"), ("path", ".github/workflows/fake.yml"), ("actor", {"id": 1, "login": "bot", "type": "Bot"}), ("conclusion", "cancelled")):
            old = self.api.run[field]
            self.api.run[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                risk.verify(self.api, self.path, self.approval, AT)
            self.api.run[field] = old

    def test_coverage_review_uses_separate_exact_inventory_schema(self):
        path = Path(self.temp.name) / "CR-0001.md"
        item = {key: value for key, value in record().items() if key in {"schema_version", "reason", "owner", "authorized_approver", "approval_time", "expires_at", "private_evidence_reference"}}
        item.update(id="CR-0001", inventory_sha256=HASH)
        path.write_bytes(b"---\n" + risk.canonical(item) + b"\n---\nReviewed configured coverage; this does not approve vulnerabilities.\n")
        api = FakeGitHub(path.read_bytes())
        approval = risk.prepare(api, path, REV, risk.sha(path.read_bytes()), 123)
        api.approval = approval
        # Reuse the fake authenticated archive backend with the CR artifact ID.
        original_get = api.get
        def get(endpoint, raw=False):
            result = original_get(endpoint, raw)
            if isinstance(result, dict) and "artifacts" in result:
                result["artifacts"][0]["name"] = "ssdf-approval-CR-0001"
            return result
        api.get = get
        self.assertEqual(risk.verify(api, path, approval, AT)["inventory_sha256"], HASH)
        self.assertEqual(approval["scope_sha256"], risk.sha(risk.canonical({"inventory_sha256": HASH})))

    def test_missing_unknown_and_wildcard_report_scopes_are_rejected(self):
        for value in (None, "", "*", "image:unknown", "source:npm:other"):
            with self.subTest(scope=value):
                item = record()
                if value is None:
                    item["findings"][0].pop("scope")
                else:
                    item["findings"][0]["scope"] = value
                self.path.write_bytes(b"---\n" + risk.canonical(item) + b"\n---\nScope schema regression.\n")
                with self.assertRaises(ValueError):
                    risk.load_record(self.path)

    def test_moving_or_adding_report_scope_requires_new_approval(self):
        for expand in (False, True):
            with self.subTest(expand=expand):
                item = record()
                runtime = {**item["findings"][0], "scope": "image:veyport"}
                item["findings"] = item["findings"] + [runtime] if expand else [runtime]
                self.assertNotEqual(risk.sha(risk.canonical(item["findings"])), self.approval["scope_sha256"])
                self.path.write_bytes(b"---\n" + risk.canonical(item) + b"\n---\nChanged approved scope.\n")
                with self.assertRaises(ValueError):
                    risk.verify(self.api, self.path, self.approval, AT)

    def test_bootstrap_unprotected_environment_fails(self):
        self.api.env["protection_rules"] = []
        with self.assertRaises(ValueError):
            risk.verify(self.api, self.path, self.approval, AT)

    def test_duplicate_json_and_wildcard_scope_rejected(self):
        with self.assertRaises(ValueError):
            risk.strict_json('{"id":1,"id":2}')
        bad = record()
        bad["findings"][0]["version"] = "*"
        self.path.write_bytes(b"---\n" + risk.canonical(bad) + b"\n---\nHuman review\n")
        with self.assertRaises(ValueError):
            risk.load_record(self.path)


class ReleasePolicyTests(unittest.TestCase):
    def evaluate(self, evidence):
        with patch.object(policy, "validate_coverage", return_value={"id": "CR-test"}):
            return policy.evaluate([evidence], "candidate-1", REV, HASH, at=AT)

    def test_clean_complete_bound_evidence_passes_with_dast_deferred(self):
        self.assertEqual(self.evaluate(report())["dast"], "deferred-owner-decision")

    def test_missing_authenticated_coverage_review_blocks(self):
        with self.assertRaises(ValueError):
            policy.evaluate([report()], "candidate-1", REV, HASH, at=AT)

    def test_baseline_high_critical_auth_authz_audit_always_block(self):
        for severity, classification in (("critical", "unresolved"), ("high", "unresolved"), ("low", "authentication"), ("info", "authorization"), ("info", "required-audit")):
            with self.subTest(severity=severity, classification=classification), self.assertRaises(ValueError):
                self.evaluate(report([finding(severity, classification)]))

    def test_medium_30_low_90_days_and_missing_dates_fail(self):
        for severity, days in (("medium", 30), ("low", 90)):
            item = finding(severity)
            item["first_seen"] = (AT - dt.timedelta(days=days) + dt.timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.evaluate(report([item]))
            item["first_seen"] = (AT - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            with self.assertRaises(ValueError):
                self.evaluate(report([item]))
            item["first_seen"] = None
            with self.assertRaises(ValueError):
                self.evaluate(report([item]))

    def test_owner_permitted_license_is_preserved_without_vulnerability_sla(self):
        item = finding("medium")
        item.update(finding_type="license", first_seen=None, scanner="snyk", id="snyk:lic:npm:test:MPL-2.0")
        result = self.evaluate(report([item]))
        self.assertEqual(result["license_findings"], 1)
        self.assertEqual(sum(result["counts"].values()), 0)

    def test_operational_failure_missing_scope_mismatch_and_unknowns_block(self):
        for mutate in (lambda r: r.update(status="failed"), lambda r: r.update(revision="c" * 40), lambda r: r.update(artifact_manifest_sha256="c" * 64), lambda r: r["scopes"].pop(), lambda r: r["scopes"][0].update(authenticated=False), lambda r: r["scopes"][0].update(coverage_complete=False)):
            evidence = report()
            mutate(evidence)
            with self.assertRaises(ValueError):
                self.evaluate(evidence)

    def test_report_supplied_ignore_does_not_authorize(self):
        item = finding()
        item.update(approved_by="lorconksu", ignored=True, exception="RA-0001")
        with self.assertRaises(ValueError):
            self.evaluate(report([item]))

    def test_expired_unrelated_historical_record_does_not_block_clean_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "RA-0001.md"
            item = record()
            item["approval_time"] = "2026-01-01T00:00:00Z"
            item["expires_at"] = "2026-01-02T00:00:00Z"
            path.write_bytes(b"---\n" + risk.canonical(item) + b"\n---\nHistorical finding, no longer applicable.\n")
            with patch.object(policy, "validate_coverage", return_value={"id": "CR-test"}):
                result = policy.evaluate([report()], "candidate-1", REV, HASH, [(path, path.with_suffix(".approval.json"))], at=AT)
            self.assertEqual(result["decision"], "pass")
            self.assertEqual(result["exceptions"], [])

    def test_authenticated_e2e_approval_cannot_waive_matching_runtime_or_other_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "RA-0001.md"
            item = record("source:npm:tests/e2e")
            item["reason"] = "Limited to the nonshipped E2E development dependency"
            path.write_bytes(b"---\n" + risk.canonical(item) + b"\n---\nE2E-only approval; no runtime artifact is covered.\n")
            api = FakeGitHub(path.read_bytes())
            approval = risk.prepare(api, path, REV, risk.sha(path.read_bytes()), 123)
            api.approval = approval
            descriptor = path.with_suffix(".approval.json")
            descriptor.write_bytes(risk.canonical(approval))
            evidence = report()
            scopes = {entry["id"]: entry for entry in evidence["scopes"]}
            scopes["source:npm:tests/e2e"]["findings"] = [finding()]
            with patch.object(policy, "validate_coverage", return_value={"id": "CR-test"}):
                passed = policy.evaluate([evidence], "candidate-1", REV, HASH, [(path, descriptor)], api=api, at=AT)
                self.assertEqual(passed["decision"], "pass")
                for other in ("image:veyport", "image:audit-ingest", "source:npm:web"):
                    with self.subTest(other=other):
                        scopes[other]["findings"] = [finding()]
                        with self.assertRaisesRegex(ValueError, "blocking finding lacks a valid scoped owner approval"):
                            policy.evaluate([evidence], "candidate-1", REV, HASH, [(path, descriptor)], api=api, at=AT)
                        scopes[other]["findings"] = []

    def test_authenticated_record_can_explicitly_approve_multiple_exact_scopes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "RA-0001.md"
            item = record("source:npm:tests/e2e")
            item["findings"].append({**item["findings"][0], "scope": "image:veyport"})
            path.write_bytes(b"---\n" + risk.canonical(item) + b"\n---\nBoth exact scopes explicitly reviewed.\n")
            api = FakeGitHub(path.read_bytes())
            approval = risk.prepare(api, path, REV, risk.sha(path.read_bytes()), 123)
            api.approval = approval
            descriptor = path.with_suffix(".approval.json")
            descriptor.write_bytes(risk.canonical(approval))
            evidence = report()
            for scope in evidence["scopes"]:
                if scope["id"] in ("source:npm:tests/e2e", "image:veyport"):
                    scope["findings"] = [finding()]
            with patch.object(policy, "validate_coverage", return_value={"id": "CR-test"}):
                passed = policy.evaluate([evidence], "candidate-1", REV, HASH, [(path, descriptor)], api=api, at=AT)
            self.assertEqual(passed["decision"], "pass")
            self.assertEqual([entry["id"] for entry in passed["exceptions"]], ["RA-0001"])
            self.assertEqual(passed["counts"]["high"], 1, "presentation deduplication must not expand approval scope")

    def test_authorization_failure_prevents_any_publication(self):
        script = Path(__file__).with_name("authorize_publication.sh").resolve()
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "published"
            result = subprocess.run(["bash", "-c", 'bash "$1" "$2" && touch "$3"', "test", str(script), directory, str(marker)], cwd=root, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists())

    def test_each_final_gate_failure_stops_the_publication_call(self):
        script = Path(__file__).with_name("authorize_publication.sh").resolve()
        checkout = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "tools"
            tools.mkdir()
            tool = tools / "python3"
            tool.write_text('#!/bin/bash\nkey="${1##*/}:$2"\nif [ "$key" = "$FAIL_POINT" ]; then exit 1; fi\nexit 0\n')
            tool.chmod(0o755)
            (root / "candidate.json").write_text('{}')
            (root / "evidence-manifest.sha256").write_text('b' * 64)
            marker = root / "published"
            env = {**os.environ, "PATH": str(tools) + ":" + os.environ["PATH"], "GITHUB_REPOSITORY": risk.REPOSITORY,
                   "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": REV,
                   "SOURCE_WORKFLOW": ".github/workflows/release.yml", "VERSION": "2.0.58"}
            for point in ("evidence_manifest.py:--verify", "candidate.py:verify-files", "candidate.py:verify-qualification", "release_policy.py:--report", "evidence.py:wait-receipt"):
                with self.subTest(point=point):
                    result = subprocess.run(["bash", "-c", 'bash "$1" "$2" && touch "$3"', "test", str(script), str(root), str(marker)], cwd=checkout, env={**env, "FAIL_POINT": point}, capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())

    def test_evaluation_inputs_cannot_change_after_signed_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "delivery/reports").mkdir(parents=True)
            (root / "security").mkdir()
            report_path = root / "security/report.json"
            report_path.write_text('{"findings":[]}')
            (root / "candidate.json").write_text('{}')
            env = {"GITHUB_REPOSITORY": risk.REPOSITORY, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": REV}
            with patch.dict(os.environ, env):
                manifest = evidence_manifest.prepare(root / "bundle", root / "delivery", root / "security", root / "candidate.json", ".github/workflows/release.yml", "2.0.58", True)
            manifest_path = root / "manifest.json"
            manifest_path.write_bytes(risk.canonical(manifest))
            digest = risk.sha(risk.canonical(manifest))
            evidence_manifest.verify_sources(manifest_path, digest, root / "delivery", root / "security", root / "candidate.json")
            report_path.write_text('{"findings":["replaced"]}')
            with self.assertRaises(ValueError):
                evidence_manifest.verify_sources(manifest_path, digest, root / "delivery", root / "security", root / "candidate.json")

    def test_no_plaintext_candidate_or_reports_uploaded(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/delivery.yml").read_text()
        self.assertNotIn("verified-delivery", workflow)
        self.assertNotIn("release-evidence.tar.gz", workflow)
        self.assertIn("transport/candidate.age", workflow)
        self.assertIn("transport/evidence.age", workflow)
        self.assertLess(workflow.index("Require durable authenticated"), workflow.index("Publish exactly"))


class CandidateTests(unittest.TestCase):
    def test_inventory_tamper_and_links_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "image.oci.tar").write_bytes(b"exact candidate")
            expected = {"files": candidate.inventory(root)}
            candidate.verify_files(root, expected)
            (root / "image.oci.tar").write_bytes(b"replaced candidate")
            with self.assertRaises(ValueError):
                candidate.verify_files(root, expected)
            (root / "link").symlink_to(root / "image.oci.tar")
            with self.assertRaises(ValueError):
                candidate.inventory(root)

    def test_native_signature_candidate_and_expiry_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(root / "key")], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(root / "key"), "-pubout", "-out", str(root / "pub")], check=True, capture_output=True)
            manifest = {"repository": risk.REPOSITORY, "run_id": 1, "run_attempt": 1, "revision": REV, "candidate_id": "candidate-1", "audit_profile": "standard", "files": []}
            payload = {key: manifest[key] for key in ("repository", "run_id", "run_attempt", "revision", "candidate_id", "audit_profile")}
            payload.update(artifact_manifest_sha256=risk.sha(risk.canonical(manifest)), status="qualified", qualified_at="2026-10-31T11:59:00Z", expires_at="2026-10-31T12:20:00Z")
            native = report()
            native["audit_profile"] = "standard"
            native["artifact_manifest_sha256"] = payload["artifact_manifest_sha256"]
            payload["report"] = native
            (root / "payload").write_bytes(risk.canonical(payload))
            signature = subprocess.check_output(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(root / "key"), "-in", str(root / "payload")])
            envelope = {"payload": payload, "signature": base64.b64encode(signature).decode()}
            candidate.verify_qualification(envelope, manifest, root / "pub", AT)
            with self.assertRaises(ValueError):
                candidate.verify_qualification(envelope, {**manifest, "candidate_id": "other"}, root / "pub", AT)
            with self.assertRaises(ValueError):
                candidate.verify_qualification(envelope, manifest, root / "pub", AT + dt.timedelta(minutes=21))
            changed = copy.deepcopy(envelope)
            changed["payload"]["status"] = "qualified-by-attacker"
            with self.assertRaises(Exception):
                candidate.verify_qualification(changed, manifest, root / "pub", AT)


if __name__ == "__main__":
    unittest.main()
