#!/usr/bin/env python3
"""Verify existing native protocol fixture tests from one Go JSON test stream.

This exports source-fixture evidence, never candidate qualification. Capture the
existing CI execution with `go test -json -count=1 -covermode=atomic ...` rather
than running a duplicate suite merely to export a report.
"""
import argparse
import json
from pathlib import Path
import re

from snyk import sha256, write_private

REQUIRED = {
    "native:fixture:grpc": {
        "github.com/wyiu/veyport/hub/internal/grpcserver": (
            "TestExecutionRPCRequiresVerifiedCurrentEnrolledCertificate",
            "TestExecutionCertificateWithoutNodeIdentityCannotAcquireAuthority",
            "TestExecutionOutputSequenceAndCompleteResult",
            "TestExecutionMalformedEOFAndOutputCancellationCannotPublishSuccess",
            "TestApplicationRPCAdmissionRejectsBeforeReadingOrReleasesCapacity",
            "TestExecutionInputRejectionPreservesExactSequenceAndSingleEOF",
        ),
    },
    "native:fixture:ssh": {
        "github.com/wyiu/veyport/hub/internal/sshgw": (
            "TestGatewayRejectsCertificateFromAnotherCA",
            "TestGatewayRejectsExpiredCertificate",
            "TestGatewayRejectsPrincipalMismatch",
            "TestGatewayRejectsBarePublicKey",
            "TestGatewayUnauthorizedUserRefused",
            "TestGatewayRefusesOutOfScopeCapabilities",
            "TestIdleSSHClientClosesWhenRoleOrRootPermissionIsRevoked",
            "TestExecSyntaxAndPTYRefusal",
            "TestBridgeOpenRequestCarriesExecutionUser",
            "TestProtectedAdmissionPersistenceFaultCannotLaunchOrReplayConsumedPermit",
            "TestProtectedAdmissionArchiveReceiptCannotOverrideRevokedActor",
            "TestProtectedSubmissionOversizeAndOrdinaryStdinCannotBecomePreparedInput",
        ),
    },
}


def assess(path, revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("immutable fixture revision required")
    path = Path(path)
    if path.is_symlink() or not 0 < path.stat().st_size <= 128 << 20:
        raise ValueError("bounded Go execution evidence required")
    passed, failed, packages = set(), set(), set()
    for line in path.read_text().splitlines():
        event = json.loads(line)
        action, package, test = event.get("Action"), event.get("Package"), event.get("Test")
        if action in ("pass", "fail", "skip"):
            if test:
                (passed if action == "pass" else failed).add((package, test))
            elif action == "pass":
                packages.add(package)
            else:
                failed.add((package, ""))
    scopes = []
    for scope, members in REQUIRED.items():
        missing = [(p, t) for p, tests in members.items() for t in tests if (p, t) not in passed]
        complete = not missing and all(p in packages and not any(f[0] == p for f in failed) for p in members)
        scopes.append({"id": scope, "status": "completed" if complete else "failed",
                       "coverage_complete": complete, "missing_required_tests": missing,
                       "findings": [], "test_count": sum(len(t) for t in members.values())})
    return {"schema_version": 1, "revision": revision,
            "status": "completed" if all(s["status"] == "completed" for s in scopes) else "failed",
            "evidence_kind": "source-fixture-tests", "report_sha256": sha256(path),
            "candidate_qualified": False, "scopes": scopes}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        report = assess(args.report, args.revision)
        write_private(args.output, report)
        raise SystemExit(0 if report["status"] == "completed" else 1)
    except (OSError, ValueError, TypeError):
        parser.exit(1, "native fixture evidence incomplete\n")
