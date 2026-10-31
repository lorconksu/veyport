import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import native_protocol
import snyk


class ScannerEvidenceTests(unittest.TestCase):
    def baseline(self):
        return {"ok": True, "packageManager": "npm", "dependencyCount": 12, "vulnerabilities": []}

    def test_operational_failure_empty_inventory_filtering_and_inconsistent_exit_fail(self):
        for change, exit_code in [({}, 2), ({"dependencyCount": 0}, 0),
                                  ({"filtered": {"ignore": [{"id": "ignored"}]}}, 0),
                                  ({"error": "partial"}, 0), ({}, 1),
                                  ({"ok": False}, 0), ({"packageManager": "pip"}, 0)]:
            report = {**self.baseline(), **change}
            with self.subTest(change=change, exit_code=exit_code), self.assertRaises(ValueError):
                snyk.normalize(report, exit_code, "npm")

    def test_preserves_license_type_severity_paths_and_unknown_first_seen(self):
        report = self.baseline()
        report["ok"] = False
        report["vulnerabilities"] = [
            {"id": "CVE-example", "name": "example", "version": "1", "severity": "high", "from": ["root", "example"]},
            {"id": "snyk:lic:npm:example:MPL-2.0", "name": "example", "version": "1", "severity": "medium"},
        ]
        findings, count = snyk.normalize(report, 1, "npm")
        self.assertEqual(count, 12)
        self.assertEqual([f["finding_type"] for f in findings], ["vulnerability", "license"])
        self.assertEqual(findings[0]["severity"], "high")
        self.assertEqual(findings[0]["dependency_path"], ["root", "example"])
        self.assertIsNone(findings[0]["first_seen"])

    def test_duplicate_paths_group_without_losing_evidence(self):
        report = self.baseline()
        report["ok"] = False
        finding = {"id": "example", "name": "example", "version": "1", "severity": "high", "from": ["root", "a", "example"]}
        report["vulnerabilities"] = [finding, {**finding, "from": ["root", "b", "example"]}]
        findings, _ = snyk.normalize(report, 1, "npm")
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0]["dependency_paths"]), 2)
        report["vulnerabilities"][1]["severity"] = "low"
        with self.assertRaises(ValueError):
            snyk.normalize(report, 1, "npm")

    def image(self, path, corrupt=False):
        content = {}

        def descriptor(data):
            raw = json.dumps(data).encode()
            digest = hashlib.sha256(raw).hexdigest()
            content["blobs/sha256/" + digest] = raw
            return {"digest": "sha256:" + digest, "size": len(raw)}

        config = descriptor({"architecture": "amd64", "os": "linux"})
        layer = descriptor({"content": "example"})
        manifest = descriptor({"config": config, "layers": [layer]})
        content["index.json"] = json.dumps({"manifests": [manifest]}).encode()
        if corrupt:
            content["blobs/sha256/" + layer["digest"][7:]] = b"corrupt"
        with tarfile.open(path, "w") as image:
            for name, raw in content.items():
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                image.addfile(member, io.BytesIO(raw))
        return manifest["digest"]

    def test_native_image_requires_matching_manifest_and_all_exact_layer_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "image.tar"
            digest = self.image(path)
            snyk.verify_image(path, digest)
            with self.assertRaises(ValueError):
                snyk.verify_image(path, "sha256:" + "0" * 64)
            self.image(path, corrupt=True)
            with self.assertRaises(ValueError):
                snyk.verify_image(path, digest)

    def test_missing_skipped_failed_or_package_failure_cannot_qualify_fixtures(self):
        events = []
        for members in native_protocol.REQUIRED.values():
            for package, tests in members.items():
                events.extend({"Action": "pass", "Package": package, "Test": test} for test in tests)
                events.append({"Action": "pass", "Package": package})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tests.jsonl"
            for mutation in ("none", "missing", "skip", "fail", "package_failure"):
                data = copy.deepcopy(events)
                if mutation == "missing":
                    data.pop(0)
                elif mutation in ("skip", "fail"):
                    data[0]["Action"] = mutation
                elif mutation == "package_failure":
                    data.append({"Action": "fail", "Package": events[0]["Package"]})
                path.write_text("\n".join(json.dumps(e) for e in data))
                report = native_protocol.assess(path, "f" * 40)
                self.assertEqual(report["status"], "completed" if mutation == "none" else "failed")
                self.assertIs(report["candidate_qualified"], False)


if __name__ == "__main__":
    unittest.main()
