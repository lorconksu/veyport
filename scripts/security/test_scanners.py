import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

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


class NpmCoverageTests(unittest.TestCase):
    PAIRS = [("@testing-library/react", "16.3.2"), ("@testing-library/dom", "10.4.1"),
             ("@types/aria-query", "5.0.4"), ("ansi-styles", "5.2.0"),
             ("dom-accessibility-api", "0.5.16"), ("lz-string", "1.5.0"),
             ("pretty-format", "27.5.1"), ("react-is", "17.0.2")]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "web"
        self.project.mkdir()
        self.lock_path = self.project / "package-lock.json"
        self.lock = {"name": "web", "version": "0.0.0", "lockfileVersion": 3,
                     "packages": {"": {"name": "web", "version": "0.0.0"}}}
        for name, version in self.PAIRS:
            self.lock["packages"]["node_modules/" + name] = {"version": version}
        self.write_lock()

    def write_lock(self):
        self.lock_path.write_text(json.dumps(self.lock))

    def report(self, pairs=None):
        pairs = self.PAIRS if pairs is None else pairs
        packages = [{"id": "web@0.0.0", "info": {"name": "web", "version": "0.0.0"}}]
        nodes = [{"nodeId": "root-node", "pkgId": "web@0.0.0", "deps": []}]
        for name, version in pairs:
            identity = name + "@" + version
            packages.append({"id": identity, "info": {"name": name, "version": version}})
            nodes[0]["deps"].append({"nodeId": identity})
            nodes.append({"nodeId": identity, "pkgId": identity, "deps": []})
        return {"ok": True, "packageManager": "npm", "dependencyCount": len(pairs), "vulnerabilities": [],
                "depGraph": {"schemaVersion": "1.3.0", "pkgManager": {"name": "npm"},
                             "pkgs": packages, "graph": {"rootNodeId": "root-node", "nodes": nodes}}}

    def collect(self, report):
        (self.project / "package.json").write_text('{"name":"web","version":"0.0.0"}')
        manifest = self.root / "candidate.json"
        manifest.write_text('{}')
        output = self.root / "evidence"
        args = SimpleNamespace(root=str(self.root), output=str(output), kind="source", revision="a" * 40,
                               candidate_id="candidate-1", artifact_manifest=str(manifest), scanner="snyk",
                               org=None, timeout=10, python="python3")
        commands = []

        def execute(command, cwd, result_path, timeout):
            commands.append(command)
            result_path.write_text(json.dumps(report))
            result_path.with_suffix('.stdout').write_text('private dependency tree and scanner output')
            result_path.with_suffix('.stderr').write_text('')
            return 1 if report["vulnerabilities"] else 0

        def check_output(command, **kwargs):
            if command == ["snyk", "--version"]:
                return snyk.VERSION.encode()
            if command == ["git", "rev-parse", "HEAD"]:
                return b'a' * 40
            return b''

        with patch.dict(snyk.os.environ, {"SNYK_TOKEN": "synthetic-test-token"}), \
                patch.object(snyk, "SOURCES", {"source:npm:web": ("web", "package.json", "npm")}), \
                patch.object(snyk, "inventory", return_value=["web/package.json"]), \
                patch.object(snyk.subprocess, "check_output", side_effect=check_output), \
                patch.object(snyk, "execute", side_effect=execute):
            accepted = snyk.collect(args)
        return accepted, json.loads((output / "assessment.json").read_text()), commands, output

    def test_nonempty_scan_omitting_seven_required_peers_cannot_complete_scope(self):
        report = self.report(self.PAIRS[:1])
        # The vulnerability-only normalizer accepts this successful nonempty
        # scan. The complete scope must additionally verify the scanned graph.
        self.assertEqual(snyk.normalize(report, 0, "npm")[1], 1)
        accepted, envelope, commands, output = self.collect(report)
        self.assertFalse(accepted)
        self.assertFalse(envelope["scopes"][0]["coverage_complete"])
        self.assertEqual(envelope["scopes"][0]["dependency_count"], 1)
        self.assertIn("--print-deps", commands[0])
        self.assertTrue((output / "scope-0.json").is_file())
        self.assertTrue((output / "scope-0.dep-graph.json").is_file())

    def test_exact_scan_preserves_graph_and_completes_without_another_command(self):
        report = self.report()
        accepted, envelope, commands, output = self.collect(report)
        self.assertTrue(accepted)
        self.assertTrue(envelope["scopes"][0]["coverage_complete"])
        self.assertEqual(len(commands), 1)
        self.assertEqual(json.loads((output / "scope-0.dep-graph.json").read_text()), report["depGraph"])
        self.assertEqual(envelope["scopes"][0]["dependency_count"], len(self.PAIRS))

    def test_coverage_failure_retains_findings_without_assigning_discovery_dates(self):
        report = self.report(self.PAIRS[:1])
        report.update(ok=False, vulnerabilities=[{"id": "SNYK-JS-URIJS-19963961", "name": "uri-js",
                      "version": "4.4.1", "severity": "medium", "from": ["web", "uri-js"]}])
        accepted, envelope, _, _ = self.collect(report)
        self.assertFalse(accepted)
        finding = envelope["scopes"][0]["findings"][0]
        self.assertEqual(finding["id"], "SNYK-JS-URIJS-19963961")
        self.assertIsNone(finding["first_seen"])
        self.assertEqual(envelope["scopes"][0]["dependency_count"], 1)

    def test_missing_extra_or_wrong_version_packages_are_rejected(self):
        inventories = [self.PAIRS[:-1], self.PAIRS + [("extra", "1.0.0")],
                       [(name, "99.0.0" if index == 0 else version) for index, (name, version) in enumerate(self.PAIRS)]]
        for pairs in inventories:
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                snyk.validate_npm_coverage(self.report(pairs), self.lock_path)

    def test_duplicate_nested_lock_instances_compare_as_unique_package_pairs(self):
        self.lock["packages"]["node_modules/parent/node_modules/react-is"] = {"version": "17.0.2"}
        self.write_lock()
        snyk.validate_npm_coverage(self.report(), self.lock_path)

    def test_malformed_or_incomplete_graph_cannot_hide_packages(self):
        mutations = [lambda r: r.pop("depGraph"),
                     lambda r: r["depGraph"].update(schemaVersion="unexpected"),
                     lambda r: r["depGraph"].update(pkgManager={"name": "pip"}),
                     lambda r: r["depGraph"].update(pkgs=None),
                     lambda r: r["depGraph"]["graph"].update(nodes=None),
                     lambda r: r["depGraph"]["graph"].update(rootNodeId="missing-root"),
                     lambda r: r["depGraph"]["graph"]["nodes"][0].update(deps=[]),
                     lambda r: r["depGraph"]["graph"]["nodes"][0]["deps"].append({"nodeId": "missing-child"}),
                     lambda r: r["depGraph"]["graph"]["nodes"][1].update(pkgId="missing-package"),
                     lambda r: r["depGraph"]["graph"]["nodes"].append(copy.deepcopy(r["depGraph"]["graph"]["nodes"][1])),
                     lambda r: r["depGraph"]["pkgs"].append(copy.deepcopy(r["depGraph"]["pkgs"][1])),
                     lambda r: r["depGraph"]["pkgs"][1]["info"].update(version=""),
                     lambda r: r["depGraph"]["pkgs"][0]["info"].update(name="foreign-root"),
                     lambda r: r.update(dependencyCount=1)]
        for mutate in mutations:
            report = self.report()
            mutate(report)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                snyk.validate_npm_coverage(report, self.lock_path)

    def test_unused_package_and_root_package_reuse_are_rejected(self):
        report = self.report()
        report["depGraph"]["pkgs"].append({"id": "unused@1", "info": {"name": "unused", "version": "1"}})
        with self.assertRaises(ValueError):
            snyk.validate_npm_coverage(report, self.lock_path)
        report = self.report()
        report["depGraph"]["graph"]["nodes"][1]["pkgId"] = "web@0.0.0"
        with self.assertRaises(ValueError):
            snyk.validate_npm_coverage(report, self.lock_path)

    def test_unsupported_lock_entries_links_workspaces_and_missing_versions_fail(self):
        mutations = [lambda lock: lock.update(lockfileVersion=1),
                     lambda lock: lock["packages"].update({"local/workspace": {"version": "1"}}),
                     lambda lock: lock["packages"].update({"node_modules/..": {"version": "1"}}),
                     lambda lock: lock["packages"]["node_modules/@testing-library/dom"].update(link=True),
                     lambda lock: lock["packages"]["node_modules/@testing-library/dom"].pop("version"),
                     lambda lock: lock["packages"][""].update(workspaces=["packages/*"])]
        original = copy.deepcopy(self.lock)
        for mutate in mutations:
            self.lock = copy.deepcopy(original)
            mutate(self.lock)
            self.write_lock()
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                snyk.validate_npm_coverage(self.report(), self.lock_path)

    def test_bounded_input_duplicate_json_keys_and_mutated_lock_fail(self):
        with patch.object(snyk, "MAX_NPM_ENTRIES", 2), self.assertRaises(ValueError):
            snyk.validate_npm_coverage(self.report(), self.lock_path)
        with patch.object(snyk, "MAX_NPM_EDGES", 2), self.assertRaises(ValueError):
            snyk.validate_npm_coverage(self.report(), self.lock_path)
        with patch.object(snyk, "MAX_NPM_LOCK_BYTES", 1), self.assertRaises(ValueError):
            snyk.validate_npm_coverage(self.report(), self.lock_path)
        with self.assertRaises(ValueError):
            snyk.validate_npm_coverage(self.report(), self.lock_path, expected_hash="0" * 64)
        self.lock_path.write_text('{"lockfileVersion":3,"packages":{},"packages":{}}')
        with self.assertRaises(ValueError):
            snyk.validate_npm_coverage(self.report(), self.lock_path)


if __name__ == "__main__":
    unittest.main()
