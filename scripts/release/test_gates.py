import hashlib
import json
import tempfile
import platform
import io
import os
import subprocess
import tarfile
import unittest
from pathlib import Path

from artifacts import BINARIES, manifest
from check_scan import check, REVIEWED_ANNOTATIONS
from go_binary_evidence import decode_stream, package_absent
from lint_changed import changed_lines
from metadata import identity
from oci_binding import binding, INDEX, MANIFEST


class ReleaseGates(unittest.TestCase):
    def test_scanned_native_image_is_bound_to_attested_archive_and_version(self):
        version, revision = "2.0.50-prototype.1", "a" * 40
        config = json.dumps({"architecture": "amd64", "os": "linux", "config": {"Labels": {"org.opencontainers.image.version": version, "org.opencontainers.image.revision": revision}}}).encode()
        def descriptor(raw, media, **extra):
            return {"mediaType": media, "digest": "sha256:" + hashlib.sha256(raw).hexdigest(), "size": len(raw), **extra}
        config_ref = descriptor(config, "application/vnd.oci.image.config.v1+json")
        native = json.dumps({"schemaVersion": 2, "mediaType": MANIFEST, "config": config_ref, "layers": []}).encode()
        native_ref = descriptor(native, MANIFEST, platform={"architecture": "amd64", "os": "linux"})
        published = json.dumps({"schemaVersion": 2, "mediaType": INDEX, "manifests": [native_ref]}).encode()
        root = json.dumps({"schemaVersion": 2, "mediaType": INDEX, "manifests": [descriptor(published, INDEX)]}).encode()
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "attested.oci.tar"
            with tarfile.open(archive, "w") as tar:
                for name, raw in [("index.json", root)] + [("blobs/sha256/" + hashlib.sha256(raw).hexdigest(), raw) for raw in (published, native, config)]:
                    member = tarfile.TarInfo(name)
                    member.size = len(raw)
                    tar.addfile(member, io.BytesIO(raw))
            evidence = binding(archive, published, native, json.dumps(json.loads(config), indent=2).encode(), version, revision)
            self.assertEqual(evidence["native_manifest_digest"], native_ref["digest"])
            self.assertEqual(evidence["published_index_digest"], descriptor(published, INDEX)["digest"])
            for altered in (b"{}", native + b" "):
                with self.assertRaises(ValueError):
                    binding(archive, published, altered, config, version, revision)
            with self.assertRaises(ValueError):
                binding(archive, published, native, config, "wrong-version", revision)
            with self.assertRaises(ValueError):
                binding(archive, published + b" ", native, config, version, revision)

    def test_publication_never_replaces_immutable_tag_or_promotes_prototype(self):
        script = Path(__file__).with_name("publish_delivery.sh").resolve()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            delivery, tools = root / "delivery", root / "tools"
            (delivery / "reports").mkdir(parents=True)
            tools.mkdir()
            raw = b'{"schemaVersion":2,"synthetic":"exact fixture manifest"}'
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            for target in ("veyport", "audit-ingest", "audit-export"):
                (delivery / (target + ".oci.tar")).write_bytes(b"synthetic scanned archive")
                (delivery / "reports" / (target + ".digest")).write_text(digest + "\n")
            files = sorted(p for p in delivery.rglob("*") if p.is_file())
            (delivery / "DELIVERY_SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + str(p.relative_to(delivery)) + "\n" for p in files))
            (root / "manifest").write_bytes(raw)
            fake = tools / "skopeo"
            fake.write_text("""#!/usr/bin/env python3
import json,os,pathlib,sys
r=pathlib.Path(os.environ['REGISTRY_FIXTURE'])
with (r/'calls').open('a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')
args=sys.argv[1:]
if args[0]=='inspect':
 destination=args[-1]
 if not destination.startswith('docker://'): print('invalid Docker transport reference',file=sys.stderr);sys.exit(2)
 mode=os.environ['REGISTRY_MODE']
 copied=(r/destination.rsplit(':',1)[0].replace('/','_')).exists()
 if mode=='auth': print('unauthorized: authentication required',file=sys.stderr);sys.exit(1)
 if mode=='absent' and not copied: print('manifest unknown',file=sys.stderr);sys.exit(1)
 if mode=='mismatch': sys.stdout.buffer.write(b'{}');sys.exit(0)
 sys.stdout.buffer.write((r/'manifest').read_bytes())
elif args[0]=='copy':
 if not args[-1].startswith('docker://') or not args[-2].startswith(('docker://','oci-archive:')): print('invalid copy transport reference',file=sys.stderr);sys.exit(2)
 (r/args[-1].rsplit(':',1)[0].replace('/','_')).touch()
else: sys.exit(2)
""")
            fake.chmod(0o700)
            fake_git = tools / "git"
            fake_git.write_text("""#!/usr/bin/env python3
import os,pathlib,sys
r=pathlib.Path(os.environ['REGISTRY_FIXTURE']);mode=os.environ.get('TAG_MODE','match')
if mode=='outage': print('private-upstream-canary',file=sys.stderr);sys.exit(1)
if mode=='absent' and not (r/'git-created').exists(): sys.exit(0)
if mode.startswith('create-'):
 if not (r/'git-created').exists(): sys.exit(0)
 if mode=='create-outage': print('private-upstream-canary',file=sys.stderr);sys.exit(1)
 if mode=='create-unconfirmed': sys.exit(0)
ref=sys.argv[-2];sha='a'*40
if mode in ('mismatch','create-wrong'): sha='b'*40
if mode=='malformed': print('not-a-sha\\t'+ref);sys.exit(0)
if mode=='orphan': print(sha+'\\t'+ref+'^{}');sys.exit(0)
if mode=='duplicate': print(sha+'\\t'+ref)
if mode=='unrelated': print(sha+'\\trefs/tags/unrelated');sys.exit(0)
if mode=='annotated':
 print('c'*40+'\\t'+ref);print(sha+'\\t'+ref+'^{}')
else: print(sha+'\\t'+ref)
""")
            fake_git.chmod(0o700)
            fake_gh = tools / "gh"
            fake_gh.write_text("""#!/usr/bin/env python3
import json,os,pathlib,sys
r=pathlib.Path(os.environ['REGISTRY_FIXTURE']);payload=json.load(sys.stdin)
if sys.argv[1:]!=['api','--method','POST','repos/fixture/repo/git/refs','--input','-'] or payload['sha']!='a'*40:sys.exit(2)
(r/'git-create-request.json').write_text(json.dumps(payload));(r/'git-created').touch()
if os.environ['TAG_MODE']=='create-lostreply': print('private-upstream-canary',file=sys.stderr);sys.exit(1)
""")
            fake_gh.chmod(0o700)
            env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"], "REGISTRY_FIXTURE": str(root), "GITHUB_REPOSITORY": "fixture/repo"}
            def run(mode, tag_mode="match", prototype=True):
                (root / "calls").write_text("")
                tag, version = ("prototype-ssh-passthrough.1", "2.0.50-prototype.1") if prototype else ("v2.0.50", "2.0.50")
                result = subprocess.run(["bash", str(script), str(delivery), tag, version, str(prototype).lower(), "a" * 40], env={**env, "REGISTRY_MODE": mode, "TAG_MODE": tag_mode}, capture_output=True, timeout=5)
                calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()]
                return result, calls
            for mode in ("auth", "mismatch"):
                result, calls = run(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(call[0] == "copy" for call in calls))
            result, calls = run("absent")
            self.assertEqual(result.returncode, 0, result.stderr)
            copies = [call for call in calls if call[0] == "copy"]
            self.assertEqual(len(copies), 3)
            self.assertTrue(all("--all" in call and "--preserve-digests" in call for call in copies))
            self.assertTrue(all(call[-1].endswith(":prototype-ssh-passthrough.1") for call in copies))
            self.assertEqual({tuple(call[-2:]) for call in copies}, {
                ("oci-archive:" + str(delivery / (target + ".oci.tar")), "docker://docker.io/yiucloud/" + repository + ":prototype-ssh-passthrough.1")
                for target, repository in (("veyport", "veyport"), ("audit-ingest", "veyport-audit-ingest"), ("audit-export", "veyport-audit-export"))
            })
            result, calls = run("match")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(any(call[0] == "copy" for call in calls))
            for prototype in (True, False):
                for tag_mode in ("mismatch", "outage", "malformed", "orphan", "duplicate", "unrelated"):
                    result, calls = run("match", tag_mode, prototype)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(calls, [], "tag mismatch/outage reached registry publication")
                    self.assertNotIn(b"private-upstream-canary", result.stderr)
                result, calls = run("match", "match", prototype)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((root / "git-create-request.json").exists())
                if not prototype:
                    copies = [call for call in calls if call[0] == "copy"]
                    self.assertEqual(len(copies), 9)
                    self.assertTrue(all("--all" in call and "--preserve-digests" in call for call in copies))
                    self.assertEqual({tuple(call[-2:]) for call in copies}, {
                        ("docker://docker.io/yiucloud/" + repository + "@" + digest, "docker://docker.io/yiucloud/" + repository + ":" + channel)
                        for repository in ("veyport", "veyport-audit-ingest", "veyport-audit-export")
                        for channel in ("2.0.50", "2.0", "latest")
                    })
                result, calls = run("match", "annotated", prototype)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((root / "git-create-request.json").exists())
                expected_tag = "prototype-ssh-passthrough.1" if prototype else "v2.0.50"
                for tag_mode in ("absent", "create-lostreply", "create-wrong", "create-outage", "create-unconfirmed"):
                    result, calls = run("match", tag_mode, prototype)
                    if tag_mode in ("absent", "create-lostreply"):
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(calls, [], "unconfirmed creation reached registry publication")
                    self.assertNotIn(b"private-upstream-canary", result.stderr)
                    self.assertEqual(json.loads((root / "git-create-request.json").read_text()), {"ref": "refs/tags/" + expected_tag, "sha": "a" * 40})
                    (root / "git-create-request.json").unlink()
                    (root / "git-created").unlink()
                result = subprocess.run(["python3", str(script.with_name("git_tag.py")), "check", expected_tag, "a" * 40, "fixture/repo"], env={**env, "TAG_MODE": "absent"}, capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "git-create-request.json").exists(), "release recheck created a missing tag")
            (delivery / "veyport.oci.tar").write_bytes(b"tampered after scan")
            result, calls = run("absent")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, [])

    def test_prototype_identity_rejects_release_channels_and_injection(self):
        identity("2.0.50-prototype.1", "prototype-ssh-passthrough.1", "a" * 40, "refs/heads/011-cli-command-passthrough", True)
        identity("2.0.50", "v2.0.50", "a" * 40, "refs/tags/v2.0.50", False)
        for version, tag, ref in (("2.0.50", "v2.0.50", "refs/heads/feature"), ("2.0.50-prototype.1", "latest", "refs/heads/feature"), ("2.0.50-prototype.1", "prototype-ssh-passthrough.1", "refs/heads/main"), ("2.0.50-prototype.1\nX=bad", "prototype-ssh-passthrough.1", "refs/heads/feature")):
            with self.assertRaises(ValueError):
                identity(version, tag, "a" * 40, ref, True)
        with self.assertRaises(ValueError):
            identity("2.0.50", "v2.0.50", "a" * 40, "refs/heads/main", False)

    def test_lint_only_new_lines_without_excluding_changed_files(self):
        self.assertEqual(changed_lines("@@ -2,0 +3,2 @@\n+a\n+b\n@@ -8 +10 @@\n-c\n+d\n@@ -12,2 +14,0 @@\n-old\n-old\n"), {3, 4, 10})

    def test_exact_binary_package_absence_requires_complete_known_advisory_proof(self):
        messages = [
            {"config": {"scanner_name": "govulncheck", "scan_mode": "binary", "scan_level": "symbol"}},
            {"SBOM": {"go_version": "go1.26.9", "modules": [{"path": "golang.org/x/crypto", "version": "v0.57.0"}]}},
            {"osv": {"id": "GO-2026-5932", "affected": [{"package": {"name": "golang.org/x/crypto"}, "ecosystem_specific": {"imports": [{"path": "golang.org/x/crypto/openpgp"}]}}]}},
            {"finding": {"osv": "GO-2026-5932", "trace": [{"module": "golang.org/x/crypto", "version": "v0.57.0"}]}},
        ]
        self.assertEqual(decode_stream("\n".join(json.dumps(m) for m in messages).encode()), messages)
        self.assertTrue(package_absent(messages, "GO-2026-5932", "golang.org/x/crypto"))
        self.assertFalse(package_absent(messages, "GO-NEW-UNREVIEWED", "golang.org/x/crypto"))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "veyport"
            binary.write_bytes(b"exact synthetic binary")
            evidence = {"binary": "veyport", "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "messages": messages}
            (root / "veyport.go.json").write_text(json.dumps(evidence))
            report = {"descriptor": {"name": "grype"}, "source": {}, "matches": [{"artifact": {"name": "golang.org/x/crypto", "type": "go-module", "locations": [{"path": "/app/veyport"}]}, "vulnerability": {"id": "GO-2026-5932", "severity": "Unknown"}}]}
            path = root / "grype.json"
            path.write_text(json.dumps(report))
            mapping = {"/app/veyport": ["veyport", str(binary)]}
            assessment = root / "assessment.json"
            check(path, "grype", root, mapping, assessment)
            self.assertEqual(json.loads(assessment.read_text())["finding_count"], 1)
            binary.write_bytes(b"changed after scan")
            with self.assertRaises(ValueError):
                check(path, "grype", root, mapping, assessment)
            binary.write_bytes(b"exact synthetic binary")
            messages[-1]["finding"]["trace"][0]["package"] = "golang.org/x/crypto/openpgp"
            evidence["messages"] = messages
            (root / "veyport.go.json").write_text(json.dumps(evidence))
            with self.assertRaises(ValueError):
                check(path, "grype", root, mapping, assessment)
        messages[0]["config"]["scan_level"] = "module"
        with self.assertRaises(ValueError):
            decode_stream("\n".join(json.dumps(m) for m in messages).encode())

    def test_manifest_binds_every_expected_binary_and_only_public_files(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            for name in BINARIES:
                (directory / name).write_bytes(name.encode())
            (directory / "private-operator-config").write_text("synthetic-canary")
            data = manifest(directory, "2.0.50-prototype.1", "a" * 40)
            self.assertEqual({r["path"] for r in data["binaries"]}, set(BINARIES))
            self.assertNotIn("synthetic-canary", (directory / "artifact-manifest.json").read_text())
            self.assertIn(hashlib.sha256(b"veyport").hexdigest() + "  veyport\n", (directory / "SHA256SUMS").read_text())
            (directory / "veyport").unlink()
            (directory / "veyport").symlink_to(directory / "private-operator-config")
            with self.assertRaises(ValueError):
                manifest(directory, "2.0.50-prototype.1", "a" * 40)
            (directory / "veyport").unlink()
            (directory / "veyport").write_bytes(b"restored synthetic hub")
            with (directory / "vey-linux-amd64").open("wb") as oversized:
                oversized.truncate((15 << 20) + 1)
            with self.assertRaisesRegex(ValueError, "15 MiB"):
                manifest(directory, "2.0.50-prototype.1", "a" * 40)

    @unittest.skipUnless(platform.system() == "Linux" and platform.machine() in ("x86_64", "aarch64", "arm64"), "native Linux version smoke")
    def test_native_version_smoke_rejects_wrong_and_extra_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in BINARIES:
                value = "vey 2.0.50-prototype.1" if name.startswith("vey-linux-") else "2.0.50-prototype.1"
                path = root / name
                path.write_text("#!/bin/sh\nprintf '%s\\n' '" + value + "'\n")
                path.chmod(0o700)
            manifest(root, "2.0.50-prototype.1", "a" * 40, True)
            (root / "veyport").write_text("#!/bin/sh\necho wrong-version\n")
            with self.assertRaises(ValueError):
                manifest(root, "2.0.50-prototype.1", "a" * 40, True)
            (root / "veyport").write_text("#!/bin/sh\necho 2.0.50-prototype.1\necho startup-diagnostic >&2\n")
            with self.assertRaises(ValueError):
                manifest(root, "2.0.50-prototype.1", "a" * 40, True)

    def test_incomplete_or_unknown_severity_scan_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "scan.json"
            for report in ({}, {"matches": []}, {"matches": [{"vulnerability": {"severity": "Unknown"}}], "descriptor": {"name": "grype"}, "source": {}}):
                path.write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    check(path, "grype")
            path.write_text(json.dumps({"matches": [], "descriptor": {"name": "grype"}, "source": {}}))
            check(path, "grype")
            run = {"results": [], "tool": {"driver": {"name": "Semgrep"}}, "invocations": [{"executionSuccessful": False}]}
            path.write_text(json.dumps({"runs": [run]}))
            with self.assertRaises(ValueError):
                check(path, "semgrep")
            run["invocations"][0]["executionSuccessful"] = True
            path.write_text(json.dumps({"runs": [run]}))
            check(path, "semgrep")
            run["invocations"][0]["toolExecutionNotifications"] = [{"level": "warning", "descriptor": {"id": "Syntax error"}}]
            path.write_text(json.dumps({"runs": [run]}))
            with self.assertRaises(ValueError):
                check(path, "semgrep")
            del run["invocations"][0]["toolExecutionNotifications"]
            run["results"] = [{"message": {"text": "synthetic finding"}}]
            path.write_text(json.dumps({"runs": [run]}))
            with self.assertRaises(ValueError):
                check(path, "semgrep")

    def test_only_bounded_individually_reviewed_source_annotations_pass(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sarif.json"
            rule, source = next(iter(REVIEWED_ANNOTATIONS))
            finding = {"ruleId": rule, "locations": [{"physicalLocation": {"artifactLocation": {"uri": source}}}], "suppressions": [{"kind": "inSource"}]}
            run = {"results": [finding], "tool": {"driver": {"name": "Semgrep"}}, "invocations": [{"executionSuccessful": True}]}
            path.write_text(json.dumps({"runs": [run]}))
            check(path, "semgrep")
            run["results"].append(finding)
            path.write_text(json.dumps({"runs": [run]}))
            with self.assertRaises(ValueError):
                check(path, "semgrep")
            run["results"] = [finding]
            finding["ruleId"] = "unreviewed-actual-rule"
            path.write_text(json.dumps({"runs": [run]}))
            with self.assertRaises(ValueError):
                check(path, "semgrep")


if __name__ == "__main__":
    unittest.main()
