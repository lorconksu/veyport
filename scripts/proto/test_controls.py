"""Behavioral fixtures using the real pinned compiler/plugins and Buf binary."""

from pathlib import Path
import io
import subprocess
import tempfile
from unittest.mock import patch

import check
from check import breaking, generate, generated_check
from tools import download


SCHEMA = '''syntax = "proto3";
package controls.v1;
option go_package = "example.com/controls/v1";
message Example { string value = 1; }
'''


def exercise_controls(tools):
    with tempfile.TemporaryDirectory(prefix="veyport-proto-controls-") as directory:
        root = Path(directory)
        schema = root / "proto/controls/v1/example.proto"
        schema.parent.mkdir(parents=True)
        schema.write_text(SCHEMA)
        baseline = root / "baseline"
        (baseline / "controls/v1").mkdir(parents=True)
        (baseline / "controls/v1/example.proto").write_text(SCHEMA)
        generate(tools, root, root)
        generated_check(tools, root)
        generated = schema.with_suffix(".pb.go")
        generated.write_bytes(generated.read_bytes() + b"// unintended edit\n")
        try:
            generated_check(tools, root)
        except ValueError as error:
            if "generated protobuf drift" not in str(error):
                raise
        else:
            raise AssertionError("generated drift unexpectedly passed")
        for label, changed in (
            ("deleted field", SCHEMA.replace("string value = 1;", "")),
            ("renumbered field", SCHEMA.replace("value = 1", "value = 2")),
        ):
            schema.write_text(changed)
            try:
                breaking(tools, root / "proto", baseline, capture=True)
            except subprocess.CalledProcessError as error:
                if error.returncode != 100 or b'Previously present field "1"' not in error.output:
                    raise
                print(f"Control fixture rejected {label}", flush=True)
            else:
                raise AssertionError(f"{label} unexpectedly passed")
        schema.write_text(SCHEMA.replace("string value = 1;", "string value = 1; string extra = 2;"))
        breaking(tools, root / "proto", baseline)
        print("Control fixtures passed: generated drift rejected, deleted/renumbered fields rejected, additive field accepted", flush=True)
    exercise_baseline()
    with tempfile.TemporaryDirectory(prefix="veyport-proto-download-") as directory:
        destination = Path(directory) / "untrusted"
        with patch("urllib.request.urlopen", return_value=io.BytesIO(b"corrupt download")):
            try:
                download("https://example.invalid/tool", "0" * 64, destination)
            except ValueError as error:
                assert "SHA256 mismatch" in str(error)
            else:
                raise AssertionError("corrupt tool download unexpectedly accepted")
        assert not destination.exists(), "corrupt tool was written before verification"
        print("Download fixture passed: corrupt tool bytes rejected before writing", flush=True)


def exercise_baseline():
    """Use a real shallow checkout to verify exact-base fetching and blob isolation."""
    with tempfile.TemporaryDirectory(prefix="veyport-proto-base-") as directory:
        root = Path(directory)
        origin = root / "origin"
        origin.mkdir()

        def git(*arguments, cwd=origin):
            return subprocess.check_output(["git", *arguments], cwd=cwd, stderr=subprocess.STDOUT).decode().strip()

        git("init", "-b", "main")
        git("config", "user.name", "Protobuf controls fixture")
        git("config", "user.email", "fixture@example.invalid")
        (origin / "proto").mkdir()
        (origin / "proto/example.proto").write_text(SCHEMA)
        (origin / "proto/buf.yaml").write_text("malicious baseline config must never be parsed")
        (origin / "proto/generate.sh").write_text("exit 99\n")
        git("add", ".")
        git("commit", "-m", "baseline")
        base = git("rev-parse", "HEAD")
        (origin / "proto/example.proto").write_text(SCHEMA + "// head\n")
        git("commit", "-am", "head")
        (origin / "proto/escape.proto").symlink_to("../../outside.proto")
        git("add", ".")
        git("commit", "-m", "untrusted symlink fixture")
        clone = root / "clone"
        git("clone", "--depth=1", origin.as_uri(), str(clone))
        # Supply only the current trusted config, not the baseline's configuration.
        (clone / "proto/buf.yaml").write_bytes((check.ROOT / "proto/buf.yaml").read_bytes())
        assert git("rev-parse", "--is-shallow-repository", cwd=clone) == "true"
        absent = subprocess.run(["git", "cat-file", "-e", base], cwd=clone, stderr=subprocess.DEVNULL)
        assert absent.returncode != 0, "base unexpectedly present before fetch"
        output = root / "snapshot"
        output.mkdir()
        with patch.object(check, "ROOT", clone):
            assert check.resolve_base(base) == base
            check.snapshot(base, output)
            assert (output / "example.proto").read_text() == SCHEMA
            assert sorted(path.name for path in output.iterdir()) == ["buf.yaml", "example.proto"]
            assert (output / "buf.yaml").read_bytes() == (clone / "proto/buf.yaml").read_bytes()
            for invalid in ("main", "--upload-pack=bad", "0" * 40):
                try:
                    check.resolve_base(invalid)
                except ValueError:
                    pass
                else:
                    raise AssertionError("untrusted comparison ref unexpectedly accepted")
            try:
                check.snapshot(git("rev-parse", "HEAD", cwd=clone), output)
            except ValueError as error:
                assert "regular file" in str(error)
            else:
                raise AssertionError("baseline schema symlink unexpectedly accepted")
        print("Baseline fixtures passed: exact missing SHA fetched in shallow checkout; only schema blobs and current config copied; untrusted refs and symlinks rejected", flush=True)
