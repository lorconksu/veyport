"""Local compatibility checks; never import the live lab restoration program.

The operator script intentionally runs remote restoration at module scope. Load
only its existing function definitions and format constant, supplying a synthetic
controller and SSH process. This exercises the real encryption/restore functions
without contacting or changing a lab guest.
"""
import ast
import hashlib
import io
from pathlib import Path
import secrets
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Generated with cryptography 46.0.5, the original VEYPORT-GCM-001 format,
# public synthetic key bytes(range(32)) and nonce bytes(range(12)).
LEGACY = bytes.fromhex(
    "564559504f52542d47434d2d3030310000000102030405060708090a0b"
    "2b67b17aa69ce268f42fe3e3d49d110ea3b4e6579b0e2f7cc76d"
    "7640a16b8fa0845893e71abbccde65af"
)
PAYLOAD = b"legacy synthetic backup\x00\xff\n"


class CaptureInput(io.BytesIO):
    def close(self):
        self.captured = self.getvalue()
        super().close()


class BackupCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.remote = []
        source = ast.parse((Path(__file__).parent / "backup-restore.py").read_text())
        nodes = [node for node in source.body if isinstance(node, ast.FunctionDef) or
                 (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MAGIC" for t in node.targets))]
        self.namespace = dict(Path=Path, hashlib=hashlib, secrets=secrets, subprocess=subprocess,
                              Cipher=Cipher, algorithms=algorithms, modes=modes,
                              key=bytes(range(32)), d=SimpleNamespace(PRIVATE=self.root, SSH=[], remote=lambda *args: self.remote.append(args)))
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "backup-restore.py", "exec"), self.namespace)

    def restore(self, envelope):
        path = self.root / "archive.gcm"
        path.write_bytes(envelope)
        process = SimpleNamespace(stdin=CaptureInput(), wait=lambda: 0)
        with patch.object(subprocess, "Popen", return_value=process) as launch:
            self.namespace["restore"]("synthetic", "test", path)
        self.assertEqual(launch.call_count, 1)
        return process.stdin.captured

    def test_old_format_archive_decrypts_with_new_library(self):
        self.assertEqual(self.restore(LEGACY), PAYLOAD)

    def test_stream_encryption_preserves_format_and_round_trips_binary_chunks(self):
        payload = bytes(range(256)) * 2049
        process = SimpleNamespace(stdout=io.BytesIO(payload), wait=lambda: 0)
        with patch.object(subprocess, "Popen", return_value=process):
            path = self.namespace["encrypt_backup"]("synthetic", "test")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(path.read_bytes().startswith(self.namespace["MAGIC"]))
        self.assertEqual(self.restore(path.read_bytes()), payload)

    def test_tampered_backup_never_starts_extraction(self):
        for location in (-1, len(self.namespace["MAGIC"]) + 12):
            tampered = bytearray(LEGACY)
            tampered[location] ^= 1
            path = self.root / "corrupted.gcm"
            path.write_bytes(tampered)
            with patch.object(subprocess, "Popen") as launch, self.assertRaises(InvalidTag):
                self.namespace["restore"]("synthetic", "test", path)
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
