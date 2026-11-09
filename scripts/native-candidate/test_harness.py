import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("native_harness", Path(__file__).with_name("run.py"))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


class NativeGateTests(unittest.TestCase):
    def test_bad_output_path_is_rejected_before_any_candidate_action(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(harness, "Harness") as constructor:
            with self.assertRaises(ValueError):
                harness.run({}, Path(folder) / "missing" / "report.json")
            constructor.assert_not_called()

    def config(self):
        return {"candidate_id": "test", "revision": "a" * 40, "artifact_manifest_sha256": "b" * 64, "audit_profile": "standard"}

    def cases(self):
        return [{"id": "bootstrap.synthetic-mfa-and-agent-enrollment", "status": "pass"}] + [
            {"id": name, "status": "pass"} for names in harness.REQUIRED.values() for name in sorted(names)]

    def test_complete_standard_case_set_and_outage_proof_are_required(self):
        complete = harness.assess(self.config(), self.cases(), {"identity_verified": True})
        self.assertTrue(complete["candidate_qualified"])
        self.assertTrue(complete["required_audit_admission_exercised"])
        self.assertIs(complete["enhanced_receipt_exercised"], False)
        for name in ["bootstrap.synthetic-mfa-and-agent-enrollment", *harness.REQUIRED["native:grpc"], *harness.REQUIRED["native:ssh"]]:
            cases = [c for c in self.cases() if c["id"] != name]
            self.assertFalse(harness.assess(self.config(), cases, {"identity_verified": True})["candidate_qualified"])

    def test_failed_skipped_or_duplicate_cases_cannot_qualify(self):
        for status in ("fail", "skip"):
            cases = self.cases()
            cases[0]["status"] = status
            if status == "skip":
                with self.assertRaises(ValueError):
                    harness.assess(self.config(), cases, {"identity_verified": True})
            else:
                self.assertFalse(harness.assess(self.config(), cases, {"identity_verified": True})["candidate_qualified"])
        with self.assertRaises(ValueError):
            harness.assess(self.config(), self.cases() + self.cases()[:1], {"identity_verified": True})
        self.assertFalse(harness.assess(self.config(), self.cases(), {})["candidate_qualified"])

    def test_audit_fault_is_removed_after_probe_exception(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "veyport.db"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE audit_logs(action TEXT)")
            subject = harness.Harness({"work_dir": folder, "hub_data_dir": folder})

            def fail_probe(_phase):
                with sqlite3.connect(database) as connection:
                    with self.assertRaises(sqlite3.IntegrityError):
                        connection.execute("INSERT INTO audit_logs VALUES ('execution.dispatched')")
                raise OSError("synthetic probe interruption")

            with patch.object(subject, "identity", return_value={"verified": True}), patch.object(subject, "phase", side_effect=fail_probe), self.assertRaises(OSError):
                subject.audit_fault()
            with sqlite3.connect(database) as connection:
                self.assertFalse(connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall())
                connection.execute("INSERT INTO audit_logs VALUES ('execution.dispatched')")

    def test_audit_fault_never_mutates_database_when_identity_check_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "veyport.db"
            with sqlite3.connect(database) as connection:
                connection.execute("CREATE TABLE audit_logs(action TEXT)")
            subject = harness.Harness({"work_dir": folder, "hub_data_dir": folder})
            with patch.object(subject, "identity", side_effect=ValueError("wrong candidate")), self.assertRaises(ValueError):
                subject.audit_fault()
            with sqlite3.connect(database) as connection:
                self.assertFalse(connection.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall())

    def test_totp_known_synthetic_vector(self):
        self.assertEqual(harness.totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59), "287082")


if __name__ == "__main__":
    unittest.main()
