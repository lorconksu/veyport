import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import provision as lab


class ProvisionGuards(unittest.TestCase):
    def test_existing_vmid_or_name_stops_before_any_other_remote_operation(self):
        for resource in ({"vmid": 126}, {"vmid": 999, "name": "veyport-app-node-lab"}):
            with self.subTest(resource=resource), patch.object(lab, "api", return_value=[resource]) as api, patch.object(lab, "remote") as remote:
                with self.assertRaises(RuntimeError):
                    lab.plan()
                api.assert_called_once_with("GET", "/cluster/resources")
                remote.assert_not_called()

    def test_orphan_volume_and_running_guest_ip_each_reject_all_mutations(self):
        cases = ("volume", "guest_ip")
        for case in cases:
            calls = []
            def api(method, path, **_):
                calls.append((method, path))
                if path == "/cluster/resources":
                    return [{"vmid": 999, "node": "proxmox1", "type": "qemu", "status": "running"}]
                if path == "/nodes":
                    return [{"node": "proxmox1"}]
                if path.endswith("/storage"):
                    return [{"enabled": True, "active": True, "storage": "vm-storage", "content": "images"}]
                if path.endswith("/content"):
                    return [{"vmid": 127}] if case == "volume" else []
                if path.endswith("/agent/network-get-interfaces"):
                    return {"result": [{"ip-addresses": [{"ip-address": "10.10.1.66"}]}]}
                raise AssertionError("Unexpected API operation")
            with self.subTest(case=case), patch.object(lab, "api", side_effect=api), patch.object(lab, "remote") as remote:
                with self.assertRaises(RuntimeError):
                    lab.plan()
                self.assertTrue(all(method == "GET" for method, _ in calls))
                remote.assert_not_called()

    def test_reviewed_plan_mismatch_cannot_create_journal_or_remote_records(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "state.json"
            with patch.object(lab, "STATE", state), patch.object(lab, "api") as api, patch.object(lab, "netbox") as netbox:
                with self.assertRaises(RuntimeError):
                    lab.apply({"candidates": lab.CANDIDATES}, "0" * 64)
                self.assertFalse(state.exists())
                api.assert_not_called()
                netbox.assert_not_called()

    def test_start_warning_acceptance_requires_exact_advisory_and_running_vm(self):
        task = "UPID:proxmox1:1:2:3:qmstart:127:fixture:"
        for expected_log, running, accepted in (
            (lab.EFI_ADVISORY, True, True),
            (lab.EFI_ADVISORY + ["unexpected warning"], True, False),
            (lab.EFI_ADVISORY, False, False),
        ):
            def api(method, path, **_):
                self.assertEqual(method, "GET")
                if path.endswith("/log"):
                    return [{"t": line.replace("VMID", "127")} for line in expected_log]
                if path.endswith("/status/current"):
                    return {"status": "running" if running else "stopped"}
                return {"status": "stopped", "exitstatus": "WARNINGS: 1"}
            with self.subTest(running=running, accepted=accepted), patch.object(lab, "api", side_effect=api):
                if accepted:
                    self.assertTrue(lab.wait(task, start_vmid=127)["running_independently_verified"])
                else:
                    with self.assertRaises(RuntimeError):
                        lab.wait(task, start_vmid=127)
        with patch.object(lab, "api", return_value={"status": "stopped", "exitstatus": "WARNINGS: 1"}):
            with self.assertRaises(RuntimeError):
                lab.wait(task)  # Clone warnings cannot enter the start-only exception.


if __name__ == "__main__":
    unittest.main()
