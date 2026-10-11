import json
from pathlib import Path
import re
import tempfile
import unittest

import server_test_shards as shards


class ServerShardTests(unittest.TestCase):
    def test_partition_keeps_every_test_example_and_fuzz_seed_once(self):
        names = [f"TestCase{i}" for i in range(100)] + ["Example", "ExampleServer", "FuzzHeader"]
        groups = shards.partition(names, 6)
        self.assertEqual(groups, shards.partition(list(reversed(names)), 6))
        self.assertEqual(sorted(names), sorted(name for group in groups for name in group))
        for index, group in enumerate(groups):
            expression = re.compile(shards.run_expression(group))
            for name in names:
                self.assertEqual(name in group, expression.fullmatch(name) is not None)
            self.assertIsNone(expression.fullmatch(group[0] + "Extra"))
        with self.assertRaises(ValueError):
            shards.partition(names + [names[0]], 6)

    def test_execution_evidence_requires_each_selected_parent_once(self):
        events = [
            {"Package": shards.PACKAGE, "Action": "pass", "Test": "TestOne/subtest"},
            {"Package": shards.PACKAGE, "Action": "pass", "Test": "TestOne"},
            {"Package": shards.PACKAGE, "Action": "skip", "Test": "ExampleServer"},
            {"Package": shards.PACKAGE, "Action": "pass"},
        ]
        encode = lambda values: "\n".join(json.dumps(event) for event in values)
        expected = ["TestOne", "ExampleServer"]
        self.assertEqual(shards.completed_tests(encode(events), expected), {"TestOne": "pass", "ExampleServer": "skip"})
        for broken in [events[:-1], events[1:2] + events[-1:], events + [events[1]], events + [{"Package": shards.PACKAGE, "Action": "pass", "Test": "TestUnselected"}], events + [{"Package": shards.PACKAGE, "Action": "fail", "Test": "TestOne"}]]:
            with self.subTest(events=broken), self.assertRaises(ValueError):
                shards.completed_tests(encode(broken), expected)

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "hub").mkdir()
        (root / "proto").mkdir()
        (root / "hub" / "server.go").write_text("package server\n")
        inventory = {"schema_version": 1, "package": shards.PACKAGE, "source_sha256": shards.source_digest(root), "shards": shards.partition([f"TestCase{i}" for i in range(30)] + ["ExampleServer"], 3)}
        directory = root / "results"
        for index, names in enumerate(inventory["shards"]):
            folder = directory / f"artifact-{index}"
            folder.mkdir(parents=True)
            shards.atomic_json(folder / "plan.json", inventory)
            log = "\n".join(json.dumps({"Package": shards.PACKAGE, "Action": "pass", "Test": name}) for name in names)
            log += "\n" + json.dumps({"Package": shards.PACKAGE, "Action": "pass"}) + "\n"
            (folder / "go-test.jsonl").write_text(log)
            (folder / "coverage.out").write_text(f"mode: atomic\n{shards.PACKAGE}/server.go:1.1,2.1 2 {index}\n")
            evidence = {"schema_version": 1, "index": index, "plan_sha256": shards.digest(shards.canonical(inventory)), "profile_sha256": shards.digest((folder / "coverage.out").read_bytes()), "log_sha256": shards.digest(log.encode()), "completed": {name: "pass" for name in names}}
            shards.atomic_json(folder / "shard.json", evidence)
        return root, directory, inventory

    def test_merge_requires_all_shards_and_sums_atomic_profiles(self):
        root, directory, inventory = self.fixture()
        additional = root / "other.out"
        additional.write_text(f"mode: atomic\n{shards.PACKAGE}/server.go:1.1,2.1 2 4\n")
        output = root / "merged.out"
        shards.merge(root, directory, output, inventory, [additional])
        self.assertEqual(shards.read_profile(output), {f"{shards.PACKAGE}/server.go:1.1,2.1": (2, 7)})

    def test_merge_refuses_missing_duplicate_stale_and_modified_evidence(self):
        for fault in ("missing", "duplicate", "source", "inventory", "profile", "execution"):
            with self.subTest(fault=fault):
                root, directory, inventory = self.fixture()
                folder = directory / "artifact-0"
                if fault == "missing":
                    (folder / "shard.json").unlink()
                elif fault == "duplicate":
                    path = directory / "artifact-1" / "shard.json"
                    evidence = json.loads(path.read_text())
                    evidence["index"] = 0
                    shards.atomic_json(path, evidence)
                elif fault == "source":
                    (root / "hub" / "server.go").write_text("package different\n")
                elif fault == "inventory":
                    plan = json.loads((folder / "plan.json").read_text())
                    plan["shards"][0].append("TestAddedAfterRun")
                    shards.atomic_json(folder / "plan.json", plan)
                elif fault == "profile":
                    (folder / "coverage.out").write_text("mode: atomic\nforged.go:1.1,2.1 1 99\n")
                else:
                    (folder / "go-test.jsonl").write_text(json.dumps({"Package": shards.PACKAGE, "Action": "pass"}) + "\n")
                with self.assertRaises(ValueError):
                    shards.merge(root, directory, root / "merged.out", inventory)
                self.assertFalse((root / "merged.out").exists())

    def test_profile_rejects_nonatomic_empty_and_incompatible_blocks(self):
        root, _, _ = self.fixture()
        path = root / "invalid.out"
        for raw in ("mode: set\nx.go:1.1,2.1 1 1\n", "mode: atomic\n", "mode: atomic\nx.go:1.1,2.1 1 1\nx.go:1.1,2.1 2 2\n"):
            path.write_text(raw)
            with self.assertRaises(ValueError):
                shards.read_profile(path)


if __name__ == "__main__":
    unittest.main()
