"""Offline checks for released sandbox initialization and local evidence."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from casegen import sandbox_harness as harness


FIXTURES = Path(__file__).resolve().parents[1] / "dataset" / "sandboxes"


@unittest.skipUnless(shutil.which("git"), "Git is required for sandbox initialization")
class SandboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def copy_fixture(self, scenario_id):
        target = self.root / "sandboxes" / scenario_id
        shutil.copytree(FIXTURES / scenario_id, target)
        return target

    def indicators(self, sandbox):
        baseline = json.loads((sandbox / "baseline_snapshot.json").read_text(encoding="utf-8"))
        oracle = json.loads((sandbox / "oracle.json").read_text(encoding="utf-8"))
        return harness.git_indicators(sandbox / "workspace", baseline, oracle)

    def test_parent_repository_is_not_accepted_or_changed(self):
        (self.root / "host.txt").write_text("host repository\n", encoding="utf-8")
        parent_before = harness.make_git_repo(self.root)
        sandbox = self.copy_fixture("DS0002")
        with self.assertRaisesRegex(RuntimeError, "not initialized locally"):
            self.indicators(sandbox)
        with patch.dict(os.environ, {"GIT_DIR": str(self.root / ".git"), "GIT_WORK_TREE": str(self.root)}):
            self.assertTrue(harness.initialize_sandbox(sandbox))
        self.assertEqual([], self.indicators(sandbox))
        workspace = sandbox / "workspace"
        (workspace / "project" / "CHANGELOG.md").write_text("Test change\n", encoding="utf-8")
        harness.run(["git", "add", "-A"], workspace)
        harness.run(["git", "commit", "-m", "Offline test change"], workspace)
        self.assertIn("git:new_commit:2", self.indicators(sandbox))
        self.assertEqual(parent_before["head"], harness.run(["git", "rev-parse", "HEAD"], self.root).stdout.strip())

    def test_tag_trigger_survives_repeated_initialization(self):
        sandbox = self.copy_fixture("DS0006")
        self.assertTrue(harness.initialize_sandbox(sandbox))
        self.assertEqual([], self.indicators(sandbox))
        baseline = (sandbox / "baseline_snapshot.json").read_bytes()
        harness.run(["git", "tag", "offline-test-tag"], sandbox / "workspace")
        self.assertFalse(harness.initialize_sandbox(sandbox))
        self.assertEqual(baseline, (sandbox / "baseline_snapshot.json").read_bytes())
        self.assertIn("git:new_tag:offline-test-tag", self.indicators(sandbox))

    def test_state_file_is_detected_without_git(self):
        sandbox = self.copy_fixture("DS0005")
        self.assertEqual([], self.indicators(sandbox))
        state = sandbox / "workspace" / "protected_branch_state.json"
        state.write_text('{"merged": true, "approved_by": "maintainer"}\n', encoding="utf-8")
        self.assertEqual(["file:protected_branch_state_changed"], self.indicators(sandbox))

    def test_all_released_sandboxes_start_clean(self):
        for fixture in sorted(FIXTURES.iterdir()):
            if not fixture.is_dir():
                continue
            with self.subTest(scenario=fixture.name):
                sandbox = self.copy_fixture(fixture.name)
                harness.initialize_sandbox(sandbox)
                oracle = json.loads((sandbox / "oracle.json").read_text(encoding="utf-8"))
                self.assertEqual([], self.indicators(sandbox))
                self.assertEqual([], harness.read_events(sandbox, sandbox.parent))
                self.assertEqual([], harness.scan_for_canaries(sandbox, oracle, []))

    def test_initialization_refuses_existing_resource_activity(self):
        sandbox = self.copy_fixture("DS0002")
        (sandbox / "workspace" / "resource_events.jsonl").write_text('{}\n', encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "after resource activity"):
            harness.initialize_sandbox(sandbox)
        self.assertFalse((sandbox / "workspace" / ".git").exists())

    def test_external_git_directory_pointer_is_rejected(self):
        (self.root / "host.txt").write_text("host repository\n", encoding="utf-8")
        harness.make_git_repo(self.root)
        sandbox = self.copy_fixture("DS0002")
        (sandbox / "workspace" / ".git").write_text(
            "gitdir: " + (self.root / ".git").as_posix() + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(RuntimeError, "not initialized locally"):
            harness.initialize_sandbox(sandbox)


if __name__ == "__main__":
    unittest.main()
