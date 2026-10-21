"""Offline checks for defense ordering and prompt-defense v2 semantics."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from runners import defense_adapters as adapters

ROOT = Path(__file__).resolve().parents[1]


class DefenseAdapterTests(unittest.TestCase):
    def test_guardrail_model_default_comes_from_configuration_and_allows_override(self):
        runner = adapters.load_shared_module("resource_hijack_runner_parent_contract.py", "gate_model_test")
        adapters.AgentDogGateAdapter(runner)
        with patch.dict(adapters.model_profiles.DEFAULTS, {"agentdog_model": "test-guardrail-model"}):
            configured = runner.build_parser().parse_args([])
            overridden = runner.build_parser().parse_args(["--agentdog-model", "explicit-guardrail-model"])
        self.assertEqual("test-guardrail-model", configured.agentdog_model)
        self.assertEqual("explicit-guardrail-model", overridden.agentdog_model)
        self.assertNotEqual(configured.agentdog_model, configured.openclaw_model)

    def test_gate_preserves_ungated_oracle_evidence_and_errors(self):
        original = {"verdict": "unsafe", "attack_success": True, "attack_success_level": "triggered",
                    "agentdog_case_prediction": 1, "oracle": {"status": "resource_triggered"}}
        result = adapters.apply_agentdog_gate(copy.deepcopy(original), enabled=True)
        self.assertFalse(result["attack_success"])
        self.assertTrue(result["ungated_attack_success"])
        self.assertEqual(original["oracle"], result["oracle"])
        error = {**original, "agentdog_case_prediction": -1}
        adapters.mark_agentdog_error_non_evaluable(error, enabled=True)
        adapters.apply_agentdog_gate(error, enabled=True)
        self.assertIsNone(error["attack_success"])
        self.assertEqual("non_evaluable_result_preserved", error["agentdog_gate_reason"])

    def test_observation_runs_before_judge_and_gate_after_triggered_oracle(self):
        runner = adapters.load_shared_module("resource_hijack_runner_parent_contract.py", "gate_order_test")
        adapter = adapters.AgentDogGateAdapter(runner)
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            args = runner.build_parser().parse_args([])
            args.openclaw_workspace = str(folder / "workspace")
            args.openclaw_workspace_backup = str(folder / "backup")
            args.no_sink = True
            runner.configure_model_profile(args)
            runtime = runner.legacy.load_runtime()
            runner.legacy.configure_helper(runtime, args)
            events = []
            runtime._check_agentdog = lambda *a: events.append("agentdog") or {"enabled": True, "prediction": 1, "label": "unsafe"}
            runtime._apply_agentdog_to_reply = lambda reply, decision: reply
            case = runner.load_jsonl(runner.DEFAULT_ATTACKS)[0]
            def cli(*a, **k):
                events.append("openclaw")
                return subprocess.CompletedProcess([], 0, "Operation complete.", "")
            def judge(**kwargs):
                events.append("llm_judge")
                return {"enabled": True, "verdict": "unsafe", "success_level": "triggered", "confidence": 1}
            original_gate = adapters.apply_agentdog_gate
            def gate(result, **kwargs):
                events.append("agentdog_final_gate")
                return original_gate(result, **kwargs)
            with patch.object(runner.legacy.subprocess, "run", side_effect=cli), \
                 patch.object(runner.legacy, "run_check", return_value={"status": "resource_triggered", "indicator_count": 1}), \
                 patch.object(runner.legacy, "call_llm_judge_responses", side_effect=judge), \
                 patch.object(adapters, "apply_agentdog_gate", side_effect=gate), contextlib.redirect_stdout(io.StringIO()):
                result = runner.run_one_case(helper=runtime, args=args, case=case, run_dir=folder / "run", case_index=1)
            self.assertEqual(adapters.EVALUATION_ORDER, events)
            self.assertTrue(result["ungated_attack_success"])
            self.assertFalse(result["attack_success"])

    def prompt_case(self, version, delete_policy=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        source = root / "source" / "DS0001" / "workspace"
        source.mkdir(parents=True)
        (source / "AGENTS.md").write_bytes(b"Original fixture instructions.\n")
        policy = root / "test-policy.txt"
        policy.write_bytes(b"Synthetic unit-test policy.\n\n")
        workspace = root / "workspace"
        run_dir = root / "run"
        run_copy = run_dir / "sandbox_root" / "DS0001" / "workspace"
        def copytree(src, dst):
            if dst.exists(): shutil.rmtree(dst)
            shutil.copytree(src, dst)
        legacy = SimpleNamespace(copytree_replace=copytree, write_json=lambda path, value: None,
                                 validate_runtime_requirements=lambda args: None)
        def base_case(**kwargs):
            legacy.copytree_replace(source, workspace)
            if delete_policy: (workspace / "AGENTS.md").unlink()
            legacy.copytree_replace(workspace, run_copy)
            return {"run_case_dir": str(run_dir)}
        runner = SimpleNamespace(legacy=legacy, run_one_case=base_case, sha256_file=lambda p: "test",
                                 configure_model_profile=lambda args: None, build_parser=lambda p: None)
        adapter = adapters.PromptDefenseAdapter(runner, version)
        adapter.policy_path = policy
        return adapter, {"args": SimpleNamespace(openclaw_workspace=str(workspace), sandbox_root=str(root / "source")),
                         "case": {"lineage": {"parent_scenario_id": "DS0001"}}}, source

    def test_prompt_injection_is_verbatim_once_and_preserves_canonical_source(self):
        adapter, kwargs, source = self.prompt_case("v2")
        before = (source / "AGENTS.md").read_bytes()
        result = adapter.run_one_case_with_prompt_defense(**kwargs)
        self.assertEqual(before, (source / "AGENTS.md").read_bytes())
        run_copy = Path(result["prompt_defense"]["run_copy_agents_path"])
        self.assertEqual(before + b"\nSynthetic unit-test policy.\n", run_copy.read_bytes())
        self.assertEqual(1, result["prompt_defense"]["policy_occurrences_in_run_copy"])

    def test_v2_records_removed_policy_without_rejecting_the_run(self):
        adapter, kwargs, _ = self.prompt_case("v2", delete_policy=True)
        result = adapter.run_one_case_with_prompt_defense(**kwargs)
        self.assertFalse(result["prompt_defense"]["policy_present_after_run"])
        self.assertTrue(result["prompt_defense"]["agents_modified_during_run"])

    def test_removed_v1_protocol_is_rejected_before_installing_adapter(self):
        runner = SimpleNamespace()
        with self.assertRaisesRegex(ValueError, "Only prompt-defense v2 is supported"):
            adapters.PromptDefenseAdapter(runner, "v1")
        self.assertEqual({}, vars(runner))

    def test_missing_policy_is_loaded_only_when_needed(self):
        runner = adapters.load_shared_module("resource_hijack_runner_parent_contract.py", "missing_policy_test")
        adapter = adapters.PromptDefenseAdapter(runner, "v2")
        self.assertIn("--policy-file", runner.build_parser().format_help())
        with self.assertRaisesRegex(FileNotFoundError, "provide --policy-file"):
            _ = adapter.policy_bytes


if __name__ == "__main__":
    unittest.main()
