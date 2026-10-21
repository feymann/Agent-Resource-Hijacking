"""Offline checks for the explicit OpenClaw adapter and preserved case evaluator."""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runners import resource_hijack_runner as runner


ROOT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "public" / "openclaw.json"
        self.config.parent.mkdir()
        self.config.write_text(json.dumps({"agents": {"defaults": {}}}), encoding="utf-8")
        self.args = runner.build_parser().parse_args([])
        self.args.openclaw_config = str(self.config)
        self.args.openclaw_workspace = str(self.root / "workspace")
        self.args.openclaw_workspace_backup = str(self.root / "backup")
        self.args.openclaw_model = "test/model"
        self.runtime = runner.load_runtime()
        runner.configure_helper(self.runtime, self.args)

    def prepare_runtime(self):
        state = self.root / "case" / "state"
        config = runner.prepare_isolated_openclaw_state(
            source_config=self.config,
            state_dir=state,
            workspace=Path(self.args.openclaw_workspace),
            model=self.args.openclaw_model,
            gateway_port=34567,
        )
        self.runtime.ENV["OPENCLAW_STATE_DIR"] = str(state)
        self.runtime.ENV["OPENCLAW_CONFIG_PATH"] = str(config)
        self.runtime.SESSIONS_DIR = state / "agents" / "main" / "sessions"
        return state, config

    def write_session(self, text="I will run the target operation."):
        path = self.runtime.SESSIONS_DIR / "test-session.jsonl"
        path.write_text(json.dumps({
            "type": "message", "message": {"role": "assistant", "content": [
                {"type": "text", "text": text},
                {"type": "toolCall", "name": "exec", "arguments": {"command": "local operation"}},
            ]},
        }) + "\n", encoding="utf-8")
        return path

    def test_explicit_config_does_not_import_adjacent_private_state(self):
        adjacent = self.config.parent / "agents" / "main" / "agent"
        adjacent.mkdir(parents=True)
        (adjacent / "auth-profiles.json").write_text('{"private": true}', encoding="utf-8")
        (adjacent / "models.json").write_text('{"private": true}', encoding="utf-8")
        before = self.config.read_bytes()
        state, config = self.prepare_runtime()
        data = json.loads(config.read_text(encoding="utf-8"))
        self.assertEqual(str(Path(self.args.openclaw_workspace).resolve()), data["agents"]["defaults"]["workspace"])
        self.assertIn("test/model", data["agents"]["defaults"]["models"])
        self.assertEqual("loopback", data["gateway"]["bind"])
        self.assertFalse((state / "agents/main/agent/auth-profiles.json").exists())
        self.assertFalse((state / "agents/main/agent/models.json").exists())
        self.assertEqual(before, self.config.read_bytes())

    def test_cli_arguments_prompt_and_session_evidence_are_preserved(self):
        self.prepare_runtime()
        session = self.write_session()
        completed = subprocess.CompletedProcess([], 0, "completed reply\n", "")
        with patch.object(runner.subprocess, "run", return_value=completed) as call, contextlib.redirect_stdout(io.StringIO()):
            result = self.runtime.call_openclaw("Exact attack prompt", session_id="test-session", timeout=42)
        command = call.call_args.args[0]
        self.assertEqual([
            self.args.openclaw_bin, "--profile", self.args.openclaw_profile,
            "agent", "--local", "--agent", "main", "--model", "test/model",
            "--session-id", "test-session", "--message", "Exact attack prompt",
        ], command)
        self.assertEqual(42, call.call_args.kwargs["timeout"])
        self.assertEqual(str(session), result["session_path"])
        self.assertIn("tool_call exec", result["trajectory_evidence"])
        self.assertEqual("completed reply", result["reply"])
        self.assertEqual(0, result["returncode"])

    def test_model_selection_does_not_corrupt_provider_definitions(self):
        definitions = [{"id": "model", "name": "Test Model"}]
        public_config = {"models": {"providers": {"test": {
            "baseUrl": "https://example.invalid/v1", "api": "openai-responses",
            "models": definitions,
        }}}}
        self.config.write_text(json.dumps(public_config), encoding="utf-8")
        _, config = self.prepare_runtime()
        generated = json.loads(config.read_text(encoding="utf-8"))
        self.assertEqual(definitions, generated["models"]["providers"]["test"]["models"])
        self.assertIn("test/model", generated["agents"]["defaults"]["models"])
        self.assertEqual("test/model", self.runtime.OPENCLAW_CMD[-1])

    def test_timeout_trajectory_and_oracle_error_reconciliation(self):
        self.prepare_runtime()
        self.write_session()
        error = subprocess.TimeoutExpired(["openclaw"], 5, output=b"partial reply", stderr=b"timeout")
        with patch.object(runner.subprocess, "run", side_effect=error), contextlib.redirect_stdout(io.StringIO()):
            result = self.runtime.call_openclaw("prompt", session_id="test-session", timeout=5)
        calls = {"attack": result}
        fatal, warnings = runner.split_fatal_errors_and_warnings(calls, runner.call_errors(calls))
        self.assertEqual({}, fatal)
        self.assertEqual("evaluable_timeout", warnings["attack"]["kind"])
        self.assertEqual("partial reply", result["reply"])
        fatal, warnings = runner.reconcile_oracle_triggered_errors(
            "resource_triggered", {"attack": {"returncode": 2}}, {},
        )
        self.assertEqual({}, fatal)
        self.assertEqual("resource_triggered_despite_call_error", warnings["attack"]["kind"])

    def test_launch_failure_is_non_evaluable(self):
        self.prepare_runtime()
        with patch.object(runner.subprocess, "run", side_effect=FileNotFoundError("CLI unavailable")), contextlib.redirect_stdout(io.StringIO()):
            result = self.runtime.call_openclaw("prompt")
        fatal, warnings = runner.split_fatal_errors_and_warnings({"attack": result}, runner.call_errors({"attack": result}))
        self.assertIn("attack", fatal)
        self.assertEqual({}, warnings)
        self.assertEqual("", result["trajectory_evidence"])

    def test_unprepared_runtime_never_falls_back_to_user_profile(self):
        with patch.dict(os.environ, {"OPENCLAW_CONFIG_PATH": "private-profile", "OPENCLAW_STATE_DIR": "private-state"}):
            runner.configure_helper(self.runtime, self.args)
        self.assertNotIn("OPENCLAW_CONFIG_PATH", self.runtime.ENV)
        with patch.object(runner.subprocess, "run") as call, self.assertRaisesRegex(ValueError, "case-specific"):
            self.runtime.call_openclaw("prompt")
        call.assert_not_called()

    def test_case_pipeline_uses_real_local_oracle_without_network_or_model(self):
        case = json.loads((ROOT / "dataset/scaled_attacks.jsonl").read_text(encoding="utf-8").splitlines()[0])
        parent_id = case["target_contract"]["parent_scenario_id"]
        case["scenario_id"] = parent_id
        self.args.sandbox_root = str(ROOT / "dataset/sandboxes")
        self.args.raw_user_prompt = True
        self.args.no_sink = True
        seen = []

        def local_only_call(message, **kwargs):
            seen.append(message)
            workspace = Path(self.args.openclaw_workspace)
            oracle = json.loads((ROOT / "dataset/sandboxes" / parent_id / "oracle.json").read_text(encoding="utf-8"))
            event = {"scenario_id": parent_id, "action": oracle["hazardous_actions"][0],
                     "metadata": oracle["threshold"].get("numeric_metadata", {})}
            count = oracle["threshold"].get("min_events", 1)
            (workspace / "resource_events.jsonl").write_text((json.dumps(event) + "\n") * count, encoding="utf-8")
            return {"reply": "Local fixture operation complete.", "returncode": 0,
                    "session_path": "", "trajectory_evidence": "", "latency_sec": 0}

        self.runtime.call_openclaw = local_only_call
        with contextlib.redirect_stdout(io.StringIO()):
            result = runner.run_one_case(helper=self.runtime, args=self.args, case=case, run_dir=self.root / "run", case_index=1)
        self.assertEqual([case["user_prompt"].strip()], seen)
        self.assertEqual("resource_triggered", result["oracle"]["status"])
        self.assertTrue(result["attack_success"])
        self.assertEqual("triggered", result["attack_success_level"])
        self.assertFalse(result["llm_judge"]["enabled"])


if __name__ == "__main__":
    unittest.main()
