"""Offline checks for the cross-harness transport and state boundary."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("codex_adapter_under_test",
    ROOT / "runners" / "codex_harness" / "resource_hijack_runner_codex.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class CodexAdapterTests(unittest.TestCase):
    def test_requires_explicit_environment_credential(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(Path, "read_text", side_effect=AssertionError("Private files must not be read")):
            self.assertEqual(runner.resolve_codex_api_key(), "")

    def test_public_config_and_run_local_home(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"OPENAI_API_KEY": "example-test-only", "CODEX_HOME": "personal-state-must-not-be-used"}):
            args = argparse.Namespace(codex_config=str(ROOT / "configs" / "codex.toml"), openai_base_url="https://endpoint.example.invalid/v1")
            env = runner.prepare_codex_environment(Path(temp), args)
            self.assertEqual(Path(env["CODEX_HOME"]), Path(temp) / "codex_home")
            config = (Path(env["CODEX_HOME"]) / "config.toml").read_text(encoding="utf-8")
            self.assertIn(args.openai_base_url, config)
            self.assertNotIn("example-test-only", config)
            self.assertFalse((Path(env["CODEX_HOME"]) / "auth.json").exists())

    def test_event_evidence_keeps_tool_and_final_reply(self):
        events = [
            {"type": "thread.started", "thread_id": "test-thread"},
            {"type": "item.started", "item": {"type": "command_execution", "command": "python scripts/example.py"}},
            {"type": "item.completed", "item": {"type": "command_execution", "command": "python scripts/example.py", "aggregated_output": "operation recorded"}},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "Finished."}},
            {"type": "turn.completed", "usage": {"input_tokens": 12}},
        ]
        evidence, reply, meta = runner.compact_codex_events("\n".join(json.dumps(e) for e in events))
        self.assertIn("python scripts/example.py", evidence)
        self.assertEqual(reply, "Finished.")
        self.assertEqual(meta["usage"]["input_tokens"], 12)


if __name__ == "__main__":
    unittest.main()
