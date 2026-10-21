"""Offline checks for preserved LlamaFirewall profiles and dependency handling."""

from __future__ import annotations

import contextlib
import copy
import importlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runners"))
import llamafirewall_release as release
import model_profiles


class LlamaFirewallReleaseTests(unittest.TestCase):
    def test_v5_deadlines_and_limits_are_preserved(self):
        v5 = importlib.import_module("llamafirewall_settings_v5")
        self.assertEqual((50, 360, 5, 380000, 400000, 3600, 4000), (
            v5.SCANNER_TIMEOUT_SECONDS, v5.SCANNER_TOTAL_DEADLINE_SECONDS,
            v5.SCANNER_RETRIES, v5.PLUGIN_REQUEST_TIMEOUT_MS, v5.HOOK_TIMEOUT_MS,
            v5.CASE_TIMEOUT_SECONDS, v5.JUDGE_MAX_OUTPUT_TOKENS))
        profile = release.get_profile("v5", "deepseek")
        self.assertEqual(profile["scanner_deadline"], v5.SCANNER_TOTAL_DEADLINE_SECONDS)
        self.assertEqual(profile["scanner_retries"], v5.SCANNER_RETRIES)
        self.assertEqual(profile["plugin_timeout_ms"], v5.PLUGIN_REQUEST_TIMEOUT_MS)
        self.assertEqual(4000, v5.SCANNER_MAX_OUTPUT_TOKENS)
        self.assertEqual(4194304, v5.SCANNER_MAX_RESPONSE_BYTES)
        self.assertEqual(2, profile["max_parallel_categories"])

    def test_scanner_settings_and_default_agent_are_read_from_configuration(self):
        protocols = copy.deepcopy(release.PROFILES)
        protocols["v5"]["scanner_model"] = "test-scanner-model"
        protocols["v5"]["default_model_profile"] = "gpt55"
        with patch.dict(release.PROFILES, protocols, clear=True):
            settings = runpy.run_path(str(ROOT / "runners" / "llamafirewall_settings_v5.py"))
            self.assertEqual("test-scanner-model", settings["SCANNER_MODEL"])
            self.assertEqual("gpt55", release.get_profile("v5")["model_profile"])
            self.assertEqual("deepseek-v4-pro", release.get_base_model_profile("v5")["judge_model"])

    def test_gpt_profile_keeps_firewall_limits_and_existing_provider_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            config_path = state / "openclaw.json"
            source = {"models": {"providers": {"openai": {
                "api": "openai-responses", "baseUrl": "https://old.invalid/v1",
                "models": [{"id": "gpt-5.5", "maxTokens": 777, "reasoning": True}],
            }}}, "plugins": {"entries": {"resource-hijack-llamafirewall-v5": {"enabled": True}}}}
            def write(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value), encoding="utf-8")
            def prepare(**kwargs):
                write(config_path, source)
                return config_path
            legacy = types.SimpleNamespace(prepare_isolated_openclaw_state=prepare, write_json=write)
            runner = types.SimpleNamespace(model_profiles=model_profiles, legacy=legacy)
            namespace = {"runner": runner}
            with patch.dict(model_profiles.PROFILES, copy.deepcopy(model_profiles.PROFILES), clear=True), \
                 patch.object(model_profiles, "PROFILE_NAMES", model_profiles.PROFILE_NAMES), \
                 patch.dict(os.environ, {"OPENAI_BASE_URL": "https://agent.invalid/v1", "OPENAI_API_KEY": "test-only"}):
                name = release.configure_case_profile(namespace, "v5", "gpt55")
                profile = model_profiles.get_profile(name)
                self.assertEqual((3600, 4000, "deepseek-v4-pro", "responses"), (
                    profile["timeout"], profile["judge_max_output_tokens"], profile["judge_model"], profile["judge_api"]))
                self.assertEqual({0}, set(profile["category_start_delays"].values()))
                legacy.prepare_isolated_openclaw_state(state_dir=state)
                expected = copy.deepcopy(source)
                expected["models"]["providers"]["openai"]["baseUrl"] = "https://agent.invalid/v1"
                self.assertEqual(expected, json.loads(config_path.read_text(encoding="utf-8")))
                auth = json.loads((state / "agents/main/agent/auth-profiles.json").read_text(encoding="utf-8"))
                self.assertEqual({"version": 1, "profiles": {"openai:default": {
                    "type": "api_key", "provider": "openai", "key": "test-only"}}}, auth)
                self.assertEqual("resource-hijack-parent-contract-llamafirewall-gpt55-direct-v5", runner.RUNNER_VERSION)

    def test_profile_keeps_environment_override_precedence(self):
        captured = []
        with patch.object(release, "dependency_report", return_value={"ready": True}), \
             patch.object(release, "configure_case_profile", return_value="llamafirewall-v5-gpt55"), \
             patch.dict(os.environ, {"OPENAI_BASE_URL": "https://profile.invalid/v1", "OPENAI_API_KEY": "test-only"}):
            release.run_entry({}, lambda: captured.extend(sys.argv[1:]) or 0, "case", "v5", [
                "--model-profile", "gpt55", "--openai-base-url", "https://cli.invalid/v1",
                "--openai-api-key", "cli-value",
            ])
        self.assertEqual(["--openai-base-url", "https://profile.invalid/v1", "--openai-api-key", "test-only",
                          "--allow-protocol-deviation"], captured[-5:])

    def test_parent_profile_selection_does_not_replace_defense_protocol(self):
        # Exercise profile inheritance on the shared parent without substituting
        # an implementation for the externally supplied v5 case runner.
        runner = release._load_module(
            ROOT / "runners" / "resource_hijack_runner_parent_contract.py",
            "llamafirewall_parent_profile_test",
        )
        namespace = {"runner": runner}
        with patch.dict(model_profiles.PROFILES, copy.deepcopy(model_profiles.PROFILES), clear=True), \
             patch.object(model_profiles, "PROFILE_NAMES", model_profiles.PROFILE_NAMES):
            name = release.configure_case_profile(namespace, "v5", "deepseek")
            args = runner.build_parser(name).parse_args(["--model-profile", name, "--all"])
            runner.configure_model_profile(args)
            self.assertEqual(3600, args.timeout)
            self.assertEqual(4000, args.llm_judge_max_output_tokens)
            self.assertEqual("resource-hijack-parent-contract-llamafirewall-direct-v5", runner.RUNNER_VERSION)
            self.assertEqual("isolated-openclaw-state-parent-workspace-llamafirewall-v5-direct-scanner", runner.PROTOCOL)

    def test_v5_inspection_does_not_import_a_supplied_component(self):
        with tempfile.TemporaryDirectory() as directory:
            component = Path(directory) / "original_v5.py"
            component.write_text("raise AssertionError('inspection must not execute this')\n", encoding="utf-8")
            output = io.StringIO()
            with patch.dict(os.environ, {}, clear=False), patch.object(release, "_load_module") as load, \
                 contextlib.redirect_stdout(output):
                code = release.launch("case", "v5", "gpt55", ["--plan", "--llamafirewall-v5-runner", str(component)])
                load.assert_not_called()
            self.assertEqual(0, code)
            report = json.loads(output.getvalue())
            self.assertTrue(report["dependencies"]["case_runner"]["present"])
            self.assertEqual("gpt55", report["profile"]["model_profile"])

    def test_missing_components_are_reported_without_importing_or_running(self):
        output = io.StringIO()
        with patch.object(release, "dependency_report", return_value={"ready": False, "missing": ["service", "case_runner"]}), \
             patch.object(release, "_load_module") as load, contextlib.redirect_stdout(output):
            code = release.launch("case", "v5", "gpt55", ["--preflight"])
            load.assert_not_called()
        self.assertEqual(2, code)
        self.assertEqual(["service", "case_runner"], json.loads(output.getvalue())["missing"])

    def test_shared_entry_points_can_show_help_and_plan(self):
        entries = [
            ("resource_hijack_runner_parent_contract_llamafirewall.py", []),
            ("resource_hijack_runner_parent_contract_llamafirewall.py", ["--lf-protocol", "v5", "--model-profile", "gpt55"]),
            ("run_parent_contract_llamafirewall_v5.py", []),
            ("run_parent_contract_llamafirewall_v5.py", ["--model-profile", "gpt55"]),
        ]
        env = {key: value for key, value in os.environ.items() if not key.startswith("RH_LLAMAFIREWALL_")}
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for entry, arguments in entries:
            for flag in ("--help", "--plan"):
                with self.subTest(entry=entry, flag=flag):
                    completed = subprocess.run([sys.executable, "-B", str(ROOT / "runners" / entry), *arguments, flag],
                                               cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
                    self.assertEqual(0, completed.returncode, completed.stderr)
                    if flag == "--plan":
                        report = json.loads(completed.stdout)
                        self.assertIn("missing", report)
                        if arguments:
                            self.assertEqual("gpt55", report["profile"]["model_profile"])
                            self.assertEqual("v5", report["profile"]["version"])

    def test_only_v5_is_available_and_case_dispatch_does_not_load_local_fallback(self):
        self.assertEqual({"v5"}, set(release.PROFILES))
        with self.assertRaisesRegex(ValueError, "Only the LlamaFirewall v5"):
            release.launch("case", "v1", argv=["--plan"])
        output = io.StringIO()
        with patch.object(release, "_load_module") as load, contextlib.redirect_stdout(output):
            entry = importlib.import_module("resource_hijack_runner_parent_contract_llamafirewall")
            with patch.object(sys, "argv", ["case-runner", "--plan"]):
                code = entry.main()
            load.assert_not_called()
        self.assertEqual(0, code)
        self.assertEqual("v5", json.loads(output.getvalue())["profile"]["version"])


if __name__ == "__main__":
    unittest.main()
