"""Offline regression tests for provider behavior and worker command construction."""

import copy
import importlib.util
import io
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RUNNERS = ROOT / "runners"
sys.path.insert(0, str(RUNNERS))
import model_profiles


def import_runner(name):
    spec = importlib.util.spec_from_file_location("test_" + name, RUNNERS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModelProfilesTest(unittest.TestCase):
    def test_repeated_main_calls_reset_model_profile(self):
        runner = import_runner("resource_hijack_runner_parent_contract")
        with patch("sys.stdout", new_callable=io.StringIO):
            for name in ("gemini35flash", "gemini35flash", "kimik3", "deepseek"):
                self.assertEqual(runner.main(["--model-profile", name, "--smoke18", "--dry-run"]), 0)
                profile = model_profiles.get_profile(name)
                self.assertEqual(runner.DEFAULT_OPENCLAW_MODEL, profile["openclaw_model"])
                self.assertEqual(runner.RUNNER_VERSION, profile["runner_version"])
                self.assertEqual(runner.PROTOCOL, profile["protocol"])
                args = runner.build_parser(name).parse_args([])
                self.assertEqual(runner.baseline_protocol_diff(args), {})
            self.assertIs(runner.legacy.call_llm_judge_responses, runner.legacy._profile_base_judge)

    def test_orchestrator_defaults_and_cached_runner_do_not_leak_between_invocations(self):
        baseline = import_runner("run_parent_contract_baseline")
        baseline.SOURCE_CONFIG = Path("previous-explicit-config.json")
        self.assertEqual(baseline.build_parser().parse_args([]).openclaw_config, baseline.DEFAULT_SOURCE_CONFIG)
        sharded = import_runner("run_parent_contract_sharded")
        original = sharded.load_runner()
        self.assertEqual(original.DEFAULT_OPENCLAW_MODEL, model_profiles.get_profile(model_profiles.DEFAULT_SHARDED_PROFILE)["openclaw_model"])
        alternate = next(name for name in model_profiles.PROFILE_NAMES if name != sharded.MODEL_PROFILE)
        sharded.MODEL_PROFILE = alternate
        updated = sharded.load_runner()
        self.assertIsNot(original, updated)
        self.assertEqual(updated.DEFAULT_OPENCLAW_MODEL, model_profiles.get_profile(alternate)["openclaw_model"])
        sharded.SOURCE_CONFIG = Path("previous-explicit-config.json")
        sharded.MAX_ERROR_ROUNDS = 99
        sharded.MONITOR_INTERVAL = 99
        sharded.SINK_PORT_BASE = 9999
        args = sharded.build_parser().parse_args(["start", "--root", "unused", "--dry-run"])
        configured = model_profiles.sharding_defaults(model_profiles.DEFAULT_SHARDED_PROFILE)
        self.assertEqual((args.openclaw_config, args.max_error_rounds, args.monitor_interval, args.sink_port_base), (sharded.DEFAULT_SOURCE_CONFIG, configured["max_error_rounds"], configured["monitor_interval"], configured["sink_port_base"]))

    def test_schedulers_accept_configuration_without_historical_model_names(self):
        profile = model_profiles.get_profile(model_profiles.DEFAULT_PROFILE)
        profile.pop("sharding", None)
        profile["category_concurrency"] = 2
        with patch.object(model_profiles, "PROFILES", {"custom": profile}), \
             patch.object(model_profiles, "PROFILE_NAMES", ("custom",)), \
             patch.object(model_profiles, "DEFAULT_PROFILE", "custom"), \
             patch.object(model_profiles, "DEFAULT_SHARDED_PROFILE", "custom"):
            baseline = import_runner("run_parent_contract_baseline")
            self.assertEqual(baseline.build_parser().parse_args([]).model_profile, "custom")
            self.assertEqual(baseline.CATEGORY_CONCURRENCY, 2)
            sharded = import_runner("run_parent_contract_sharded")
            args = sharded.build_parser().parse_args(["start", "--root", "unused", "--dry-run"])
            self.assertEqual(args.model_profile, "custom")
            self.assertEqual(args.max_workers, model_profiles.DEFAULTS["sharding"]["max_workers"])
            shards = sharded.build_shard_plan(Path("unused"), categories=("material",), shard_size=args.shard_size)
            self.assertEqual(shards[0]["command"][shards[0]["command"].index("--model-profile") + 1], "custom")

    def test_selected_sharding_configuration_and_explicit_cli_overrides(self):
        base = model_profiles.get_profile(model_profiles.DEFAULT_PROFILE)
        base.pop("sharding", None)
        customized = copy.deepcopy(base)
        customized["category_concurrency"] = 1
        customized["sharding"] = {"shard_size": 17, "max_workers": 4, "max_error_rounds": 2}
        with patch.object(model_profiles, "PROFILES", {"plain": base, "custom": customized}), \
             patch.object(model_profiles, "PROFILE_NAMES", ("plain", "custom")), \
             patch.object(model_profiles, "DEFAULT_SHARDED_PROFILE", "plain"):
            sharded = import_runner("run_parent_contract_sharded")
            parser = sharded.build_parser()
            args = parser.parse_args(["start", "--root", "unused", "--model-profile", "custom"])
            self.assertEqual((args.shard_size, args.max_workers, args.max_error_rounds), (17, 4, 2))
            self.assertEqual(args.monitor_interval, model_profiles.DEFAULTS["sharding"]["monitor_interval"])
            explicit = parser.parse_args([
                "start", "--root", "unused", "--model-profile", "custom",
                "--shard-size", "9", "--max-workers", "7", "--max-error-rounds", "0",
                "--monitor-interval", "5", "--sink-port-base", "9900",
            ])
            self.assertEqual((explicit.shard_size, explicit.max_workers, explicit.max_error_rounds,
                              explicit.monitor_interval, explicit.sink_port_base), (9, 7, 0, 5, 9900))
            plain = parser.parse_args(["start", "--root", "unused", "--model-profile", "plain"])
            self.assertEqual(plain.max_workers, model_profiles.DEFAULTS["sharding"]["max_workers"])
            self.assertNotIn("sharding", base)

    def test_sharded_resume_uses_saved_topology_and_model(self):
        sharded = import_runner("run_parent_contract_sharded")
        profile_name = model_profiles.DEFAULT_PROFILE
        saved = {
            "orchestrator_version": sharded.MANIFEST_VERSION,
            "model_profile": profile_name,
            "source_openclaw_config": "saved-openclaw.json",
            "categories": ["material"],
            "max_error_rounds": 1,
            "monitor_interval": 7,
            "execution_topology": {"shard_size": 17, "max_workers": 4, "sink_port_base": 9850},
            **{key: "same" for key in ("dataset_sha256", "runner_sha256", "source_openclaw_config_sha256",
                                        "model_profiles_sha256", "model_adapter_sha256")},
        }
        with patch.object(Path, "exists", return_value=True), \
             patch.object(sharded, "load_json", return_value=saved), \
             patch.object(sharded, "sha256_file", return_value="same"), \
             patch.object(sharded, "run_error_rounds") as rerun, \
             patch.object(sharded, "finish", return_value=0):
            self.assertEqual(sharded.cmd_resume(types.SimpleNamespace(root=Path("unused"))), 0)
        kwargs = rerun.call_args.kwargs
        self.assertEqual((kwargs["max_workers"], kwargs["max_rounds"], kwargs["expected_rows"]), (4, 1, 150))
        self.assertEqual((sharded.MODEL_PROFILE, sharded.MONITOR_INTERVAL), (profile_name, 7))
        shards = kwargs["shards"]
        self.assertEqual(len(shards), 9)
        self.assertEqual((shards[0]["attack_count"], shards[-1]["attack_count"]), (17, 14))
        self.assertEqual([row["sink_port"] for row in shards], list(range(9850, 9859)))
        command = shards[0]["command"]
        self.assertEqual(command[command.index("--model-profile") + 1], profile_name)
        self.assertEqual(command[command.index("--openclaw-config") + 1], "saved-openclaw.json")

    def test_glm_compat_replaces_only_same_model(self):
        source = {"models": {"providers": {"openai": {"models": [
            {"id": "retained"}, {"id": "glm-5.2", "stale": True}, "extension"
        ]}}}}
        result = model_profiles.apply_model_config(source, "glm52", base_url="test", api_key="test")
        models = result["models"]["providers"]["openai"]["models"]
        self.assertEqual(models[:2], [{"id": "retained"}, "extension"])
        self.assertEqual(models[-1]["compat"], {"thinkingFormat": "qwen"})
        self.assertFalse(models[-1]["reasoning"])
        self.assertEqual((models[-1]["contextWindow"], models[-1]["maxTokens"]), (202752, 16384))
        with self.assertRaises(TypeError):
            model_profiles.apply_model_config(
                {"models": {"providers": {"openai": {"models": {}}}}},
                "glm52", base_url="test", api_key="test",
            )

    def test_kimi_and_gemini_transport_and_registration(self):
        for name, provider_name, api, model_id, context, tokens in [
            ("kimik3", "kimi", "anthropic-messages", "kimi-k3", 262144, 32768),
            ("gemini35flash", "relay", "openai-responses", "gemini-3.5-flash", 1048576, 65536),
        ]:
            config = model_profiles.apply_model_config({}, name, base_url="https://example.test/v1", api_key="test-key")
            provider = config["models"]["providers"][provider_name]
            self.assertEqual(provider["api"], api)
            self.assertEqual(provider["apiKey"], "test-key")
            self.assertEqual(provider["baseUrl"], "https://example.test/v1")
            model = provider["models"][0]
            self.assertEqual((model["id"], model["api"], model["contextWindow"], model["maxTokens"]), (model_id, api, context, tokens))
            self.assertIn(provider_name + "/" + model_id, config["agents"]["defaults"]["models"])
            if name == "kimik3":
                self.assertEqual(provider["headers"], {"User-Agent": "claude-code/0.1.0"})
                self.assertTrue(model["reasoning"])
            else:
                self.assertNotIn("reasoning", model)
        original = copy.deepcopy(model_profiles.PROFILES)
        config["models"]["providers"]["relay"]["models"][0]["maxTokens"] = 1
        self.assertEqual(model_profiles.PROFILES, original)

    def test_gpt_endpoint_and_auth_override_and_profile_reset(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            config_path = state / "openclaw.json"
            def write_json(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(value))
            def prepare(**kwargs):
                write_json(config_path, {"models": {"providers": {"openai": {"baseUrl": "old"}}}})
                return config_path
            original_judge = lambda **kwargs: {"api": "responses"}
            legacy = types.SimpleNamespace(prepare_isolated_openclaw_state=prepare, call_llm_judge_responses=original_judge, write_json=write_json)
            args = types.SimpleNamespace(openai_base_url="https://example.test/v1", openai_api_key="explicit-test-key", openclaw_agent="main")
            model_profiles.configure_runtime(legacy, "gpt55", args)
            legacy.prepare_isolated_openclaw_state(state_dir=state)
            self.assertEqual(json.loads(config_path.read_text())["models"]["providers"]["openai"]["baseUrl"], args.openai_base_url)
            auth = json.loads((state / "agents/main/agent/auth-profiles.json").read_text())
            self.assertEqual(auth["profiles"]["openai:default"], {"type": "api_key", "provider": "openai", "key": args.openai_api_key})
            model_profiles.configure_runtime(legacy, "gemini35flash", args)
            self.assertIsNot(legacy.call_llm_judge_responses, original_judge)
            model_profiles.configure_runtime(legacy, "deepseek", args)
            self.assertIs(legacy.call_llm_judge_responses, original_judge)

    def test_delays_and_cli_profile_defaults(self):
        runner = import_runner("resource_hijack_runner_parent_contract")
        categories = ["material", "condition", "energy", "symbolic", "knowledge", "interaction"]
        for name in model_profiles.PROFILE_NAMES:
            defaults = runner.build_parser(name).parse_args([])
            self.assertEqual(defaults.timeout, 300)
            self.assertEqual(defaults.llm_judge_timeout, 60)
            self.assertEqual(defaults.llm_judge_retries, 2)
            self.assertEqual(defaults.llm_judge_max_output_tokens, 2400 if name == "gemini35flash" else 800)
            self.assertEqual([model_profiles.category_start_delay(name, cat) for cat in categories], [0] * 6 if name == "deepseek" else [0, 5, 10, 15, 20, 25])
            args = runner.build_parser(name).parse_args(["--openclaw-model", "custom/model", "--timeout", "9"])
            self.assertEqual((args.openclaw_model, args.timeout), ("custom/model", 9))
        self.assertEqual(model_profiles.selected_profile(["--model-profile=kimik3", "--all"]), "kimik3")

    def test_gemini_judge_request_retry_and_timeout(self):
        calls = []
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self):
                return json.dumps({"choices": [{"message": {"content": '{"verdict":"safe"}'}}]}).encode()
        def request(req, timeout):
            calls.append((req, timeout))
            if len(calls) < 3:
                raise TimeoutError("test timeout")
            return Response()
        legacy = types.SimpleNamespace(
            build_llm_judge_instructions=lambda: "test instructions",
            build_llm_judge_input=lambda **kwargs: json.dumps(kwargs, sort_keys=True),
            extract_first_json_object=json.loads, normalize_llm_judge=lambda value: value,
            truncate_text=lambda value, limit: value[:limit], LLM_JUDGE_PROMPT_VERSION="v6",
        )
        args = types.SimpleNamespace(llm_judge=True, llm_judge_base_url="https://example.test/v1/", llm_judge_api_key="test-key", llm_judge_model="deepseek-v4-pro", llm_judge_max_output_tokens=2400, llm_judge_timeout=60, llm_judge_retries=2)
        with patch.object(model_profiles.urllib.request, "urlopen", side_effect=request), patch.object(model_profiles.time, "sleep") as sleep:
            result = model_profiles.call_llm_judge_chat_completions(legacy=legacy, args=args, case={"id": "test"}, prompt="p", reply="r", oracle={}, rule_verdict="safe", rule_detail="d", trajectory_evidence="trajectory", evaluation_note="note")
        self.assertEqual((result["status"], result["attempts"], result["api"]), ("ok", 3, "chat-completions"))
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 2])
        req, timeout = calls[0]
        body = json.loads(req.data)
        self.assertEqual(req.full_url, "https://example.test/v1/chat/completions")
        self.assertEqual(timeout, 60)
        self.assertEqual(req.get_header("Authorization"), "Bearer test-key")
        self.assertEqual((body["model"], body["temperature"], body["max_tokens"]), ("deepseek-v4-pro", 0, 2400))
        self.assertEqual(body["response_format"], {"type": "json_object"})
        self.assertEqual([row["role"] for row in body["messages"]], ["system", "user"])
        self.assertEqual(json.loads(body["messages"][1]["content"])["trajectory_evidence"], "trajectory")

    def test_gemini_judge_environment_override_and_original_fallback(self):
        environment = {"OPENAI_BASE_URL": "https://agent.example.test/v1", "OPENAI_API_KEY": "agent-test"}
        with patch.dict(model_profiles.os.environ, environment, clear=True):
            defaults = model_profiles.parser_defaults("gemini35flash")
            self.assertEqual((defaults["llm_judge_base_url"], defaults["llm_judge_api_key"]), (environment["OPENAI_BASE_URL"], environment["OPENAI_API_KEY"]))
        environment.update(JUDGE_BASE_URL="https://judge.example.test/v1", JUDGE_API_KEY="judge-test")
        with patch.dict(model_profiles.os.environ, environment, clear=True):
            defaults = model_profiles.parser_defaults("gemini35flash")
            self.assertEqual((defaults["llm_judge_base_url"], defaults["llm_judge_api_key"]), (environment["JUDGE_BASE_URL"], environment["JUDGE_API_KEY"]))

    def test_kimi_sequential_categories_and_worker_arguments(self):
        baseline = import_runner("run_parent_contract_baseline")
        baseline.MODEL_PROFILE = "kimik3"
        baseline.CATEGORY_CONCURRENCY = 1
        calls = []
        def batch(**kwargs):
            calls.append(tuple(kwargs["categories"]))
            return {category: 0 for category in kwargs["categories"]}
        with patch.object(baseline, "_run_wave_batch", side_effect=batch):
            result = baseline.run_wave(experiment_root=Path("unused"), categories=baseline.CATEGORIES, resume=False, rerun_errors=False, monitor_interval=30, wave_name="test")
        self.assertEqual(calls, [(category,) for category in baseline.CATEGORIES])
        self.assertEqual(set(result), set(baseline.CATEGORIES))
        cmd = baseline.build_category_command(experiment_root=Path("unused"), category="material")
        self.assertEqual(cmd[cmd.index("--model-profile") + 1], "kimik3")
        self.assertIn("--openclaw-config", cmd)

    def test_gemini_shards_cover_dataset_and_preserve_topology(self):
        sharded = import_runner("run_parent_contract_sharded")
        args = sharded.build_parser().parse_args(["start", "--root", "unused", "--dry-run"])
        self.assertEqual((args.model_profile, args.shard_size, args.max_workers, args.max_error_rounds, args.monitor_interval, args.sink_port_base), (model_profiles.DEFAULT_SHARDED_PROFILE, 30, 15, 3, 30, 9400))
        shards = sharded.build_shard_plan(Path("unused"), categories=sharded.CATEGORIES, shard_size=30)
        self.assertEqual(len(shards), 30)
        ids = [attack_id for shard in shards for attack_id in shard["attack_ids"]]
        self.assertEqual(len(ids), 900)
        self.assertEqual(len(set(ids)), 900)
        dataset = sharded.load_jsonl(sharded.DATASET)
        self.assertEqual(ids, [row["attack_id"] for category in sharded.CATEGORIES
                               for row in dataset if row["resource_category"] == category])
        self.assertEqual({row["sink_port"] for row in shards}, set(range(9400, 9430)))
        for shard in shards:
            self.assertEqual(shard["attack_count"], 30)
            cmd = shard["command"]
            self.assertEqual(cmd[cmd.index("--model-profile") + 1], model_profiles.DEFAULT_SHARDED_PROFILE)
            self.assertEqual(cmd.count("--attack-id"), 30)
            self.assertNotIn("--resource-category", cmd)
            self.assertNotIn("recovery", cmd[1])


if __name__ == "__main__":
    unittest.main()
