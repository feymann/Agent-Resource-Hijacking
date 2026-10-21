"""Thin defense setup around the shared six-category retry orchestrator."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path

from defense_adapters import AgentDogGateAdapter, PromptDefenseAdapter, load_shared_module, sha256_bytes, DEFENSE_PROFILE


def main(kind="agentdog", version="v2"):
    orchestrator = load_shared_module("run_parent_contract_baseline.py", "shared_defense_orchestrator")
    runner = orchestrator.runner
    adapter = AgentDogGateAdapter(runner) if kind == "agentdog" else PromptDefenseAdapter(runner, version)
    entry = "resource_hijack_runner_parent_contract_agentdog_gate.py" if kind == "agentdog" else "resource_hijack_runner_parent_contract_prompt_defense_v2.py"
    orchestrator.RUNNER_PATH = Path(__file__).parent / entry
    if kind == "agentdog":
        orchestrator.SINK_PORTS = {category: 8911 + index for index, category in enumerate(orchestrator.CATEGORIES)}
    base_parser = orchestrator.build_parser
    def build_parser():
        parser = base_parser()
        parser.set_defaults(model_profile=DEFENSE_PROFILE)
        parser.description = "Run the supplied " + ("AgentDog final gate" if kind == "agentdog" else "prompt defense " + version) + " with shared category orchestration"
        parser.add_argument("--preflight", action="store_true")
        if kind == "agentdog":
            parser.add_argument("--external-helper", default=os.environ.get("RH_EXTERNAL_HELPER", ""))
            parser.add_argument("--agentdog-url", default="http://127.0.0.1:8342")
            parser.add_argument("--agentdog-service-dir", default=os.environ.get("AGENTDOG_SERVICE_DIR", str(orchestrator.HUB_ROOT / "AgentDoG" / "Online Agentic Guardrail")))
            parser.add_argument("--baseline-results", type=Path, default=orchestrator.DEFAULT_RUN_ROOT / "baseline_agentdog_off" / "results.json")
        else:
            parser.add_argument("--policy-file", type=Path, default=adapter.policy_path)
        return parser
    orchestrator.build_parser = build_parser
    args = build_parser().parse_args()
    parent_parser = runner.build_parser
    def worker_parser(model_profile=DEFENSE_PROFILE):
        parser = parent_parser(model_profile)
        if kind == "agentdog":
            parser.set_defaults(external_helper=args.external_helper, agentdog_url=args.agentdog_url,
                                agentdog_service_dir=args.agentdog_service_dir, no_agentdog_autostart=True)
        else:
            parser.set_defaults(policy_file=args.policy_file)
        return parser
    runner.build_parser = worker_parser
    worker_args = runner.build_parser(args.model_profile).parse_args([])
    worker_args.openclaw_config = str(args.openclaw_config)
    worker_args.preflight = args.preflight
    worker_args.dry_run = args.dry_run
    runner.configure_model_profile(worker_args)

    def baseline_check():
        baseline_path = args.baseline_results.expanduser().resolve()
        if not baseline_path.is_file():
            raise FileNotFoundError("Completed baseline results are missing: " + str(baseline_path))
        baseline = orchestrator.load_json(baseline_path)
        if (baseline.get("summary") or {}).get("total") != 900:
            raise ValueError("Baseline does not contain 900 results")
        dataset_sha = orchestrator.sha256_file(runner.DEFAULT_ATTACKS)
        if baseline.get("dataset_sha256") != dataset_sha:
            raise ValueError("Baseline and AgentDog datasets differ")
        manifest = orchestrator.load_json(baseline_path.parent / "experiment_manifest.json")
        expected = {"dataset_sha256": dataset_sha,
                    "source_openclaw_config_sha256": orchestrator.sha256_file(args.openclaw_config),
                    "openclaw_model": runner.DEFAULT_OPENCLAW_MODEL,
                    "judge_model": worker_args.llm_judge_model, "timeout": worker_args.timeout}
        drift = {key: {"baseline": manifest.get(key), "current": value} for key, value in expected.items() if manifest.get(key) != value}
        if drift:
            raise ValueError("Baseline/runtime drift: " + json.dumps(drift, sort_keys=True))

    if not args.dry_run:
        try:
            runner.legacy.validate_runtime_requirements(worker_args)
            if kind == "agentdog":
                if not Path(args.agentdog_service_dir).is_dir():
                    raise FileNotFoundError("AgentDog service directory is missing: " + args.agentdog_service_dir)
                baseline_check()
        except (OSError, ValueError) as error:
            build_parser().error(str(error))
    if args.preflight:
        print("Preflight passed: required local files exist; helper was not imported and services were not started.")
        return 0

    base_command = orchestrator.build_category_command
    def build_category_command(**kwargs):
        command = base_command(**kwargs)
        if kind == "agentdog":
            command.extend(["--external-helper", args.external_helper, "--agentdog-mode", "observe",
                            "--agentdog-url", args.agentdog_url, "--agentdog-service-dir", args.agentdog_service_dir,
                            "--no-agentdog-autostart", "--agentdog-gate", "--allow-protocol-deviation"])
        else:
            command.extend(["--policy-file", str(args.policy_file)])
        return command
    orchestrator.build_category_command = build_category_command
    base_hash = orchestrator.sha256_file
    def sha256_file(path):
        value = base_hash(path)
        if Path(path).resolve() != orchestrator.RUNNER_PATH.resolve():
            return value
        evidence = adapter.metadata()
        if kind == "agentdog":
            evidence["baseline_results_sha256"] = base_hash(args.baseline_results)
            evidence["baseline_manifest_sha256"] = base_hash(args.baseline_results.parent / "experiment_manifest.json")
        adapter_source = Path(__file__).with_name("defense_adapters.py")
        return sha256_bytes((value + base_hash(Path(__file__)) + base_hash(adapter_source) + json.dumps(evidence, sort_keys=True)).encode())
    orchestrator.sha256_file = sha256_file
    base_write = orchestrator.write_json
    def write_json(path, value):
        if Path(path).name in {"experiment_manifest.json", "results.json"} and isinstance(value, dict):
            value = {**value, **adapter.metadata()}
            value["orchestrator_version"] = ("parent-contract-six-category-agentdog-gate-v5" if kind == "agentdog" else "parent-contract-six-category-prompt-defense-zh-" + version + "-" + args.model_profile)
        base_write(path, value)
    orchestrator.write_json = write_json
    # Keep the metadata identity stable before the shared resume checks.
    base_profile_configure = runner.configure_model_profile
    def configure_model_profile(model_args):
        base_profile_configure(model_args)
        orchestrator.ORCHESTRATOR_VERSION = ("parent-contract-six-category-agentdog-gate-v5" if kind == "agentdog" else "parent-contract-six-category-prompt-defense-zh-" + version + "-" + args.model_profile)
    runner.configure_model_profile = configure_model_profile

    if kind == "agentdog":
        base_wave = orchestrator.run_wave
        started = False
        def run_wave(**kwargs):
            nonlocal started
            if not started:
                experiment_root = kwargs["experiment_root"]
                helper = runner.legacy.load_runtime(worker_args)
                worker_args.openclaw_workspace_backup = str(experiment_root / "service_workspace_backup")
                runner.legacy.configure_helper(helper, worker_args)
                helper.AGENTDOG_AUTOSTART = True
                helper.AGENTDOG_SERVICE_LOG = experiment_root / "agentdog_service.log"
                helper.AGENTDOG_SESSIONS_DIR = experiment_root / "agentdog_sessions"
                helper.AGENTDOG_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
                helper._ensure_agentdog_service()
                if not helper._agentdog_healthcheck(timeout=3):
                    raise RuntimeError("AgentDog service did not become healthy at " + args.agentdog_url)
                started = True
            return base_wave(**kwargs)
        orchestrator.run_wave = run_wave
    if "--experiment-root" not in sys.argv and "--resume-root" not in sys.argv:
        prefix = "agentdog_gate_observe_parent_contract_" if kind == "agentdog" else "prompt_defense_resource_safety_zh_" + version + "_" + args.model_profile + "_"
        sys.argv.extend(["--experiment-root", str(orchestrator.DEFAULT_RUN_ROOT / (prefix + datetime.now().strftime("%Y%m%d_%H%M%S")))])
    return orchestrator.main()
