#!/usr/bin/env python3
"""Run the 900-case parent-contract benchmark with LlamaFirewall enabled."""

from __future__ import annotations

import tempfile
import llamafirewall_release as release

import hashlib
import importlib.util
import json
import signal
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from llamafirewall_settings_v5 import (
    CASE_TIMEOUT_SECONDS,
    HOOK_TIMEOUT_MS,
    JUDGE_MAX_OUTPUT_TOKENS,
    PLUGIN_REQUEST_TIMEOUT_MS,
    SCANNER_API_ROOT,
    SCANNER_MAX_OUTPUT_TOKENS,
    SCANNER_MAX_RESPONSE_BYTES,
    SCANNER_MODEL,
    SCANNER_IMPLEMENTATION,
    SCANNER_RETRIES,
    SCANNER_RESPONSES_ENDPOINT,
    SCANNER_TIMEOUT_SECONDS,
    SCANNER_TOTAL_DEADLINE_SECONDS,
    SCANNER_TRANSPORT_PROTOCOL,
    scanner_key_fingerprint,
)


THIS_DIR = Path(__file__).resolve().parent
BASE_ORCHESTRATOR_PATH = THIS_DIR / "run_parent_contract_baseline.py"
RUNNER_PATH = THIS_DIR / "resource_hijack_runner_parent_contract_llamafirewall_v5.py"
SERVICE_PATH = THIS_DIR / "resource_hijack_llamafirewall_service_v5.py"
PLUGIN_DIR = THIS_DIR.parent / "defenses" / "llamafirewall-v5" / "openclaw-plugin"
LLAMAFIREWALL_ROOT = THIS_DIR.parent / "otherdefense" / "PurpleLlama" / "LlamaFirewall"
ORCHESTRATOR_VERSION = "parent-contract-six-category-llamafirewall-direct-v5"
LLAMAFIREWALL_CASE_TIMEOUT = CASE_TIMEOUT_SECONDS


def load_base_orchestrator():
    spec = importlib.util.spec_from_file_location(
        "run_parent_contract_llamafirewall_base",
        BASE_ORCHESTRATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import orchestrator from {BASE_ORCHESTRATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def runtime_fingerprint_paths() -> List[Path]:
    local_paths = [
        BASE_ORCHESTRATOR_PATH,
        Path(__file__).resolve(),
        RUNNER_PATH,
        SERVICE_PATH,
        THIS_DIR / "llamafirewall_settings_v5.py",
        PLUGIN_DIR / "index.js",
        PLUGIN_DIR / "runtime.js",
        PLUGIN_DIR / "package.json",
        PLUGIN_DIR / "openclaw.plugin.json",
    ]
    imported_llamafirewall_modules = sorted(
        path
        for path in (LLAMAFIREWALL_ROOT / "src" / "llamafirewall").rglob("*.py")
        if "__pycache__" not in path.parts
    )
    return local_paths + imported_llamafirewall_modules


def hash_runtime_paths(paths: Sequence[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def runtime_fingerprint() -> str:
    return hash_runtime_paths(runtime_fingerprint_paths())


def summarize_llamafirewall(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    enabled = [row for row in rows if (row.get("llamafirewall") or {}).get("enabled")]
    missing_metadata = [row for row in rows if not (row.get("llamafirewall") or {}).get("enabled")]
    firewall_errors = [
        row for row in enabled if (row.get("llamafirewall") or {}).get("error_count")
    ]
    global_non_evaluable = [
        row for row in rows if row.get("evaluation_status") == "non_evaluable"
    ]
    evaluable = [
        row
        for row in enabled
        if row.get("evaluation_status") == "evaluable"
        and not (row.get("llamafirewall") or {}).get("error_count")
    ]
    by_category: Dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        category = str(row.get("resource_category", "unknown"))
        firewall = row.get("llamafirewall") or {}
        by_category[category]["cases"] += 1
        by_category[category]["defense_metadata_missing"] += not firewall.get("enabled")
        by_category[category]["global_non_evaluable"] += (
            row.get("evaluation_status") == "non_evaluable"
        )
        by_category[category]["firewall_error"] += bool(firewall.get("error_count"))
        if row not in evaluable:
            continue
        by_category[category]["firewall_evaluable"] += 1
        by_category[category]["blocked"] += bool(firewall.get("blocked"))
        by_category[category]["blocked_without_oracle_trigger"] += bool(
            firewall.get("blocked_without_oracle_trigger")
        )
        by_category[category]["oracle_triggered"] += bool(
            firewall.get("oracle_triggered_after_defense")
        )
        by_category[category]["llm_judge_attack_success"] += (
            (row.get("llm_judge") or {}).get("verdict") == "unsafe"
        )
        by_category[category]["benchmark_attack_success"] += row.get("attack_success") is True
    blocked = sum(bool((row.get("llamafirewall") or {}).get("blocked")) for row in evaluable)
    blocked_without_oracle = sum(
        bool((row.get("llamafirewall") or {}).get("blocked_without_oracle_trigger"))
        for row in evaluable
    )
    oracle_triggered = sum(
        bool((row.get("llamafirewall") or {}).get("oracle_triggered_after_defense"))
        for row in evaluable
    )
    scan_count = sum(int((row.get("llamafirewall") or {}).get("scan_count", 0)) for row in enabled)
    return {
        "implementation": SCANNER_IMPLEMENTATION,
        "scanner_model": SCANNER_MODEL,
        "scanner_api_root": SCANNER_API_ROOT,
        "scanner_responses_endpoint": SCANNER_RESPONSES_ENDPOINT,
        "scanner_transport_protocol": SCANNER_TRANSPORT_PROTOCOL,
        "scanner_max_output_tokens": SCANNER_MAX_OUTPUT_TOKENS,
        "scanner_max_response_bytes": SCANNER_MAX_RESPONSE_BYTES,
        "plugin_request_timeout_ms": PLUGIN_REQUEST_TIMEOUT_MS,
        "hook_timeout_ms": HOOK_TIMEOUT_MS,
        "scanner_timeout_seconds": SCANNER_TIMEOUT_SECONDS,
        "scanner_total_deadline_seconds": SCANNER_TOTAL_DEADLINE_SECONDS,
        "scanner_retries": SCANNER_RETRIES,
        "enforcement_point": "openclaw_before_tool_call",
        "total_cases": len(rows),
        "enabled_cases": len(enabled),
        "defense_metadata_missing_cases": len(missing_metadata),
        "global_non_evaluable_cases": len(global_non_evaluable),
        "firewall_error_cases": len(firewall_errors),
        "firewall_evaluable_cases": len(evaluable),
        "scan_count": scan_count,
        "blocked_cases": blocked,
        "block_rate": blocked / len(evaluable) if evaluable else None,
        "blocked_without_oracle_trigger_cases": blocked_without_oracle,
        "oracle_triggered_after_defense": oracle_triggered,
        "oracle_trigger_rate": oracle_triggered / len(evaluable) if evaluable else None,
        "llm_judge_attack_success_cases": sum(
            (row.get("llm_judge") or {}).get("verdict") == "unsafe" for row in evaluable
        ),
        "benchmark_attack_success_cases": sum(
            row.get("attack_success") is True for row in evaluable
        ),
        "by_category": {key: dict(value) for key, value in sorted(by_category.items())},
    }


orchestrator = load_base_orchestrator()
orchestrator.RUNNER_PATH = RUNNER_PATH
orchestrator.ORCHESTRATOR_VERSION = ORCHESTRATOR_VERSION
orchestrator.runner.RUNNER_VERSION = "resource-hijack-parent-contract-llamafirewall-direct-v5"
orchestrator.runner.PROTOCOL = (
    "isolated-openclaw-state-parent-workspace-llamafirewall-v5-direct-scanner"
)
CATEGORY_WAVES = (
    ("material", "condition"),
    ("energy", "symbolic"),
    ("knowledge", "interaction"),
)
MAX_PARALLEL_CATEGORIES = max(len(wave) for wave in CATEGORY_WAVES)


def opaque_category_workspace(experiment_root: Path, category: str) -> Path:
    root_tag = hashlib.sha256(str(experiment_root.resolve()).encode("utf-8")).hexdigest()[:16]
    category_tag = hashlib.sha256(category.encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / "rh_eval" / root_tag / category_tag / "workspace"


orchestrator.category_workspace = opaque_category_workspace
BASELINE_EXPECTED_TIMEOUT = orchestrator.runner.DEFAULT_TIMEOUT

_base_write_json = orchestrator.write_json
_base_aggregate_results = orchestrator.aggregate_results
_base_build_category_command = orchestrator.build_category_command
_base_run_wave = orchestrator.run_wave


def build_category_command_with_firewall(
    *,
    experiment_root: Path,
    category: str,
    resume_run: Optional[Path] = None,
    rerun_errors: bool = False,
) -> List[str]:
    command = _base_build_category_command(
        experiment_root=experiment_root,
        category=category,
        resume_run=resume_run,
        rerun_errors=rerun_errors,
    )
    command.extend(
        [
            "--timeout",
            str(LLAMAFIREWALL_CASE_TIMEOUT),
            "--llm-judge-max-output-tokens",
            str(JUDGE_MAX_OUTPUT_TOKENS),
            "--allow-protocol-deviation",
        ]
    )
    return command


orchestrator.build_category_command = build_category_command_with_firewall


def run_wave_in_parallel_pairs(**kwargs: Any) -> Dict[str, int]:
    categories = set(kwargs.pop("categories"))
    codes: Dict[str, int] = {}
    for wave in CATEGORY_WAVES:
        selected = [category for category in wave if category in categories]
        if selected:
            codes.update(_base_run_wave(categories=selected, **kwargs))
    return codes


orchestrator.run_wave = run_wave_in_parallel_pairs


def write_json_with_firewall(path: Path, value: Any) -> None:
    if path.name == "experiment_manifest.json" and isinstance(value, dict):
        value = dict(value)
        value.update(
            {
                "defense": "llamafirewall_alignmentcheck",
                "llamafirewall_version": "1.0.3-source",
                "llamafirewall_implementation": (
                    SCANNER_IMPLEMENTATION
                ),
                "llamafirewall_scanner_model": SCANNER_MODEL,
                "llamafirewall_scanner_api_root": SCANNER_API_ROOT,
                "llamafirewall_scanner_responses_endpoint": (
                    SCANNER_RESPONSES_ENDPOINT
                ),
                "llamafirewall_scanner_key_fingerprint": scanner_key_fingerprint(),
                "llamafirewall_scanner_transport_protocol": (
                    SCANNER_TRANSPORT_PROTOCOL
                ),
                "llamafirewall_scanner_max_output_tokens": (
                    SCANNER_MAX_OUTPUT_TOKENS
                ),
                "llamafirewall_scanner_max_response_bytes": (
                    SCANNER_MAX_RESPONSE_BYTES
                ),
                "llamafirewall_plugin_request_timeout_ms": PLUGIN_REQUEST_TIMEOUT_MS,
                "llamafirewall_hook_timeout_ms": HOOK_TIMEOUT_MS,
                "llamafirewall_scanner_timeout_seconds": SCANNER_TIMEOUT_SECONDS,
                "llamafirewall_scanner_total_deadline_seconds": (
                    SCANNER_TOTAL_DEADLINE_SECONDS
                ),
                "llamafirewall_scanner_retries": SCANNER_RETRIES,
                "llamafirewall_judge_max_output_tokens": JUDGE_MAX_OUTPUT_TOKENS,
                "llamafirewall_max_parallel_categories": MAX_PARALLEL_CATEGORIES,
                "llamafirewall_workspace_path_protocol": "opaque-hashed-category-v1",
                "llamafirewall_enforcement_point": "openclaw_before_tool_call",
                "llamafirewall_runtime_sha256": runtime_fingerprint(),
                "baseline_expected_timeout": BASELINE_EXPECTED_TIMEOUT,
                "timeout": LLAMAFIREWALL_CASE_TIMEOUT,
                "protocol_deviations": {
                    "timeout": {
                        "expected": BASELINE_EXPECTED_TIMEOUT,
                        "actual": LLAMAFIREWALL_CASE_TIMEOUT,
                        "allowed": True,
                    },
                    "llm_judge_max_output_tokens": {
                        "expected": 800,
                        "actual": JUDGE_MAX_OUTPUT_TOKENS,
                        "allowed": True,
                    },
                },
            }
        )
    _base_write_json(path, value)


orchestrator.write_json = write_json_with_firewall


def aggregate_results_with_firewall(
    experiment_root: Path,
    categories: Sequence[str],
) -> Dict[str, Any]:
    output = _base_aggregate_results(experiment_root, categories)
    output["summary"]["llamafirewall"] = summarize_llamafirewall(output["results"])
    orchestrator.write_json(experiment_root / "results.json", output)
    summary_path = experiment_root / "summary.md"
    with summary_path.open("a", encoding="utf-8") as handle:
        summary = output["summary"]["llamafirewall"]
        handle.write("\n## LlamaFirewall\n\n")
        handle.write(f"- Firewall-evaluable cases: {summary['firewall_evaluable_cases']}\n")
        handle.write(f"- Firewall error cases: {summary['firewall_error_cases']}\n")
        handle.write(
            f"- Missing defense metadata: {summary['defense_metadata_missing_cases']}\n"
        )
        handle.write(
            f"- Global non-evaluable cases: {summary['global_non_evaluable_cases']}\n"
        )
        handle.write(f"- Blocked cases: {summary['blocked_cases']}\n")
        handle.write(
            "- Blocked without oracle trigger: "
            f"{summary['blocked_without_oracle_trigger_cases']}\n"
        )
        handle.write(f"- Oracle triggers after defense: {summary['oracle_triggered_after_defense']}\n")
        handle.write(
            f"- LLM-Judge attack successes: {summary['llm_judge_attack_success_cases']}\n"
        )
    return output


orchestrator.aggregate_results = aggregate_results_with_firewall


def main() -> int:
    args = orchestrator.build_parser().parse_args()
    if args.experiment_root and args.resume_root:
        raise SystemExit("choose only one of --experiment-root and --resume-root")
    if args.resume_root:
        experiment_root = args.resume_root.expanduser().resolve()
        resume = True
    else:
        experiment_root = (
            args.experiment_root.expanduser().resolve()
            if args.experiment_root
            else orchestrator.DEFAULT_RUN_ROOT
            / ("llamafirewall_alignmentcheck_direct_v5_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
        )
        resume = False
    experiment_root.mkdir(parents=True, exist_ok=True)
    categories = tuple(args.categories)
    commands = {
        category: build_category_command_with_firewall(
            experiment_root=experiment_root,
            category=category,
        )
        for category in categories
    }
    if args.dry_run:
        print(json.dumps({"experiment_root": str(experiment_root), "commands": commands}, indent=2))
        return 0

    unavailable = {
        category: orchestrator.SINK_PORTS[category]
        for category in categories
        if not orchestrator.port_available(orchestrator.SINK_PORTS[category])
    }
    if unavailable:
        print(f"[preflight error] sink ports are in use: {unavailable}", file=sys.stderr)
        return 2

    source_config = release.dependency_paths("v5")["openclaw_config"]
    manifest = {
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "created_at": datetime.now().isoformat(),
        "experiment_root": str(experiment_root),
        "categories": list(categories),
        "dataset": str(orchestrator.runner.DEFAULT_ATTACKS),
        "dataset_sha256": orchestrator.sha256_file(orchestrator.runner.DEFAULT_ATTACKS),
        "runner": str(RUNNER_PATH),
        "runner_sha256": orchestrator.sha256_file(RUNNER_PATH),
        "source_openclaw_config_sha256": orchestrator.sha256_file(source_config),
        "baseline_reference": str(orchestrator.runner.BASELINE_REFERENCE),
        "agentdog_mode": "off",
        "openclaw_model": orchestrator.runner.DEFAULT_OPENCLAW_MODEL,
        "judge_model": release.get_base_model_profile("v5")["judge_model"],
        "judge_max_output_tokens": JUDGE_MAX_OUTPUT_TOKENS,
        "timeout": LLAMAFIREWALL_CASE_TIMEOUT,
        "commands": commands,
    }
    manifest_path = experiment_root / "experiment_manifest.json"
    if resume:
        if not manifest_path.exists():
            print(f"[resume error] missing {manifest_path}", file=sys.stderr)
            return 2
        previous = orchestrator.load_json(manifest_path)
        guarded = (
            "orchestrator_version",
            "categories",
            "dataset_sha256",
            "runner_sha256",
            "source_openclaw_config_sha256",
            "agentdog_mode",
            "openclaw_model",
            "judge_model",
            "judge_max_output_tokens",
            "timeout",
            "llamafirewall_runtime_sha256",
            "llamafirewall_scanner_key_fingerprint",
            "llamafirewall_scanner_api_root",
            "llamafirewall_scanner_responses_endpoint",
            "llamafirewall_scanner_transport_protocol",
            "llamafirewall_scanner_max_output_tokens",
            "llamafirewall_scanner_max_response_bytes",
            "llamafirewall_plugin_request_timeout_ms",
            "llamafirewall_hook_timeout_ms",
            "llamafirewall_workspace_path_protocol",
            "llamafirewall_scanner_timeout_seconds",
            "llamafirewall_scanner_total_deadline_seconds",
            "llamafirewall_scanner_retries",
            "llamafirewall_max_parallel_categories",
        )
        current_for_guard = dict(manifest)
        current_for_guard.update(
            {
                "llamafirewall_runtime_sha256": runtime_fingerprint(),
                "llamafirewall_scanner_key_fingerprint": scanner_key_fingerprint(),
                "llamafirewall_scanner_api_root": SCANNER_API_ROOT,
                "llamafirewall_scanner_responses_endpoint": (
                    SCANNER_RESPONSES_ENDPOINT
                ),
                "llamafirewall_scanner_transport_protocol": (
                    SCANNER_TRANSPORT_PROTOCOL
                ),
                "llamafirewall_scanner_max_output_tokens": (
                    SCANNER_MAX_OUTPUT_TOKENS
                ),
                "llamafirewall_scanner_max_response_bytes": (
                    SCANNER_MAX_RESPONSE_BYTES
                ),
                "llamafirewall_plugin_request_timeout_ms": PLUGIN_REQUEST_TIMEOUT_MS,
                "llamafirewall_hook_timeout_ms": HOOK_TIMEOUT_MS,
                "llamafirewall_workspace_path_protocol": "opaque-hashed-category-v1",
                "llamafirewall_scanner_timeout_seconds": SCANNER_TIMEOUT_SECONDS,
                "llamafirewall_scanner_total_deadline_seconds": (
                    SCANNER_TOTAL_DEADLINE_SECONDS
                ),
                "llamafirewall_scanner_retries": SCANNER_RETRIES,
                "llamafirewall_max_parallel_categories": MAX_PARALLEL_CATEGORIES,
            }
        )
        drift = {
            key: {"previous": previous.get(key), "current": current_for_guard.get(key)}
            for key in guarded
            if previous.get(key) != current_for_guard.get(key)
        }
        if drift:
            print(
                f"[resume error] experiment drift: {json.dumps(drift, sort_keys=True)}",
                file=sys.stderr,
            )
            return 2
    else:
        write_json_with_firewall(manifest_path, manifest)

    stop_requested = False

    def handle_signal(signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True
        raise KeyboardInterrupt(f"received signal {signum}")

    old_handlers = {
        signal.SIGINT: signal.signal(signal.SIGINT, handle_signal),
        signal.SIGTERM: signal.signal(signal.SIGTERM, handle_signal),
    }
    try:
        initial_codes = orchestrator.run_wave(
            experiment_root=experiment_root,
            categories=categories,
            resume=resume,
            rerun_errors=False,
            monitor_interval=args.monitor_interval,
            wave_name="initial_or_resume",
        )
        print(f"[llamafirewall] initial/resume return codes: {initial_codes}", flush=True)

        for round_index in range(1, args.max_error_rerun_rounds + 1):
            error_categories = [
                category
                for category in categories
                if orchestrator.category_status(experiment_root, category)["non_evaluable"] > 0
            ]
            incomplete_categories = [
                category
                for category in categories
                if orchestrator.category_status(experiment_root, category)["completed"] < 150
            ]
            target_categories = sorted(
                set(error_categories + incomplete_categories),
                key=orchestrator.CATEGORIES.index,
            )
            if not target_categories:
                break
            before = {
                category: orchestrator.category_status(experiment_root, category)
                for category in target_categories
            }
            codes = orchestrator.run_wave(
                experiment_root=experiment_root,
                categories=target_categories,
                resume=True,
                rerun_errors=bool(error_categories),
                monitor_interval=args.monitor_interval,
                wave_name=f"error_rerun_{round_index}",
            )
            after = {
                category: orchestrator.category_status(experiment_root, category)
                for category in target_categories
            }
            orchestrator.write_json(
                experiment_root / f"error_rerun_{round_index}_progress.json",
                {"before": before, "after": after, "returncodes": codes},
            )

        output = aggregate_results_with_firewall(experiment_root, categories)
        print(json.dumps(output["summary"], ensure_ascii=False, indent=2), flush=True)
        print(f"[llamafirewall] results: {experiment_root / 'results.json'}", flush=True)
        return 4 if output["summary"]["non_evaluable"] else 0
    except KeyboardInterrupt as error:
        print(
            f"[llamafirewall] interrupted: {error}; resume with --resume-root {experiment_root}",
            file=sys.stderr,
        )
        return 130 if stop_requested else 1
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


_historical_main = main


def main() -> int:
    return release.run_entry(globals(), _historical_main, "batch", "v5")


if __name__ == "__main__":
    raise SystemExit(main())
