#!/usr/bin/env python3
"""Run the 900-case parent-contract baseline in six isolated category batches."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


THIS_DIR = Path(__file__).resolve().parent
HUB_ROOT = THIS_DIR.parent
# Default output root for run artifacts (created at runtime).
RUNNER_PATH = THIS_DIR / "resource_hijack_runner_parent_contract.py"
DEFAULT_RUN_ROOT = HUB_ROOT / "runs" / "resource_hijack_runs_900_parent_contract"
CATEGORIES = ("material", "condition", "energy", "symbolic", "knowledge", "interaction")
SINK_PORTS = {category: 8911 + index for index, category in enumerate(CATEGORIES)}
ORCHESTRATOR_VERSION = "parent-contract-six-category-baseline-v1"


def load_runner():
    spec = importlib.util.spec_from_file_location("parent_contract_runner_for_orchestration", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import runner from {RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_runner()
model_profiles = runner.model_profiles
MODEL_PROFILE = model_profiles.DEFAULT_PROFILE
CATEGORY_CONCURRENCY = model_profiles.get_profile(MODEL_PROFILE)["category_concurrency"]
DEFAULT_SOURCE_CONFIG = runner.legacy.DEFAULT_OPENCLAW_CONFIG
SOURCE_CONFIG = DEFAULT_SOURCE_CONFIG


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def append_jsonl(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def category_workspace(experiment_root: Path, category: str) -> Path:
    return Path(tempfile.gettempdir()) / "rh_parent_contract_baseline_900" / experiment_root.name / category / "workspace"


def category_run_root(experiment_root: Path, category: str) -> Path:
    return experiment_root / "categories" / category


def discover_run_dir(experiment_root: Path, category: str) -> Optional[Path]:
    root = category_run_root(experiment_root, category)
    candidates = sorted(path for path in root.glob("*") if path.is_dir()) if root.exists() else []
    if len(candidates) > 1:
        raise RuntimeError(f"multiple run directories for {category}: {candidates}")
    return candidates[0] if candidates else None


def build_category_command(
    *,
    experiment_root: Path,
    category: str,
    resume_run: Optional[Path] = None,
    rerun_errors: bool = False,
) -> List[str]:
    command = [
        sys.executable,
        str(RUNNER_PATH),
        "--model-profile", MODEL_PROFILE,
        "--openclaw-config", str(SOURCE_CONFIG),
        "--resource-category",
        category,
        "--all",
        "--run-root",
        str(category_run_root(experiment_root, category)),
        "--openclaw-bin",
        str(runner.DEFAULT_OPENCLAW_BIN),
        "--openclaw-workspace",
        str(category_workspace(experiment_root, category)),
        "--sink-port",
        str(SINK_PORTS[category]),
    ]
    if resume_run is not None:
        command.extend(["--resume-run", str(resume_run)])
    if rerun_errors:
        command.append("--rerun-errors")
    return command


def port_available(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def result_rows(run_dir: Optional[Path]) -> List[Dict[str, Any]]:
    if run_dir is None:
        return []
    final = run_dir / "results.json"
    partial = run_dir / "results_partial.json"
    if final.exists():
        value = load_json(final)
        return value.get("results", []) if isinstance(value, dict) else []
    if partial.exists():
        value = load_json(partial)
        return value if isinstance(value, list) else []
    return []


def category_status(experiment_root: Path, category: str) -> Dict[str, Any]:
    run_dir = discover_run_dir(experiment_root, category)
    rows = result_rows(run_dir)
    evaluable = sum(row.get("evaluation_status") == "evaluable" for row in rows)
    non_evaluable = sum(row.get("evaluation_status") == "non_evaluable" for row in rows)
    return {
        "category": category,
        "run_dir": str(run_dir) if run_dir else None,
        "completed": len(rows),
        "evaluable": evaluable,
        "non_evaluable": non_evaluable,
        "safe": sum(row.get("verdict") == "safe" for row in rows),
        "unsafe": sum(row.get("verdict") == "unsafe" for row in rows),
    }


def print_progress(experiment_root: Path, categories: Sequence[str]) -> None:
    statuses = [category_status(experiment_root, category) for category in categories]
    total = sum(row["completed"] for row in statuses)
    evaluable = sum(row["evaluable"] for row in statuses)
    errors = sum(row["non_evaluable"] for row in statuses)
    detail = " ".join(
        f"{row['category']}={row['completed']}/150(e={row['evaluable']},err={row['non_evaluable']})"
        for row in statuses
    )
    print(
        f"[baseline-monitor] total={total}/{len(categories) * 150} "
        f"evaluable={evaluable} non_evaluable={errors} {detail}",
        flush=True,
    )


def terminate_processes(processes: Dict[str, subprocess.Popen[Any]]) -> None:
    for process in processes.values():
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                process.terminate()
    deadline = time.time() + 5
    while time.time() < deadline and any(process.poll() is None for process in processes.values()):
        time.sleep(0.1)
    for process in processes.values():
        if process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()


def _run_wave_batch(
    *,
    experiment_root: Path,
    categories: Sequence[str],
    resume: bool,
    rerun_errors: bool,
    monitor_interval: int,
    wave_name: str,
) -> Dict[str, int]:
    processes: Dict[str, subprocess.Popen[Any]] = {}
    logs: Dict[str, Any] = {}
    commands: Dict[str, List[str]] = {}
    try:
        for category in categories:
            run_dir = discover_run_dir(experiment_root, category) if resume else None
            command = build_category_command(
                experiment_root=experiment_root,
                category=category,
                resume_run=run_dir,
                rerun_errors=rerun_errors,
            )
            log_path = experiment_root / "logs" / f"{category}.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log = log_path.open("a", encoding="utf-8")
            logs[category] = log
            commands[category] = command
            append_jsonl(
                experiment_root / "waves.jsonl",
                {
                    "timestamp": datetime.now().isoformat(),
                    "wave": wave_name,
                    "category": category,
                    "command": command,
                },
            )
            processes[category] = subprocess.Popen(
                command,
                cwd=str(THIS_DIR),
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )

        while any(process.poll() is None for process in processes.values()):
            print_progress(experiment_root, categories)
            time.sleep(monitor_interval)
        print_progress(experiment_root, categories)
        returncodes = {category: int(process.wait()) for category, process in processes.items()}
        write_json(
            experiment_root / f"{wave_name}_returncodes.json",
            {"returncodes": returncodes, "commands": commands},
        )
        return returncodes
    except BaseException:
        terminate_processes(processes)
        raise
    finally:
        for log in logs.values():
            log.close()


def run_wave(
    *, experiment_root: Path, categories: Sequence[str], resume: bool,
    rerun_errors: bool, monitor_interval: int, wave_name: str,
) -> Dict[str, int]:
    """Bound category concurrency using the selected experiment configuration."""
    returncodes: Dict[str, int] = {}
    for start in range(0, len(categories), CATEGORY_CONCURRENCY):
        batch = categories[start:start + CATEGORY_CONCURRENCY]
        label = wave_name if len(categories) <= CATEGORY_CONCURRENCY else f"{wave_name}_batch_{start // CATEGORY_CONCURRENCY + 1}"
        returncodes.update(_run_wave_batch(
            experiment_root=experiment_root, categories=batch, resume=resume,
            rerun_errors=rerun_errors, monitor_interval=monitor_interval, wave_name=label,
        ))
    return returncodes


def aggregate_results(experiment_root: Path, categories: Sequence[str]) -> Dict[str, Any]:
    attacks = runner.load_jsonl(runner.DEFAULT_ATTACKS)
    expected = {
        row["attack_id"]: row
        for row in attacks
        if row.get("resource_category") in set(categories)
    }
    rows: List[Dict[str, Any]] = []
    category_runs: Dict[str, str] = {}
    for category in categories:
        run_dir = discover_run_dir(experiment_root, category)
        if run_dir is None or not (run_dir / "results.json").exists():
            raise RuntimeError(f"missing completed results for {category}: {run_dir}")
        category_runs[category] = str(run_dir)
        category_rows = result_rows(run_dir)
        if len(category_rows) != 150:
            raise RuntimeError(f"{category} has {len(category_rows)} results, expected 150")
        if any(row.get("resource_category") != category for row in category_rows):
            raise RuntimeError(f"{category} result file contains another category")
        rows.extend(category_rows)

    attack_ids = [str(row.get("attack_id")) for row in rows]
    if len(attack_ids) != len(set(attack_ids)):
        raise RuntimeError("duplicate attack IDs in combined results")
    if set(attack_ids) != set(expected):
        raise RuntimeError(
            f"combined selection mismatch: missing={sorted(set(expected) - set(attack_ids))[:20]} "
            f"extra={sorted(set(attack_ids) - set(expected))[:20]}"
        )
    for row in rows:
        expected_sha = runner.stable_sha256(expected[row["attack_id"]])
        if row.get("case_sha256") != expected_sha:
            raise RuntimeError(f"case fingerprint mismatch: {row['attack_id']}")
    rows.sort(key=lambda row: row["attack_id"])
    summary = runner.legacy.summarize(rows)
    summary["evaluable"] = sum(row.get("evaluation_status") == "evaluable" for row in rows)
    summary["non_evaluable"] = sum(row.get("evaluation_status") == "non_evaluable" for row in rows)
    summary["by_evaluation_status"] = dict(
        sorted(Counter(str(row.get("evaluation_status", "unknown")) for row in rows).items())
    )
    summary["by_success_level"] = dict(
        sorted(Counter(str(row.get("attack_success_level")) for row in rows).items())
    )
    output = {
        "timestamp": datetime.now().isoformat(),
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "runner_version": runner.RUNNER_VERSION,
        "protocol": runner.PROTOCOL,
        "dataset": str(runner.DEFAULT_ATTACKS),
        "dataset_sha256": sha256_file(runner.DEFAULT_ATTACKS),
        "category_runs": category_runs,
        "summary": summary,
        "results": rows,
    }
    write_json(experiment_root / "results.json", output)
    with (experiment_root / "results.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    markdown = [
        "# Parent-Contract Resource Hijack Baseline ",
        "",
        f"- Total: {summary['total']}",
        f"- Evaluable: {summary['evaluable']}",
        f"- Non-evaluable: {summary['non_evaluable']}",
        f"- Unsafe: {summary['by_verdict'].get('unsafe', 0)}",
        f"- Safe: {summary['by_verdict'].get('safe', 0)}",
        f"- Oracle triggered: {summary['oracle_triggered']}",
        f"- Dataset SHA-256: `{output['dataset_sha256']}`",
        "",
        "## Success Levels",
        "",
    ]
    for level, count in summary["by_success_level"].items():
        markdown.append(f"- {level}: {count}")
    (experiment_root / "summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-profile", choices=model_profiles.PROFILE_NAMES, default=model_profiles.DEFAULT_PROFILE)
    parser.add_argument("--openclaw-config", type=Path, default=DEFAULT_SOURCE_CONFIG)
    parser.add_argument("--category-concurrency", type=int, help="Maximum category workers; defaults to the selected model profile")
    parser.add_argument("--experiment-root", type=Path)
    parser.add_argument("--resume-root", type=Path)
    parser.add_argument("--categories", nargs="+", choices=CATEGORIES, default=list(CATEGORIES))
    parser.add_argument("--monitor-interval", type=int, default=30)
    parser.add_argument("--max-error-rerun-rounds", type=int, default=3)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main() -> int:
    global MODEL_PROFILE, CATEGORY_CONCURRENCY, SOURCE_CONFIG, ORCHESTRATOR_VERSION
    parser = build_parser()
    args = parser.parse_args()
    MODEL_PROFILE = args.model_profile
    profile = model_profiles.get_profile(MODEL_PROFILE)
    CATEGORY_CONCURRENCY = args.category_concurrency if args.category_concurrency is not None else profile["category_concurrency"]
    if CATEGORY_CONCURRENCY < 1:
        parser.error("--category-concurrency must be positive")
    SOURCE_CONFIG = args.openclaw_config.expanduser().resolve()
    ORCHESTRATOR_VERSION = "parent-contract-six-category-" + MODEL_PROFILE + "-v2"
    model_args = runner.build_parser(MODEL_PROFILE).parse_args([])
    runner.configure_model_profile(model_args)
    if args.experiment_root and args.resume_root:
        raise SystemExit("choose only one of --experiment-root and --resume-root")
    if args.resume_root:
        experiment_root = args.resume_root.expanduser().resolve()
        resume = True
    else:
        experiment_root = (
            args.experiment_root.expanduser().resolve()
            if args.experiment_root
            else DEFAULT_RUN_ROOT / (MODEL_PROFILE + "_" + datetime.now().strftime("%Y%m%d_%H%M%S"))
        )
        resume = False
    categories = tuple(args.categories)

    commands = {
        category: build_category_command(experiment_root=experiment_root, category=category)
        for category in categories
    }
    if args.dry_run:
        print(json.dumps({"experiment_root": str(experiment_root), "commands": commands}, indent=2))
        return 0
    experiment_root.mkdir(parents=True, exist_ok=True)
    unavailable = {category: SINK_PORTS[category] for category in categories if not port_available(SINK_PORTS[category])}
    if unavailable:
        print(f"[preflight error] sink ports are in use: {unavailable}", file=sys.stderr)
        return 2

    source_config = SOURCE_CONFIG
    manifest = {
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "created_at": datetime.now().isoformat(),
        "experiment_root": str(experiment_root),
        "categories": list(categories),
        "dataset": str(runner.DEFAULT_ATTACKS),
        "dataset_sha256": sha256_file(runner.DEFAULT_ATTACKS),
        "runner": str(RUNNER_PATH),
        "runner_sha256": sha256_file(RUNNER_PATH),
        "source_openclaw_config_sha256": sha256_file(source_config),
        "model_profile": MODEL_PROFILE,
        "model_profiles_sha256": sha256_file(model_profiles.PROFILE_PATH),
        "model_adapter_sha256": sha256_file(Path(model_profiles.__file__)),
        "category_concurrency": CATEGORY_CONCURRENCY,
        "openclaw_model": runner.DEFAULT_OPENCLAW_MODEL,
        "judge_model": model_args.llm_judge_model,
        "judge_api": profile["judge_api"],
        "timeout": runner.DEFAULT_TIMEOUT,
        "commands": commands,
    }
    manifest_path = experiment_root / "experiment_manifest.json"
    if resume:
        if not manifest_path.exists():
            print(f"[resume error] missing {manifest_path}", file=sys.stderr)
            return 2
        previous = load_json(manifest_path)
        guarded = (
            "orchestrator_version",
            "categories",
            "dataset_sha256",
            "runner_sha256",
            "source_openclaw_config_sha256",
            "model_profile",
            "model_profiles_sha256",
            "model_adapter_sha256",
            "category_concurrency",
            "judge_api",
            "openclaw_model",
            "judge_model",
            "timeout",
        )
        drift = {
            key: {"previous": previous.get(key), "current": manifest.get(key)}
            for key in guarded
            if previous.get(key) != manifest.get(key)
        }
        if drift:
            print(f"[resume error] experiment drift: {json.dumps(drift, sort_keys=True)}", file=sys.stderr)
            return 2
    else:
        write_json(manifest_path, manifest)

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
        initial_codes = run_wave(
            experiment_root=experiment_root,
            categories=categories,
            resume=resume,
            rerun_errors=False,
            monitor_interval=args.monitor_interval,
            wave_name="initial_or_resume",
        )
        print(f"[baseline] initial/resume return codes: {initial_codes}", flush=True)

        for round_index in range(1, args.max_error_rerun_rounds + 1):
            error_categories = [
                category
                for category in categories
                if category_status(experiment_root, category)["non_evaluable"] > 0
            ]
            incomplete_categories = [
                category
                for category in categories
                if category_status(experiment_root, category)["completed"] < 150
            ]
            target_categories = sorted(set(error_categories + incomplete_categories), key=CATEGORIES.index)
            if not target_categories:
                break
            before = {category: category_status(experiment_root, category) for category in target_categories}
            codes = run_wave(
                experiment_root=experiment_root,
                categories=target_categories,
                resume=True,
                rerun_errors=bool(error_categories),
                monitor_interval=args.monitor_interval,
                wave_name=f"error_rerun_{round_index}",
            )
            after = {category: category_status(experiment_root, category) for category in target_categories}
            write_json(
                experiment_root / f"error_rerun_{round_index}_progress.json",
                {"before": before, "after": after, "returncodes": codes},
            )

        output = aggregate_results(experiment_root, categories)
        print(json.dumps(output["summary"], ensure_ascii=False, indent=2), flush=True)
        print(f"[baseline] results: {experiment_root / 'results.json'}", flush=True)
        return 4 if output["summary"]["non_evaluable"] else 0
    except KeyboardInterrupt as error:
        print(f"[baseline] interrupted: {error}; resume with --resume-root {experiment_root}", file=sys.stderr)
        return 130 if stop_requested else 1
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
