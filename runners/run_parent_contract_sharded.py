#!/usr/bin/env python3
"""Run parent-contract cases in bounded per-category shard workers.

The selected profile supplies the model and optional shard settings. Each
worker uses the shared parent-contract runner; command-line options override
the configured shard topology.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
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
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))
import model_profiles
RESOURCE_ROOT = Path(os.environ.get("RH_DATASET_DIR", str(HUB_ROOT / "dataset")))
DATASET = RESOURCE_ROOT / "scaled_attacks.jsonl"
ORIGINAL_RUNNER = THIS_DIR / "resource_hijack_runner_parent_contract.py"
DEFAULT_SOURCE_CONFIG = Path(os.environ.get("RH_OPENCLAW_CONFIG", str(HUB_ROOT / "configs" / "openclaw.json")))
SOURCE_CONFIG = DEFAULT_SOURCE_CONFIG
MODEL_PROFILE = model_profiles.DEFAULT_SHARDED_PROFILE
CATEGORIES = ("material", "condition", "energy", "symbolic", "knowledge", "interaction")
OPENCLAW_BIN = os.environ.get("OPENCLAW_BIN", shutil.which("openclaw") or "openclaw")
DEFAULT_SHARDING = model_profiles.sharding_defaults(MODEL_PROFILE)
SINK_PORT_BASE = DEFAULT_SHARDING["sink_port_base"]
SHARD_SIZE = DEFAULT_SHARDING["shard_size"]
MAX_WORKERS = DEFAULT_SHARDING["max_workers"]
MAX_ERROR_ROUNDS = DEFAULT_SHARDING["max_error_rounds"]
MONITOR_INTERVAL = DEFAULT_SHARDING["monitor_interval"]
MANIFEST_VERSION = "parent-contract-model-profile-sharded-v2"
ORCHESTRATOR_VERSION = "parent-contract-model-profile-sharded-v2"


_RUNNER = None
_RUNNER_PROFILE = None


def load_runner():
    """Lazily import the selected shared runner for merging and fingerprints."""
    global _RUNNER, _RUNNER_PROFILE
    if _RUNNER is None or _RUNNER_PROFILE != MODEL_PROFILE:
        spec = importlib.util.spec_from_file_location(
            "parent_contract_for_sharded_merge",
            ORIGINAL_RUNNER,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot import {ORIGINAL_RUNNER}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.configure_model_profile(module.build_parser(MODEL_PROFILE).parse_args([]))
        _RUNNER = module
        _RUNNER_PROFILE = MODEL_PROFILE
    return _RUNNER


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def append_jsonl(path: Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


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


def build_shard_plan(
    root: Path,
    *,
    categories: Sequence[str],
    shard_size: int,
    limit_per_category: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Split each category's attack IDs (dataset order) into shards of shard_size."""
    dataset = load_jsonl(DATASET)
    shards: List[Dict[str, Any]] = []
    global_index = 0
    for category in CATEGORIES:
        if category not in categories:
            continue
        attack_ids = [
            str(row["attack_id"])
            for row in dataset
            if row.get("resource_category") == category
        ]
        if limit_per_category is not None:
            attack_ids = attack_ids[:limit_per_category]
        for start in range(0, len(attack_ids), shard_size):
            chunk = attack_ids[start : start + shard_size]
            shard_index = start // shard_size
            shard_dir = root / "shards" / category / f"shard_{shard_index:02d}"
            workspace = (
                Path(tempfile.gettempdir())
                / "rh_parent_contract_baseline_900"
                / root.name
                / "shards"
                / f"{category}_{shard_index:02d}"
                / "workspace"
            )
            command = [sys.executable, str(ORIGINAL_RUNNER), "--model-profile", MODEL_PROFILE, "--openclaw-config", str(SOURCE_CONFIG)]
            for attack_id in chunk:
                command.extend(["--attack-id", attack_id])
            command.extend(
                [
                    "--run-root",
                    str(shard_dir),
                    "--openclaw-bin",
                    OPENCLAW_BIN,
                    "--openclaw-workspace",
                    str(workspace),
                    "--sink-port",
                    str(SINK_PORT_BASE + global_index),
                ]
            )
            shards.append(
                {
                    "name": f"{category}/shard_{shard_index:02d}",
                    "category": category,
                    "shard_index": shard_index,
                    "global_index": global_index,
                    "attack_ids": chunk,
                    "attack_count": len(chunk),
                    "shard_dir": shard_dir,
                    "workspace": workspace,
                    "sink_port": SINK_PORT_BASE + global_index,
                    "log_path": root / "logs" / f"shard_{category}_{shard_index:02d}.log",
                    "command": command,
                }
            )
            global_index += 1
    return shards


def resolve_run_dir(shard_dir: Path) -> Optional[Path]:
    """Find the runner's run directory for a shard.

    The runner creates a timestamped subdirectory below --run-root; tolerate a
    shard directory that itself is the run directory as well.
    """
    if (shard_dir / "selection.json").exists():
        return shard_dir
    if not shard_dir.exists():
        return None
    subdirs = sorted(path for path in shard_dir.glob("*") if path.is_dir())
    if not subdirs:
        return None
    with_selection = [path for path in subdirs if (path / "selection.json").exists()]
    return (with_selection or subdirs)[-1]


def read_shard_rows(shard_dir: Path) -> List[Dict[str, Any]]:
    run_dir = resolve_run_dir(shard_dir)
    if run_dir is None:
        return []
    final = run_dir / "results.json"
    partial = run_dir / "results_partial.json"
    try:
        if final.exists():
            value = load_json(final)
            return value.get("results", []) if isinstance(value, dict) else []
        if partial.exists():
            value = load_json(partial)
            return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []
    return []


def collect_row_stats(root: Path, categories: Sequence[str]) -> Dict[str, int]:
    rows = evaluable = non_evaluable = 0
    for category in categories:
        shards_root = root / "shards" / category
        if not shards_root.exists():
            continue
        for shard_dir in sorted(shards_root.glob("shard_*")):
            for row in read_shard_rows(shard_dir):
                rows += 1
                if row.get("evaluation_status") == "evaluable":
                    evaluable += 1
                else:
                    non_evaluable += 1
    return {"rows": rows, "evaluable": evaluable, "non_evaluable": non_evaluable}


def print_monitor(
    root: Path,
    *,
    label: str,
    done: int,
    total: int,
    running: int,
    categories: Sequence[str],
    expected_rows: int,
) -> None:
    stats = collect_row_stats(root, categories)
    print(
        f"[sharded:{label}] shards_done={done}/{total} running={running} "
        f"rows={stats['rows']}/{expected_rows} "
        f"evaluable={stats['evaluable']} non_evaluable={stats['non_evaluable']}",
        flush=True,
    )


def run_pool(
    root: Path,
    *,
    label: str,
    jobs: Sequence[Dict[str, Any]],
    max_workers: int,
    categories: Sequence[str],
    expected_rows: int,
) -> Dict[str, int]:
    """Run shard jobs with at most max_workers concurrent processes.

    On KeyboardInterrupt or any other exception every surviving process group is
    SIGTERMed, then SIGKILLed after a ten second grace period.
    """
    pending = list(jobs)
    running: Dict[str, subprocess.Popen] = {}
    logs: List[Any] = []
    returncodes: Dict[str, int] = {}
    journal = root / "logs" / "sharded_waves.jsonl"
    last_monitor = 0.0
    try:
        while pending or running:
            while pending and len(running) < max_workers:
                job = pending.pop(0)
                job["log_path"].parent.mkdir(parents=True, exist_ok=True)
                log = job["log_path"].open("a", encoding="utf-8")
                logs.append(log)
                env = dict(os.environ)
                process = subprocess.Popen(
                    job["command"],
                    cwd=str(THIS_DIR),
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env=env,
                    start_new_session=True,
                )
                running[job["name"]] = process
                append_jsonl(
                    journal,
                    {
                        "timestamp": datetime.now().isoformat(),
                        "wave": label,
                        "shard": job["name"],
                        "category": job["category"],
                        "sink_port": job["sink_port"],
                        "pid": process.pid,
                        "command": job["command"],
                    },
                )
            time.sleep(2)
            for name, process in list(running.items()):
                code = process.poll()
                if code is not None:
                    returncodes[name] = int(code)
                    del running[name]
            now = time.monotonic()
            if now - last_monitor >= MONITOR_INTERVAL:
                last_monitor = now
                print_monitor(
                    root,
                    label=label,
                    done=len(returncodes),
                    total=len(jobs),
                    running=len(running),
                    categories=categories,
                    expected_rows=expected_rows,
                )
        print_monitor(
            root,
            label=label,
            done=len(returncodes),
            total=len(jobs),
            running=0,
            categories=categories,
            expected_rows=expected_rows,
        )
        print(f"[sharded:{label}] returncodes={returncodes}", flush=True)
        return returncodes
    finally:
        live = [process for process in running.values() if process.poll() is None]
        for process in live:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
        if live:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and any(
                process.poll() is None for process in live
            ):
                time.sleep(0.2)
        for process in live:
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
        for process in running.values():
            process.wait()
        for log in logs:
            log.close()


def error_round_jobs(shards: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Select shards that still need work and build their resume commands."""
    jobs: List[Dict[str, Any]] = []
    for shard in shards:
        rows = read_shard_rows(shard["shard_dir"])
        non_evaluable = sum(row.get("evaluation_status") != "evaluable" for row in rows)
        missing = len(rows) < shard["attack_count"]
        if not non_evaluable and not missing:
            continue
        job = dict(shard)
        command = list(shard["command"])
        run_dir = resolve_run_dir(shard["shard_dir"])
        resumable = (
            run_dir is not None
            and (run_dir / "selection.json").exists()
            and (run_dir / "openclaw_workspace_backup.json").exists()
        )
        if resumable:
            command.extend(["--resume-run", str(run_dir), "--rerun-errors"])
        job["command"] = command
        jobs.append(job)
    return jobs


def preflight_ports(jobs: Sequence[Dict[str, Any]]) -> List[int]:
    return sorted({job["sink_port"] for job in jobs if not port_available(job["sink_port"])})


def build_manifest(
    root: Path,
    shards: Sequence[Dict[str, Any]],
    *,
    categories: Sequence[str],
    shard_size: int,
    max_workers: int,
    limit_per_category: Optional[int],
    self_test: bool,
) -> Dict[str, Any]:
    return {
        "orchestrator_version": MANIFEST_VERSION,
        "created_at": datetime.now().isoformat(),
        "experiment_root": str(root),
        "categories": list(categories),
        "dataset": str(DATASET),
        "dataset_sha256": sha256_file(DATASET),
        "runner": str(ORIGINAL_RUNNER),
        "runner_sha256": sha256_file(ORIGINAL_RUNNER),
        "source_openclaw_config_sha256": sha256_file(SOURCE_CONFIG),
        "model_profile": MODEL_PROFILE,
        "model_profiles_sha256": sha256_file(model_profiles.PROFILE_PATH),
        "model_adapter_sha256": sha256_file(Path(model_profiles.__file__)),
        "source_openclaw_config": str(SOURCE_CONFIG),
        "openclaw_model": model_profiles.PROFILES[MODEL_PROFILE]["openclaw_model"],
        "judge_model": model_profiles.PROFILES[MODEL_PROFILE]["judge_model"],
        "judge_api": model_profiles.PROFILES[MODEL_PROFILE]["judge_api"],
        "judge_max_output_tokens": model_profiles.PROFILES[MODEL_PROFILE]["judge_max_output_tokens"],
        "timeout": model_profiles.PROFILES[MODEL_PROFILE]["timeout"],
        "case_transport_retries": 0,
        "max_error_rounds": MAX_ERROR_ROUNDS,
        "monitor_interval": MONITOR_INTERVAL,
        "execution_topology": {
            "mode": "sharded",
            "shard_size": shard_size,
            "max_workers": max_workers,
            "sink_port_base": SINK_PORT_BASE,
            "shard_count": len(shards),
            "limit_per_category": limit_per_category,
            "self_test": self_test,
        },
        "commands": [
            {
                "shard": shard["name"],
                "category": shard["category"],
                "shard_index": shard["shard_index"],
                "global_index": shard["global_index"],
                "sink_port": shard["sink_port"],
                "attack_count": shard["attack_count"],
                "attack_ids": shard["attack_ids"],
                "run_root": str(shard["shard_dir"]),
                "openclaw_workspace": str(shard["workspace"]),
                "log": str(shard["log_path"]),
                "command": shard["command"],
            }
            for shard in shards
        ],
    }


def merge_results(root: Path, *, strict: bool) -> Dict[str, Any]:
    """Merge shard outputs into per-category run dirs and root-level results."""
    runner = load_runner()
    legacy = runner.legacy
    dataset = load_jsonl(DATASET)
    dataset_sha256 = sha256_file(DATASET)
    merge_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    category_runs: Dict[str, str] = {}
    combined: List[Dict[str, Any]] = []
    for category in CATEGORIES:
        shards_root = root / "shards" / category
        shard_dirs = (
            sorted(shards_root.glob("shard_*")) if shards_root.exists() else []
        )
        if not shard_dirs:
            if strict:
                raise RuntimeError(f"missing shard outputs for category {category}")
            continue
        expected = [row for row in dataset if row.get("resource_category") == category]
        expected_ids = [str(row["attack_id"]) for row in expected]
        by_attack_id: Dict[str, Dict[str, Any]] = {}
        for shard_dir in shard_dirs:
            for row in read_shard_rows(shard_dir):
                attack_id = row.get("attack_id")
                if attack_id:
                    by_attack_id[str(attack_id)] = row
        unknown = sorted(set(by_attack_id) - set(expected_ids))
        if unknown:
            raise RuntimeError(f"{category}: shard rows not in dataset: {unknown[:10]}")
        ordered: List[Dict[str, Any]] = []
        for case in expected:
            attack_id = str(case["attack_id"])
            row = by_attack_id.get(attack_id)
            if row is None:
                continue
            expected_sha = runner.stable_sha256(case)
            if row.get("case_sha256") != expected_sha:
                raise RuntimeError(f"case fingerprint mismatch: {attack_id}")
            ordered.append(row)
        if strict and len(ordered) != len(expected):
            raise RuntimeError(
                f"{category} has {len(ordered)} merged rows, expected {len(expected)}"
            )
        if not ordered:
            continue
        merge_dir = root / "categories" / category / merge_timestamp
        summary = legacy.summarize(ordered)
        summary["evaluable"] = sum(
            row.get("evaluation_status") == "evaluable" for row in ordered
        )
        summary["non_evaluable"] = sum(
            row.get("evaluation_status") == "non_evaluable" for row in ordered
        )
        output = {
            "timestamp": datetime.now().isoformat(),
            "run_dir": str(merge_dir),
            "runner_version": runner.RUNNER_VERSION,
            "protocol": runner.PROTOCOL,
            "dataset_sha256": dataset_sha256,
            "summary": summary,
            "results": ordered,
        }
        write_json(merge_dir / "results.json", output)
        write_json(merge_dir / "results_partial.json", ordered)
        merged_ids = {row["attack_id"] for row in ordered}
        selection = [
            {
                "attack_id": str(case["attack_id"]),
                "case_sha256": runner.stable_sha256(case),
            }
            for case in expected
            if str(case["attack_id"]) in merged_ids
        ]
        write_json(merge_dir / "selection.json", selection)
        category_runs[category] = str(merge_dir)
        combined.extend(ordered)

    combined.sort(key=lambda row: str(row.get("attack_id")))
    if strict:
        expected_all = {str(row["attack_id"]) for row in dataset}
        merged_all = {str(row.get("attack_id")) for row in combined}
        if merged_all != expected_all:
            missing = sorted(expected_all - merged_all)[:20]
            extra = sorted(merged_all - expected_all)[:20]
            raise RuntimeError(
                f"combined selection mismatch: missing={missing} extra={extra}"
            )
    summary = legacy.summarize(combined)
    summary["evaluable"] = sum(
        row.get("evaluation_status") == "evaluable" for row in combined
    )
    summary["non_evaluable"] = sum(
        row.get("evaluation_status") == "non_evaluable" for row in combined
    )
    summary["by_evaluation_status"] = dict(
        sorted(Counter(str(row.get("evaluation_status", "unknown")) for row in combined).items())
    )
    summary["by_success_level"] = dict(
        sorted(Counter(str(row.get("attack_success_level")) for row in combined).items())
    )
    output = {
        "timestamp": datetime.now().isoformat(),
        "orchestrator_version": ORCHESTRATOR_VERSION,
        "runner_version": runner.RUNNER_VERSION,
        "protocol": runner.PROTOCOL,
        "dataset": str(DATASET),
        "dataset_sha256": dataset_sha256,
        "category_runs": category_runs,
        "summary": summary,
        "results": combined,
    }
    write_json(root / "results.json", output)
    with (root / "results.jsonl").open("w", encoding="utf-8") as handle:
        for row in combined:
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
    (root / "summary.md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return output


def load_manifest(root: Path) -> Dict[str, Any]:
    global MODEL_PROFILE, SOURCE_CONFIG, SINK_PORT_BASE, MAX_ERROR_ROUNDS, MONITOR_INTERVAL, _RUNNER
    manifest_path = root / "experiment_manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"missing experiment manifest: {manifest_path}")
    manifest = load_json(manifest_path)
    MODEL_PROFILE = manifest["model_profile"]
    SOURCE_CONFIG = Path(manifest["source_openclaw_config"])
    SINK_PORT_BASE = int(manifest["execution_topology"]["sink_port_base"])
    MAX_ERROR_ROUNDS = int(manifest["max_error_rounds"])
    MONITOR_INTERVAL = int(manifest["monitor_interval"])
    _RUNNER = None
    current = {
        "orchestrator_version": MANIFEST_VERSION,
        "dataset_sha256": sha256_file(DATASET),
        "runner_sha256": sha256_file(ORIGINAL_RUNNER),
        "source_openclaw_config_sha256": sha256_file(SOURCE_CONFIG),
        "model_profiles_sha256": sha256_file(model_profiles.PROFILE_PATH),
        "model_adapter_sha256": sha256_file(Path(model_profiles.__file__)),
    }
    drift = {key: {"previous": manifest.get(key), "current": value}
             for key, value in current.items() if manifest.get(key) != value}
    if drift:
        raise SystemExit("experiment configuration changed: " + json.dumps(drift, sort_keys=True))
    return manifest


def plan_from_manifest(root: Path, manifest: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    topology = manifest.get("execution_topology") or {}
    shards = build_shard_plan(
        root,
        categories=manifest.get("categories", list(CATEGORIES)),
        shard_size=int(topology.get("shard_size", SHARD_SIZE)),
        limit_per_category=topology.get("limit_per_category"),
    )
    return shards, topology


def run_error_rounds(
    root: Path,
    *,
    shards: Sequence[Dict[str, Any]],
    max_workers: int,
    categories: Sequence[str],
    expected_rows: int,
    max_rounds: int,
) -> None:
    for round_index in range(1, max_rounds + 1):
        jobs = error_round_jobs(shards)
        if not jobs:
            break
        busy = preflight_ports(jobs)
        if busy:
            raise RuntimeError(f"sink ports still in use before error round: {busy}")
        print(
            f"[sharded] error round {round_index}: {len(jobs)} shard(s) need rerun",
            flush=True,
        )
        run_pool(
            root,
            label=f"errors-{round_index}",
            jobs=jobs,
            max_workers=max_workers,
            categories=categories,
            expected_rows=expected_rows,
        )


def finish(root: Path, *, strict: bool) -> int:
    output = merge_results(root, strict=strict)
    print(json.dumps(output["summary"], ensure_ascii=False, indent=2), flush=True)
    print(f"[sharded] results: {root / 'results.json'}", flush=True)
    leftover = sum(
        row.get("evaluation_status") != "evaluable" for row in output["results"]
    )
    return 4 if leftover else 0


def cmd_start(args: argparse.Namespace) -> int:
    global MODEL_PROFILE, SOURCE_CONFIG, SINK_PORT_BASE, MAX_ERROR_ROUNDS, MONITOR_INTERVAL, _RUNNER
    _RUNNER = None
    MODEL_PROFILE = args.model_profile
    SOURCE_CONFIG = args.openclaw_config.expanduser().resolve()
    SINK_PORT_BASE = args.sink_port_base
    MAX_ERROR_ROUNDS = args.max_error_rounds
    MONITOR_INTERVAL = args.monitor_interval
    if args.shard_size < 1 or args.max_workers < 1 or args.monitor_interval < 1 or args.max_error_rounds < 0:
        raise SystemExit("shard size, worker count, and monitor interval must be positive; error rounds must be nonnegative")
    root = args.root.expanduser().resolve()
    manifest_path = root / "experiment_manifest.json"
    if manifest_path.exists():
        raise SystemExit(f"experiment already exists; resume it instead: {root}")
    self_test = bool(args.self_test)
    categories = ("material",) if self_test else CATEGORIES
    shard_size = 1 if self_test else args.shard_size
    max_workers = 2 if self_test else args.max_workers
    limit_per_category = 2 if self_test else None
    shards = build_shard_plan(
        root,
        categories=categories,
        shard_size=shard_size,
        limit_per_category=limit_per_category,
    )
    if not shards:
        raise SystemExit("empty shard plan; nothing to run")
    manifest = build_manifest(
        root,
        shards,
        categories=categories,
        shard_size=shard_size,
        max_workers=max_workers,
        limit_per_category=limit_per_category,
        self_test=self_test,
    )
    if args.dry_run:
        print(json.dumps(manifest, indent=2))
        return 0
    root.mkdir(parents=True, exist_ok=True)
    write_json(manifest_path, manifest)
    expected_rows = sum(shard["attack_count"] for shard in shards)
    busy = preflight_ports(shards)
    if busy:
        print(f"[preflight error] sink ports are in use: {busy}", file=sys.stderr)
        return 2
    print(
        f"[sharded] initial wave: {len(shards)} shard(s), {expected_rows} case(s), "
        f"max_workers={max_workers}",
        flush=True,
    )
    run_pool(
        root,
        label="initial",
        jobs=shards,
        max_workers=max_workers,
        categories=categories,
        expected_rows=expected_rows,
    )
    if not self_test:
        run_error_rounds(
            root,
            shards=shards,
            max_workers=max_workers,
            categories=categories,
            expected_rows=expected_rows,
            max_rounds=MAX_ERROR_ROUNDS,
        )
    return finish(root, strict=not self_test)


def cmd_resume(args: argparse.Namespace) -> int:
    root = args.root.expanduser().resolve()
    manifest = load_manifest(root)
    shards, topology = plan_from_manifest(root, manifest)
    max_workers = int(topology.get("max_workers", MAX_WORKERS))
    categories = manifest.get("categories", list(CATEGORIES))
    expected_rows = sum(shard["attack_count"] for shard in shards)
    run_error_rounds(
        root,
        shards=shards,
        max_workers=max_workers,
        categories=categories,
        expected_rows=expected_rows,
        max_rounds=MAX_ERROR_ROUNDS,
    )
    return finish(root, strict=not topology.get("self_test"))


def cmd_merge(args: argparse.Namespace) -> int:
    root = args.root.expanduser().resolve()
    manifest = load_manifest(root)
    topology = manifest.get("execution_topology") or {}
    return finish(root, strict=not topology.get("self_test"))


class ShardedArgumentParser(argparse.ArgumentParser):
    """Resolve topology defaults only after the selected profile is known."""

    def parse_args(self, args=None, namespace=None):
        parsed = super().parse_args(args, namespace)
        if getattr(parsed, "subcommand", None) == "start":
            defaults = model_profiles.sharding_defaults(parsed.model_profile)
            for name in ("shard_size", "max_workers", "max_error_rounds", "monitor_interval", "sink_port_base"):
                if getattr(parsed, name) is None:
                    setattr(parsed, name, defaults[name])
        return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = ShardedArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="subcommand", required=True)
    start = subparsers.add_parser("start", help="create the experiment root and run all shards")
    start.add_argument("--root", type=Path, required=True)
    start.add_argument("--model-profile", choices=model_profiles.PROFILE_NAMES, default=model_profiles.DEFAULT_SHARDED_PROFILE)
    start.add_argument("--openclaw-config", type=Path, default=DEFAULT_SOURCE_CONFIG)
    start.add_argument("--shard-size", type=int, help="Cases per shard; defaults to the selected profile's shard configuration")
    start.add_argument("--max-workers", type=int, help="Concurrent shard workers; defaults to the shard configuration")
    start.add_argument("--max-error-rounds", type=int, help="Error rerun rounds; defaults to the shard configuration")
    start.add_argument("--monitor-interval", type=int, help="Progress interval in seconds; defaults to the shard configuration")
    start.add_argument("--sink-port-base", type=int, help="First local sink port; defaults to the shard configuration")
    start.add_argument("--dry-run", action="store_true", help="Print the exact shard plan without running agents")
    start.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    start.set_defaults(handler=cmd_start)
    resume = subparsers.add_parser("resume", help="error rounds + merge for an existing root")
    resume.add_argument("--root", type=Path, required=True)
    resume.set_defaults(handler=cmd_resume)
    merge = subparsers.add_parser("merge", help="merge shard outputs only")
    merge.add_argument("--root", type=Path, required=True)
    merge.set_defaults(handler=cmd_merge)
    return parser


def main() -> int:
    args = build_parser().parse_args()
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
        return args.handler(args)
    except KeyboardInterrupt as error:
        print(
            f"[sharded] interrupted: {error}; resume with: "
            f"{Path(__file__).name} resume --root {args.root.expanduser().resolve()}",
            file=sys.stderr,
        )
        return 130 if stop_requested else 1
    finally:
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
