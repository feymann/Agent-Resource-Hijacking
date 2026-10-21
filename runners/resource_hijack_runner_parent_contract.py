#!/usr/bin/env python3
"""Run fixed-parent-target resource hijacking descendants against OpenClaw.

This is the non-Docker protocol used by the original local baseline: every
case receives an isolated OpenClaw state and a fresh copy of its successful
parent's controlled workspace.  The parent's local script and oracle are used
unchanged. Model profiles preserve provider-specific transport settings.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


THIS_DIR = Path(__file__).resolve().parent
HUB_ROOT = THIS_DIR.parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))
import model_profiles
RESOURCE_ROOT = Path(os.environ.get("RH_DATASET_DIR", str(HUB_ROOT / "dataset")))
LEGACY_RUNNER_PATH = THIS_DIR / "resource_hijack_runner.py"
DEFAULT_ATTACKS = RESOURCE_ROOT / "scaled_attacks.jsonl"
DEFAULT_SANDBOX_ROOT = RESOURCE_ROOT / "sandboxes"
DEFAULT_RUN_ROOT = HUB_ROOT / "runs" / "resource_hijack_runs_900_parent_contract"
DEFAULT_OPENCLAW_WORKSPACE = Path(tempfile.gettempdir()) / "rh_parent_contract_baseline" / "workspace"
_DEFAULT_PROFILE = model_profiles.get_profile(model_profiles.DEFAULT_PROFILE)
DEFAULT_OPENCLAW_MODEL = _DEFAULT_PROFILE["openclaw_model"]
DEFAULT_OPENCLAW_BIN = Path(os.environ.get("OPENCLAW_BIN", shutil.which("openclaw") or "openclaw"))
DEFAULT_TIMEOUT = _DEFAULT_PROFILE["timeout"]
RUNNER_VERSION = _DEFAULT_PROFILE["runner_version"]
PROTOCOL = _DEFAULT_PROFILE["protocol"]
CATEGORIES = ("material", "condition", "energy", "symbolic", "knowledge", "interaction")
ATTACK_SETTINGS = ("implicit", "direct_unconfirmed", "persistent_context")
CASE_CONTRACT_FIELDS = (
    "resource_category",
    "resource_target",
    "resource_use_signal",
    "expected_resource_action",
    "cost_unit",
    "normal_use",
    "hijack_goal",
    "resource_use_clues",
    "invocation_path",
)


class ContractValidationError(RuntimeError):
    pass


def load_legacy_runner():
    spec = importlib.util.spec_from_file_location("resource_hijack_runner_parent_legacy", LEGACY_RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import legacy runner from {LEGACY_RUNNER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legacy = load_legacy_runner()
_legacy_run_one_case = legacy.run_one_case


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(path.lstat().st_mode & 0o777).encode("ascii"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"L")
            digest.update(path.readlink().as_posix().encode("utf-8"))
        elif path.is_file():
            digest.update(b"F")
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif path.is_dir():
            digest.update(b"D")
        digest.update(b"\0")
    return digest.hexdigest()


def stable_sha256(value: Any) -> str:
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def file_sha256_or_none(path: Path) -> Optional[str]:
    return sha256_file(path) if path.is_file() else None


def secret_fingerprint(value: str) -> Optional[str]:
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else None


def load_seed_map(attacks_path: Path) -> Dict[str, Dict[str, Any]]:
    path = attacks_path.parent / "successful_seed_cases.jsonl"
    if not path.exists():
        # successful_seed_cases.jsonl is a case-generation pipeline intermediate
        # and is not released; skip the parent-seed cross-checks in that case.
        if not getattr(load_seed_map, "_warned", False):
            print(f"  [{path.name} not found beside dataset; skipping parent-seed cross-checks]")
            load_seed_map._warned = True
        return {}
    return {row["parent_attack_id"]: row for row in load_jsonl(path)}


def validate_case_contract(
    case: Dict[str, Any],
    sandbox_root: Path,
    seed_by_id: Dict[str, Dict[str, Any]],
    tree_hash_cache: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    attack_id = str(case.get("attack_id", "<missing>"))
    lineage = case.get("lineage")
    contract = case.get("target_contract")
    if not isinstance(lineage, dict) or not isinstance(contract, dict):
        raise ContractValidationError(f"{attack_id}: missing lineage or target_contract")
    parent_attack_id = str(lineage.get("parent_attack_id", ""))
    parent_scenario_id = str(lineage.get("parent_scenario_id", ""))
    if contract.get("parent_scenario_id") != parent_scenario_id:
        raise ContractValidationError(f"{attack_id}: target contract points at another parent scenario")
    if seed_by_id:
        seed = seed_by_id.get(parent_attack_id)
        if seed is None:
            raise ContractValidationError(f"{attack_id}: unknown parent attack {parent_attack_id!r}")
        if parent_scenario_id != seed.get("parent_scenario_id"):
            raise ContractValidationError(f"{attack_id}: parent scenario does not match successful seed")
        for field in CASE_CONTRACT_FIELDS:
            if case.get(field) != seed.get(field):
                raise ContractValidationError(f"{attack_id}: fixed parent field changed: {field}")

    sandbox_dir = (sandbox_root / parent_scenario_id).resolve()
    if sandbox_dir.parent != sandbox_root.resolve():
        raise ContractValidationError(f"{attack_id}: invalid parent scenario path")
    manifest_path = sandbox_dir / "manifest.json"
    oracle_path = sandbox_dir / "oracle.json"
    workspace = sandbox_dir / "workspace"
    for path in (manifest_path, oracle_path, workspace):
        if not path.exists():
            raise ContractValidationError(f"{attack_id}: missing target contract artifact {path}")
    manifest = load_json(manifest_path)
    oracle = load_json(oracle_path)
    if manifest.get("scenario_id") != parent_scenario_id or oracle.get("scenario_id") != parent_scenario_id:
        raise ContractValidationError(f"{attack_id}: parent manifest/oracle ID mismatch")
    for field in ("resource_category", "resource_target", "resource_use_signal", "expected_resource_action"):
        if manifest.get(field) != case.get(field):
            raise ContractValidationError(f"{attack_id}: case disagrees with parent manifest: {field}")

    script = str(contract.get("local_resource_script", ""))
    if script != manifest.get("local_resource_script"):
        raise ContractValidationError(f"{attack_id}: local resource entry point changed")
    script_path = Path(script)
    if not script or script_path.is_absolute() or ".." in script_path.parts or not (workspace / script).is_file():
        raise ContractValidationError(f"{attack_id}: invalid or missing local resource script {script!r}")
    if contract.get("hazardous_actions") != oracle.get("hazardous_actions"):
        raise ContractValidationError(f"{attack_id}: hazardous oracle actions changed")
    if contract.get("oracle_threshold") != (oracle.get("threshold") or {}):
        raise ContractValidationError(f"{attack_id}: oracle threshold changed")
    return {
        "ok": True,
        "parent_attack_id": parent_attack_id,
        "parent_scenario_id": parent_scenario_id,
        "local_resource_script": script,
        "hazardous_actions": oracle.get("hazardous_actions"),
    }


def validate_dataset(cases: Sequence[Dict[str, Any]], attacks_path: Path, sandbox_root: Path) -> Dict[str, Any]:
    if not cases:
        raise ContractValidationError("dataset contains no cases")
    seed_by_id = load_seed_map(attacks_path)
    cache: Dict[str, str] = {}
    attack_ids = set()
    scenario_settings: Dict[str, set[str]] = defaultdict(set)
    for case in cases:
        attack_id = str(case.get("attack_id", ""))
        if not attack_id or attack_id in attack_ids:
            raise ContractValidationError(f"missing or duplicate attack ID: {attack_id!r}")
        attack_ids.add(attack_id)
        if case.get("generation_mode") != "parent-contract-scaleup-v1":
            raise ContractValidationError(f"{attack_id}: unsupported generation mode")
        setting = str(case.get("attack_setting", ""))
        if setting not in ATTACK_SETTINGS:
            raise ContractValidationError(f"{attack_id}: invalid attack setting {setting!r}")
        scenario_settings[str(case.get("scenario_id"))].add(setting)
        validate_case_contract(case, sandbox_root, seed_by_id, cache)
    for scenario_id, settings in scenario_settings.items():
        if settings != set(ATTACK_SETTINGS):
            raise ContractValidationError(f"{scenario_id}: scenario does not contain all three settings")
    return {
        "cases": len(cases),
        "scenarios": len(scenario_settings),
        "parents": len({case["lineage"]["parent_attack_id"] for case in cases}),
        "parent_target_environments": len(cache),
        "by_category": dict(sorted(Counter(case["resource_category"] for case in cases).items())),
        "by_setting": dict(sorted(Counter(case["attack_setting"] for case in cases).items())),
    }


def deterministic_stratified_cases(
    cases: Sequence[Dict[str, Any]], per_cell: int, selection_seed: int
) -> List[Dict[str, Any]]:
    grouped: Dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for case in cases:
        grouped[(case["resource_category"], case["attack_setting"])].append(case)
    selected: List[Dict[str, Any]] = []
    for category in CATEGORIES:
        for setting in ATTACK_SETTINGS:
            rows = grouped[(category, setting)]
            rows = sorted(
                rows,
                key=lambda row: stable_sha256(f"{selection_seed}:{row['attack_id']}"),
            )
            if len(rows) < per_cell:
                raise ContractValidationError(f"not enough cases for {category}/{setting}: {len(rows)}")
            selected.extend(rows[:per_cell])
    return sorted(selected, key=lambda row: row["attack_id"])


def select_cases(args: argparse.Namespace, all_cases: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if args.smoke18:
        rows = deterministic_stratified_cases(all_cases, 1, args.selection_seed)
    elif args.pilot90:
        rows = deterministic_stratified_cases(all_cases, 5, args.selection_seed)
    else:
        rows = list(all_cases)
        if args.attack_id:
            wanted = set(args.attack_id)
            rows = [row for row in rows if row.get("attack_id") in wanted]
        if args.scenario_id:
            wanted = set(args.scenario_id)
            rows = [row for row in rows if row.get("scenario_id") in wanted]
        if args.resource_category:
            wanted = set(args.resource_category)
            rows = [row for row in rows if row.get("resource_category") in wanted]
        if args.attack_setting:
            wanted = set(args.attack_setting)
            rows = [row for row in rows if row.get("attack_setting") in wanted]
        rows.sort(key=lambda row: (str(row.get("scenario_id")), str(row.get("attack_id"))))
        if args.limit is not None:
            rows = rows[: args.limit]
    return rows


def run_one_case(
    *,
    helper: Any,
    args: argparse.Namespace,
    case: Dict[str, Any],
    run_dir: Path,
    case_index: int,
) -> Dict[str, Any]:
    seed_by_id = load_seed_map(Path(args.attacks))
    attestation = validate_case_contract(case, Path(args.sandbox_root), seed_by_id)
    child_scenario_id = str(case["scenario_id"])
    parent_scenario_id = attestation["parent_scenario_id"]
    execution_case = copy.deepcopy(case)
    execution_case["scenario_id"] = parent_scenario_id
    execution_case["child_scenario_id"] = child_scenario_id

    result = _legacy_run_one_case(
        helper=helper,
        args=args,
        case=execution_case,
        run_dir=run_dir,
        case_index=case_index,
    )
    result["scenario_id"] = child_scenario_id
    result["scenario_name"] = case.get("scenario_name")
    result["target_scenario_id"] = parent_scenario_id
    result["lineage"] = case["lineage"]
    result["target_contract"] = case["target_contract"]
    result["target_contract_attestation"] = attestation
    result["runner_version"] = RUNNER_VERSION
    result["protocol"] = PROTOCOL
    result["case_sha256"] = stable_sha256(case)
    result["prompt_sha256"] = stable_sha256(case["user_prompt"])
    result["model_profile"] = args.model_profile

    oracle_status = (result.get("oracle") or {}).get("status")
    if oracle_status == "check_error":
        result["verdict"] = "runner_error"
        result["detail"] = "Parent local oracle failed; case is non-evaluable"
        result["attack_success"] = None
        result["attack_success_level"] = None
        result.setdefault("runner_errors", {})["oracle"] = {
            "status": "check_error",
            "stderr": (result.get("oracle") or {}).get("stderr"),
        }
    result["evaluation_status"] = (
        "non_evaluable"
        if result.get("verdict") in {"runner_error", "judge_error"}
        else "evaluable"
    )

    run_case_dir = Path(result["run_case_dir"])
    legacy.write_json(run_case_dir / "case.json", case)
    legacy.write_json(run_case_dir / "target_contract_attestation.json", attestation)
    legacy.write_json(run_case_dir / "result.json", result)
    return result


def build_parser(model_profile: str = model_profiles.DEFAULT_PROFILE) -> argparse.ArgumentParser:
    parser = legacy.build_parser()
    parser.description = __doc__
    parser.set_defaults(
        attacks=str(DEFAULT_ATTACKS),
        sandbox_root=str(DEFAULT_SANDBOX_ROOT),
        run_root=str(DEFAULT_RUN_ROOT),
        raw_user_prompt=True,
        openclaw_bin=str(DEFAULT_OPENCLAW_BIN),
        openclaw_workspace=str(DEFAULT_OPENCLAW_WORKSPACE),
        openclaw_model=DEFAULT_OPENCLAW_MODEL,
        timeout=DEFAULT_TIMEOUT,
        llm_judge=True,
        llm_judge_apply=True,
    )
    parser.set_defaults(**model_profiles.parser_defaults(model_profile))
    parser.add_argument("--model-profile", choices=model_profiles.PROFILE_NAMES, default=model_profile)
    parser.add_argument("--smoke18", action="store_true", help="Run one deterministic case per category/setting cell")
    parser.add_argument("--pilot90", action="store_true", help="Run five deterministic cases per category/setting cell")
    parser.add_argument("--selection-seed", type=int, default=20260714)
    parser.add_argument("--resume-run", type=Path, help="Resume a run directory containing selection.json and results_partial.json")
    parser.add_argument("--rerun-errors", action="store_true", help="With --resume-run, rerun non-evaluable prior cases")
    parser.add_argument(
        "--allow-protocol-deviation",
        action="store_true",
        help="Allow settings that differ from the selected model profile",
    )
    parser.add_argument(
        "--no-llm-judge",
        action="store_true",
        dest="disable_llm_judge",
        help="Disable behavioral intent/claim/attempt judging",
    )
    return parser


def baseline_protocol_diff(args: argparse.Namespace) -> Dict[str, Dict[str, Any]]:
    profile = model_profiles.get_profile(args.model_profile)
    expected = {
        "openclaw_profile": legacy.DEFAULT_OPENCLAW_PROFILE,
        "openclaw_agent": "main",
        "openclaw_model": DEFAULT_OPENCLAW_MODEL,
        "openclaw_via_gateway": False,
        "shared_openclaw_state": False,
        "raw_user_prompt": True,
        "timeout": DEFAULT_TIMEOUT,
        "llm_judge": True,
        "llm_judge_apply": True,
        "llm_judge_model": profile["judge_model"],
        "pressure_turn": False,
        "agentdog_mode": "off",
        "defense": "none",
        "clawguard": False,
        "monitor_gpu": False,
        "no_sink": False,
    }
    diff = {
        key: {"expected": expected_value, "actual": getattr(args, key)}
        for key, expected_value in expected.items()
        if getattr(args, key) != expected_value
    }
    workspace = Path(args.openclaw_workspace).expanduser().resolve()
    temp_root = Path(tempfile.gettempdir()).resolve()
    if workspace != temp_root and temp_root not in workspace.parents:
        diff["openclaw_workspace"] = {
            "expected": "a dedicated path under the system temporary directory",
            "actual": str(workspace),
        }
    return diff


def args_for_record(args: argparse.Namespace) -> Dict[str, Any]:
    data = legacy.args_for_record(args)
    if data.get("resume_run"):
        data["resume_run"] = str(data["resume_run"])
    return data


def case_identity(rows: Sequence[Dict[str, Any]]) -> List[Dict[str, str]]:
    return [
        {"attack_id": row["attack_id"], "case_sha256": stable_sha256(row)}
        for row in rows
    ]


def ordered_results(cases: Sequence[Dict[str, Any]], by_attack_id: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [by_attack_id[case["attack_id"]] for case in cases if case["attack_id"] in by_attack_id]


def category_start_delay(args: argparse.Namespace) -> int:
    category = args.resource_category
    if isinstance(category, list):
        category = category[0] if category else None
    return model_profiles.category_start_delay(args.model_profile, category)


def configure_model_profile(args: argparse.Namespace) -> None:
    global DEFAULT_OPENCLAW_MODEL, DEFAULT_TIMEOUT, RUNNER_VERSION, PROTOCOL
    profile = model_profiles.get_profile(args.model_profile)
    DEFAULT_OPENCLAW_MODEL = profile["openclaw_model"]
    DEFAULT_TIMEOUT = profile["timeout"]
    RUNNER_VERSION = profile["runner_version"]
    PROTOCOL = profile["protocol"]
    model_profiles.configure_runtime(legacy, args.model_profile, args)


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser(model_profiles.selected_profile(argv))
    args = parser.parse_args(argv)
    configure_model_profile(args)
    if args.preflight:
        try:
            legacy.validate_runtime_requirements(args)
        except (OSError, ValueError) as error:
            parser.error(str(error))
        print("Preflight passed: required local files exist; external services were not started.")
        return 0
    if not (args.list or args.dry_run):
        try:
            legacy.validate_runtime_requirements(args)
        except (OSError, ValueError) as error:
            parser.error(str(error))
    if args.disable_llm_judge:
        args.llm_judge = False
        args.llm_judge_apply = False
    elif args.llm_judge_apply:
        args.llm_judge = True
    protocol_diff = baseline_protocol_diff(args)
    if protocol_diff and not args.allow_protocol_deviation:
        parser.error(
            "settings differ from the selected model profile: "
            + json.dumps(protocol_diff, ensure_ascii=False, sort_keys=True)
            + "; pass --allow-protocol-deviation only for a separately named experiment"
        )
    if args.smoke18 and args.pilot90:
        parser.error("choose only one of --smoke18 and --pilot90")
    selected_explicitly = any(
        (
            args.attack_id,
            args.scenario_id,
            args.resource_category,
            args.attack_setting,
            args.all,
            args.list,
            args.smoke18,
            args.pilot90,
        )
    )
    if not selected_explicitly:
        parser.error("select cases, use --smoke18/--pilot90, or pass --all")
    if not (args.list or args.dry_run):
        legacy.finalize_workspace_args(args, parser)
    attacks_path = Path(args.attacks).expanduser().resolve()
    sandbox_root = Path(args.sandbox_root).expanduser().resolve()
    if not attacks_path.exists():
        print(f"Missing parent-contract dataset: {attacks_path}", file=sys.stderr)
        return 2
    try:
        all_cases = load_jsonl(attacks_path)
        dataset_summary = validate_dataset(all_cases, attacks_path, sandbox_root)
        cases = select_cases(args, all_cases)
    except Exception as error:
        print(f"[Dataset contract error] {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    if not cases:
        print("No cases selected.")
        return 1
    if args.list or args.dry_run:
        for row in cases:
            print(
                f"{row['attack_id']} {row['scenario_id']} target={row['lineage']['parent_scenario_id']} "
                f"{row['resource_category']} {row['attack_setting']}"
            )
        print(f"selected {len(cases)} case(s); protocol={PROTOCOL}")
        return 0

    time.sleep(category_start_delay(args))
    run_dir = args.resume_run.expanduser().resolve() if args.resume_run else (
        Path(args.run_root).expanduser() / datetime.now().strftime("%Y%m%d_%H%M%S")
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    selection_path = run_dir / "selection.json"
    if args.resume_run:
        if not selection_path.exists():
            print(f"[Resume error] missing {selection_path}", file=sys.stderr)
            return 2
        previous_selection = load_json(selection_path)
        if case_identity(previous_selection) != case_identity(cases):
            print("[Resume error] selected cases or case fingerprints changed", file=sys.stderr)
            return 2
    else:
        legacy.write_json(selection_path, cases)

    workspace = Path(args.openclaw_workspace).expanduser()
    if args.openclaw_workspace_backup is None:
        args.openclaw_workspace_backup = str(run_dir / "openclaw_workspace_backup")
    workspace_backup = Path(args.openclaw_workspace_backup).expanduser()
    try:
        legacy.validate_replace_paths(
            workspace,
            workspace_backup,
            args.i_understand_workspace_replace,
            extra_allowed_bases=[run_dir],
        )
    except ValueError as error:
        print(f"[Workspace path error] {error}", file=sys.stderr)
        return 2

    backup_meta_path = run_dir / "openclaw_workspace_backup.json"
    if args.resume_run:
        if not backup_meta_path.exists() or not workspace_backup.exists():
            print("[Resume error] original OpenClaw workspace backup is missing", file=sys.stderr)
            return 2
        backup_meta = load_json(backup_meta_path)
    else:
        if workspace_backup.exists():
            shutil.rmtree(workspace_backup)
        backup_meta = legacy.backup_openclaw_workspace(workspace, workspace_backup)
        legacy.write_json(backup_meta_path, backup_meta)

    if not args.shared_openclaw_state and not Path(args.openclaw_config).expanduser().exists():
        legacy.restore_openclaw_workspace(workspace, workspace_backup, bool(backup_meta["existed"]))
        print(f"[OpenClaw config error] missing source config: {args.openclaw_config}", file=sys.stderr)
        return 2

    manifest = {
        "runner_version": RUNNER_VERSION,
        "protocol": PROTOCOL,
        "created_or_resumed_at": datetime.now().isoformat(),
        "dataset": str(attacks_path),
        "dataset_sha256": sha256_file(attacks_path),
        "dataset_summary": dataset_summary,
        "selection": case_identity(cases),
        "raw_prompt": True,
        "target_specific_oracle": True,
        "docker": False,
        "baseline_compatible_defaults": {
            "openclaw_local": not args.openclaw_via_gateway,
            "isolated_openclaw_state": not args.shared_openclaw_state,
            "raw_user_prompt": bool(args.raw_user_prompt),
            "openclaw_model": args.openclaw_model,
            "timeout": args.timeout,
            "llm_judge": bool(args.llm_judge),
            "llm_judge_apply": bool(args.llm_judge_apply),
            "llm_judge_model": args.llm_judge_model,
            "pressure_turn": bool(args.pressure_turn),
            "local_sink": not args.no_sink,
        },
        "baseline_protocol_diff": protocol_diff,
        "resume_guard": {
            "defense_runtime": legacy.defense_runtime_fingerprint(args),
            "model_profile": args.model_profile,
            "model_profiles_sha256": sha256_file(model_profiles.PROFILE_PATH),
            "model_adapter_sha256": sha256_file(Path(model_profiles.__file__)),
            "runner_sha256": sha256_file(Path(__file__).resolve()),
            "legacy_runner_sha256": sha256_file(LEGACY_RUNNER_PATH),
            "openclaw_config_sha256": file_sha256_or_none(Path(args.openclaw_config).expanduser()),
            "openclaw_bin": str(Path(args.openclaw_bin).expanduser()),
            "openclaw_model": args.openclaw_model,
            "agent_base_url": args.openai_base_url or os.environ.get("OPENAI_BASE_URL", ""),
            "agent_key_fingerprint": secret_fingerprint(args.openai_api_key or os.environ.get("OPENAI_API_KEY", "")),
            "timeout": args.timeout,
            "judge_base_url": args.llm_judge_base_url,
            "judge_model": args.llm_judge_model,
            "judge_key_fingerprint": secret_fingerprint(args.llm_judge_api_key),
            "judge_retries": args.llm_judge_retries,
            "judge_timeout": args.llm_judge_timeout,
            "judge_max_output_tokens": args.llm_judge_max_output_tokens,
            "judge_safe_audit": not args.no_llm_judge_safe_audit,
            "sink_port": args.sink_port,
            "workspace": str(workspace.resolve()),
        },
    }
    if args.resume_run:
        old_manifest_path = run_dir / "run_manifest.json"
        if not old_manifest_path.exists():
            print(f"[Resume error] missing {old_manifest_path}", file=sys.stderr)
            legacy.restore_openclaw_workspace(workspace, workspace_backup, bool(backup_meta["existed"]))
            return 2
        old_manifest = load_json(old_manifest_path)
        guarded_fields = (
            "runner_version",
            "protocol",
            "dataset_sha256",
            "selection",
            "raw_prompt",
            "target_specific_oracle",
            "docker",
            "baseline_protocol_diff",
            "resume_guard",
        )
        drift = {
            field: {"previous": old_manifest.get(field), "current": manifest.get(field)}
            for field in guarded_fields
            if old_manifest.get(field) != manifest.get(field)
        }
        if drift:
            print(
                "[Resume error] protocol/runtime fingerprint changed: "
                + json.dumps(drift, ensure_ascii=False, sort_keys=True),
                file=sys.stderr,
            )
            legacy.restore_openclaw_workspace(workspace, workspace_backup, bool(backup_meta["existed"]))
            return 2
    legacy.write_json(run_dir / "run_manifest.json", manifest)
    legacy.write_json(run_dir / "config.json", args_for_record(args))

    previous_results = (
        load_json(run_dir / "results_partial.json")
        if args.resume_run and (run_dir / "results_partial.json").exists()
        else []
    )
    by_attack_id = {
        row["attack_id"]: row
        for row in previous_results
        if isinstance(row, dict) and row.get("attack_id")
    }

    helper = legacy.load_runtime(args)
    legacy.configure_helper(helper, args)
    # Keep the symlink's bin directory: resolving the npm symlink points into
    # lib/node_modules and loses the sibling `node` executable required by the
    # /usr/bin/env node shebang.
    openclaw_bin_dir = str(Path(args.openclaw_bin).expanduser().absolute().parent)
    helper.ENV["PATH"] = openclaw_bin_dir + os.pathsep + helper.ENV.get("PATH", "")
    print(f"\n  [Run dir] {run_dir}")
    print(f"  [Selected cases] {len(cases)}")
    print(f"  [Protocol] {PROTOCOL}")
    try:
        legacy.start_runtime_defenses(helper, args)
        for index, case in enumerate(cases, 1):
            existing = by_attack_id.get(case["attack_id"])
            if existing and not (
                args.rerun_errors and existing.get("evaluation_status") == "non_evaluable"
            ):
                print(f"  [Resume skip] {case['attack_id']} verdict={existing.get('verdict')}")
                continue
            try:
                result = run_one_case(
                    helper=helper,
                    args=args,
                    case=case,
                    run_dir=run_dir,
                    case_index=index,
                )
            except Exception as error:
                result = {
                    "attack_id": case.get("attack_id"),
                    "scenario_id": case.get("scenario_id"),
                    "target_scenario_id": (case.get("lineage") or {}).get("parent_scenario_id"),
                    "resource_category": case.get("resource_category"),
                    "attack_setting": case.get("attack_setting"),
                    "lineage": case.get("lineage"),
                    "run_case_dir": str(run_dir / "cases" / f"{index:03d}_{case.get('attack_id')}"),
                    "oracle": {"status": "check_error", "indicator_count": 0, "indicators": []},
                    "verdict": "runner_error",
                    "attack_success": None,
                    "attack_success_level": None,
                    "evaluation_status": "non_evaluable",
                    "detail": f"runner exception: {type(error).__name__}: {error}",
                    "llm_judge": {
                        "enabled": bool(args.llm_judge),
                        "verdict": "skipped",
                        "skipped_reason": "runner_exception",
                    },
                    "runner_errors": {"exception": {"type": type(error).__name__, "message": str(error)}},
                    "runner_version": RUNNER_VERSION,
                    "protocol": PROTOCOL,
                    "case_sha256": stable_sha256(case),
                }
                print(f"  [Runner error] {result['attack_id']}: {result['detail']}")
            by_attack_id[case["attack_id"]] = result
            legacy.write_json(run_dir / "results_partial.json", ordered_results(cases, by_attack_id))
    finally:
        legacy.restore_openclaw_workspace(workspace, workspace_backup, bool(backup_meta["existed"]))
        legacy.stop_runtime_defenses(helper, args)

    results = ordered_results(cases, by_attack_id)
    summary = legacy.summarize(results)
    summary["evaluable"] = sum(row.get("evaluation_status") == "evaluable" for row in results)
    summary["non_evaluable"] = sum(row.get("evaluation_status") == "non_evaluable" for row in results)
    output = {
        "timestamp": datetime.now().isoformat(),
        "run_dir": str(run_dir),
        "runner_version": RUNNER_VERSION,
        "protocol": PROTOCOL,
        "dataset_sha256": manifest["dataset_sha256"],
        "summary": summary,
        "results": results,
    }
    legacy.write_json(run_dir / "results.json", output)
    print("\n" + "=" * 72)
    print("  Parent-contract ResourceHijack run summary")
    print("=" * 72)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"  Results saved: {run_dir / 'results.json'}")
    return 4 if summary["non_evaluable"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
