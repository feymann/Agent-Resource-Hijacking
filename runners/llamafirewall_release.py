"""Release adapters for the preserved online LlamaFirewall v5 protocol.

This module does not replace unavailable historical scanner services or the v5
case runner. Inspection is offline; execution requires the original components.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence
import model_profiles


THIS_DIR = Path(__file__).resolve().parent
PROFILE_PATH = THIS_DIR.parent / "configs" / "llamafirewall_profiles.json"
PROFILES = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
DEFAULT_BASE_URL = "https://your-openai-compatible-endpoint.example.com/v1"


def get_base_model_profile(version: str) -> Dict[str, Any]:
    return model_profiles.get_profile(PROFILES[version]["base_model_profile"])


def get_profile(version: str, model: Optional[str] = None) -> Dict[str, Any]:
    protocol = copy.deepcopy(PROFILES[version])
    model = model or protocol["default_model_profile"]
    models = protocol.pop("models")
    if model not in models:
        raise ValueError(f"No historical LlamaFirewall {version} profile is available for {model}")
    return {**protocol, **models[model], "version": version, "model_profile": model}


def dependency_paths(version: str) -> Dict[str, Path]:
    if version != "v5":
        raise ValueError("Only the LlamaFirewall v5 protocol is included")
    return {
        "service": Path(os.environ.get("RH_LLAMAFIREWALL_SERVICE_V5",
                        str(THIS_DIR / "resource_hijack_llamafirewall_service_v5.py"))),
        "case_runner": Path(os.environ.get("RH_LLAMAFIREWALL_V5_RUNNER",
                            str(THIS_DIR / "resource_hijack_runner_parent_contract_llamafirewall_v5.py"))),
        "plugin": Path(os.environ.get("RH_LLAMAFIREWALL_PLUGIN_V5",
                       str(THIS_DIR.parent / "defenses" / "llamafirewall-v5" / "openclaw-plugin"))),
        "source": Path(os.environ.get("RH_LLAMAFIREWALL_ROOT",
                       str(THIS_DIR.parent / "otherdefense" / "PurpleLlama" / "LlamaFirewall"))),
        "openclaw_config": Path(os.environ.get("RH_OPENCLAW_CONFIG",
                                str(THIS_DIR.parent / "configs" / "openclaw.json"))),
    }


def dependency_report(version: str, model: str, mode: str) -> Dict[str, Any]:
    paths = dependency_paths(version)
    required = {"service": paths["service"], "case_runner": paths["case_runner"],
                "openclaw_config": paths["openclaw_config"]}
    for name in ("index.js", "runtime.js", "package.json", "openclaw.plugin.json"):
        required["plugin/" + name] = paths["plugin"] / name
    missing = [name for name, path in required.items() if not path.is_file()]
    binary = os.environ.get("OPENCLAW_BIN", "openclaw")
    if not (Path(binary).is_file() or shutil.which(binary)):
        missing.append("OpenClaw CLI")
    return {
        "mode": mode, "defense": "LlamaFirewall online before-tool-call hook",
        "profile": get_profile(version, model),
        "dependencies": {name: {"path": str(path), "present": path.is_file()}
                         for name, path in required.items()},
        "optional_source_tree": {"path": str(paths["source"]), "present": paths["source"].is_dir()},
        "missing": missing, "ready": not missing,
        "verification": "File availability only; no service import, network call, or model inference.",
        "source_requirement": "Supply the original v5 scanner service and original v5 case runner.",
    }


def _load_module(path: Path, name: str):
    if not path.is_file():
        raise FileNotFoundError(f"Original LlamaFirewall component is missing: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load LlamaFirewall component: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def configure_paths(namespace: Dict[str, Any], version: str) -> None:
    paths = dependency_paths(version)
    namespace.update(SERVICE_PATH=paths["service"], PLUGIN_DIR=paths["plugin"], LLAMAFIREWALL_ROOT=paths["source"])
    if "runtime_fingerprint_paths" in namespace and not namespace.get("_release_fingerprint_installed"):
        original = namespace["runtime_fingerprint_paths"]
        def fingerprint_paths():
            extra = [Path(__file__).resolve(), PROFILE_PATH, paths["case_runner"]]
            return list(dict.fromkeys([*original(), *extra]))
        namespace["runtime_fingerprint_paths"] = fingerprint_paths
        namespace["_release_fingerprint_installed"] = True


def apply_provider_endpoint_config(config_path: Path, state_dir: Path, writer: Any) -> Path:
    """Apply the profile's endpoint and auth overrides without other provider changes."""
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config.setdefault("models", {}).setdefault("providers", {}).setdefault("openai", {})[
        "baseUrl"
    ] = os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL)
    writer(config_path, config)
    auth_path = state_dir / "agents" / "main" / "agent" / "auth-profiles.json"
    auth = json.loads(auth_path.read_text(encoding="utf-8")) if auth_path.exists() else {"version": 1}
    auth.setdefault("profiles", {})["openai:default"] = {
        "type": "api_key", "provider": "openai", "key": os.environ.get("OPENAI_API_KEY", ""),
    }
    writer(auth_path, auth)
    return config_path


def configure_case_profile(namespace: Dict[str, Any], version: str, model: str) -> str:
    """Register the defense profile with its own timeouts and inherited judge behavior."""
    profile = get_profile(version, model)
    runner = namespace["runner"]
    profiles = runner.model_profiles
    name = f"llamafirewall-{version}-{model}"
    data = profiles.get_profile(profile["base_model_profile"])
    data.update({
        "openclaw_model": profile["openclaw_model"],
        "runner_version": profile["runner_version"], "protocol": profile["protocol"],
        "timeout": profile["case_timeout"],
        "judge_max_output_tokens": profile["judge_max_output_tokens"],
    })
    profiles.PROFILES[name] = data
    profiles.PROFILE_NAMES = tuple(profiles.PROFILES)
    runner.DEFAULT_OPENCLAW_MODEL = profile["openclaw_model"]
    runner.RUNNER_VERSION = profile["runner_version"]
    runner.PROTOCOL = profile["protocol"]
    if profile["override_openai_endpoint"] and not namespace.get("_release_provider_adapter_installed"):
        prepare = runner.legacy.prepare_isolated_openclaw_state
        def with_provider_override(**kwargs):
            return apply_provider_endpoint_config(prepare(**kwargs), Path(kwargs["state_dir"]), runner.legacy.write_json)
        runner.legacy.prepare_isolated_openclaw_state = with_provider_override
        namespace["_release_provider_adapter_installed"] = True
    return name


def _release_parser(version: str, model: Optional[str]) -> argparse.ArgumentParser:
    if version != "v5":
        raise ValueError("Only the LlamaFirewall v5 protocol is included")
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--lf-protocol", choices=tuple(PROFILES), default=version)
    parser.add_argument("--model-profile", default=model, help="Agent profile defined for the selected protocol in configs/llamafirewall_profiles.json")
    parser.add_argument("--plan", action="store_true", help="Print the original protocol settings and missing components without running")
    parser.add_argument("--preflight", action="store_true", help="Check local dependency availability; exit 2 if anything is missing")
    parser.add_argument("--llamafirewall-service", type=Path, help="Path to the original scanner service for the selected protocol")
    parser.add_argument("--llamafirewall-v5-runner", type=Path, help="Path to the missing original v5 case runner")
    parser.add_argument("--llamafirewall-root", type=Path, help="Optional original LlamaFirewall source checkout")
    parser.add_argument("--llamafirewall-plugin", type=Path, help="Matching OpenClaw plugin directory")
    return parser


def run_entry(namespace: Dict[str, Any], historical_main: Any, mode: str, version: str,
              argv: Optional[Sequence[str]] = None, default_model: Optional[str] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _release_parser(version, default_model)
    args, remaining = parser.parse_known_args(argv)
    args.model_profile = args.model_profile or PROFILES[args.lf_protocol]["default_model_profile"]
    if "--help" in remaining or "-h" in remaining:
        print(parser.format_help())
        print("Other arguments are passed to the preserved " + mode + " launcher.")
        return 0
    overrides = {
        "RH_LLAMAFIREWALL_SERVICE_V5": args.llamafirewall_service,
        "RH_LLAMAFIREWALL_V5_RUNNER": args.llamafirewall_v5_runner,
        "RH_LLAMAFIREWALL_ROOT": args.llamafirewall_root,
        "RH_LLAMAFIREWALL_PLUGIN_V5": args.llamafirewall_plugin,
    }
    for key, value in overrides.items():
        if value is not None:
            os.environ[key] = str(value.expanduser().resolve())
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--openclaw-config", type=Path)
    config_args, _ = config_parser.parse_known_args(remaining)
    config = config_args.openclaw_config
    if config is not None:
        os.environ["RH_OPENCLAW_CONFIG"] = str(config.expanduser().resolve())
    try:
        report = dependency_report(args.lf_protocol, args.model_profile, mode)
    except (KeyError, ValueError) as error:
        parser.error(str(error))
    inspect_only = args.plan or args.preflight or "--dry-run" in remaining
    if inspect_only or not report["ready"]:
        print(json.dumps(report, indent=2))
        return 2 if (args.preflight or not inspect_only) and not report["ready"] else 0
    if namespace.get("_external_case_pending"):
        module = _load_module(dependency_paths(version)["case_runner"], "llamafirewall_external_v5")
        return run_entry(vars(module), module.main, mode, version, remaining, args.model_profile)
    paths = dependency_paths(version)
    configure_paths(namespace, version)
    profile = get_profile(version, args.model_profile)
    if mode == "case":
        name = configure_case_profile(namespace, version, args.model_profile)
        remaining.extend(["--model-profile", name])
        if profile["override_openai_endpoint"]:
            # Historical endpoint overrides were appended after earlier CLI occurrences.
            remaining.extend(["--openai-base-url", os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL),
                              "--openai-api-key", os.environ.get("OPENAI_API_KEY", ""), "--allow-protocol-deviation"])
    elif mode == "batch":
        orchestrator = namespace["orchestrator"]
        namespace["RUNNER_PATH"] = THIS_DIR / "resource_hijack_runner_parent_contract_llamafirewall.py"
        namespace["ORCHESTRATOR_VERSION"] = profile["orchestrator_version"]
        orchestrator.RUNNER_PATH = namespace["RUNNER_PATH"]
        orchestrator.ORCHESTRATOR_VERSION = profile["orchestrator_version"]
        orchestrator.MODEL_PROFILE = args.model_profile
        orchestrator.SOURCE_CONFIG = paths["openclaw_config"]
        orchestrator.runner.DEFAULT_OPENCLAW_MODEL = profile["openclaw_model"]
        orchestrator.runner.RUNNER_VERSION = profile["runner_version"]
        orchestrator.runner.PROTOCOL = profile["protocol"]
        original = namespace["_base_build_category_command"]
        def command(**kwargs):
            return original(**kwargs) + ["--lf-protocol", version]
        namespace["_base_build_category_command"] = command
    previous = sys.argv
    sys.argv = [previous[0], *remaining]
    try:
        return historical_main()
    finally:
        sys.argv = previous


def launch(mode: str, version: str, model: Optional[str] = None, argv: Optional[Sequence[str]] = None) -> int:
    """Shared protocol dispatcher with configuration-selected model behavior."""
    if version != "v5":
        raise ValueError("Only the LlamaFirewall v5 protocol is included")
    args = list(sys.argv[1:] if argv is None else argv)
    if mode == "case":
        # Parse component overrides and inspect before importing external code.
        return run_entry({"_external_case_pending": True}, None, mode, version, args, model)
    else:
        filenames = {
            "batch": "run_parent_contract_llamafirewall_v5.py",
        }
        if mode not in filenames:
            raise ValueError(f"Unknown LlamaFirewall launcher mode: {mode}")
        filename = filenames[mode]
        module = _load_module(THIS_DIR / filename, f"llamafirewall_release_{mode}_{version}_{model}")
    return run_entry(vars(module), getattr(module, "_historical_main", module.main), mode, version, args, model)
