"""Shared model configuration and the required judge transport adapter."""

from __future__ import annotations

import argparse
import copy
import functools
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Sequence


PROFILE_PATH = Path(__file__).resolve().parents[1] / "configs" / "model_profiles.json"
_CONFIG = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
DEFAULTS = _CONFIG["defaults"]
PROFILES = _CONFIG["profiles"]
PROFILE_NAMES = tuple(PROFILES)
DEFAULT_PROFILE = DEFAULTS["baseline_profile"]
DEFAULT_SHARDED_PROFILE = DEFAULTS["sharded_profile"]
DEFAULT_BASE_URL = "https://your-openai-compatible-endpoint.example.com/v1"


def get_profile(name: str) -> Dict[str, Any]:
    """Return an independent copy so applying a profile cannot mutate defaults."""
    return copy.deepcopy(PROFILES[name])


def sharding_defaults(name: Optional[str] = None) -> Dict[str, Any]:
    """Combine shared scheduling defaults with optional profile-specific settings."""
    return {
        **copy.deepcopy(DEFAULTS["sharding"]),
        **get_profile(name or DEFAULT_SHARDED_PROFILE).get("sharding", {}),
    }


def selected_profile(argv: Optional[Sequence[str]] = None) -> str:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--model-profile", choices=PROFILE_NAMES, default=DEFAULT_PROFILE)
    return parser.parse_known_args(argv)[0].model_profile


def parser_defaults(name: str) -> Dict[str, Any]:
    profile = get_profile(name)
    defaults = {
        "openclaw_model": profile["openclaw_model"],
        "timeout": profile["timeout"],
        "model_profile": name,
        "llm_judge_model": profile["judge_model"],
        "llm_judge_timeout": profile["judge_timeout"],
        "llm_judge_retries": profile["judge_retries"],
        "llm_judge_max_output_tokens": profile["judge_max_output_tokens"],
    }
    if profile.get("override_openai_endpoint"):
        defaults.update(
            openai_base_url=os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL),
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
        )
    if profile["judge_api"] == "chat-completions":
        defaults.update(
            llm_judge_base_url=os.environ.get("JUDGE_BASE_URL") or os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL),
            llm_judge_api_key=os.environ.get("JUDGE_API_KEY") or os.environ.get("OPENAI_API_KEY", ""),
            llm_judge_model=profile["judge_model"],
            llm_judge_max_output_tokens=profile["judge_max_output_tokens"],
        )
    return defaults


def apply_model_config(
    config: Dict[str, Any], name: str, *, base_url: str, api_key: str
) -> Dict[str, Any]:
    """Apply only the changes made by the corresponding model adapter."""
    profile = get_profile(name)
    if profile.get("override_openai_endpoint"):
        provider = config.setdefault("models", {}).setdefault("providers", {}).setdefault("openai", {})
        provider["baseUrl"] = base_url
    if profile.get("extra_model"):
        provider = config.setdefault("models", {}).setdefault("providers", {}).setdefault("openai", {})
        models = provider.setdefault("models", [])
        if not isinstance(models, list):
            raise TypeError("models.providers.openai.models must be a list")
        extra = profile["extra_model"]
        provider["models"] = [
            model for model in models
            if not isinstance(model, dict) or model.get("id") != extra["id"]
        ] + [extra]
    if profile.get("provider_config"):
        provider = profile["provider_config"]
        provider["baseUrl"] = base_url
        provider["apiKey"] = api_key
        config.setdefault("models", {}).setdefault("providers", {})[profile["provider_name"]] = provider
        defaults = config.setdefault("agents", {}).setdefault("defaults", {})
        defaults.setdefault("models", {}).setdefault(profile["openclaw_model"], {})
    return config


def configure_runtime(legacy: Any, name: str, args: argparse.Namespace) -> None:
    """Install one profile on a freshly loaded runner, without stacking adapters."""
    if not hasattr(legacy, "_profile_base_prepare"):
        legacy._profile_base_prepare = legacy.prepare_isolated_openclaw_state
        legacy._profile_base_judge = legacy.call_llm_judge_responses
    profile = get_profile(name)
    base_url = args.openai_base_url or os.environ.get("OPENAI_BASE_URL", DEFAULT_BASE_URL)
    api_key = args.openai_api_key or os.environ.get("OPENAI_API_KEY", "")

    def prepare(**kwargs: Any) -> Path:
        config_path = legacy._profile_base_prepare(**kwargs)
        config = json.loads(config_path.read_text(encoding="utf-8"))
        legacy.write_json(config_path, apply_model_config(config, name, base_url=base_url, api_key=api_key))
        if profile.get("override_openai_endpoint"):
            auth_path = Path(kwargs["state_dir"]) / "agents" / args.openclaw_agent / "agent" / "auth-profiles.json"
            auth = json.loads(auth_path.read_text(encoding="utf-8")) if auth_path.exists() else {"version": 1}
            auth.setdefault("profiles", {})["openai:default"] = {
                "type": "api_key", "provider": "openai", "key": api_key,
            }
            legacy.write_json(auth_path, auth)
        return config_path

    legacy.prepare_isolated_openclaw_state = prepare
    legacy.call_llm_judge_responses = (
        functools.partial(call_llm_judge_chat_completions, legacy=legacy)
        if profile["judge_api"] == "chat-completions"
        else legacy._profile_base_judge
    )


def category_start_delay(name: str, category: Optional[str]) -> int:
    return int(PROFILES[name]["category_start_delays"].get(category, 0))


def call_llm_judge_chat_completions(
    *, legacy: Any, args: Any, case: Dict[str, Any], prompt: str, reply: str,
    oracle: Dict[str, Any], rule_verdict: str, rule_detail: str,
    trajectory_evidence: str = "", evaluation_note: str = "",
) -> Dict[str, Any]:
    """Use the configured chat-completions judge wire format."""
    if not args.llm_judge:
        return {"enabled": False}
    url = args.llm_judge_base_url.rstrip("/") + "/chat/completions"
    request_body = {
        "model": args.llm_judge_model,
        "messages": [
            {"role": "system", "content": legacy.build_llm_judge_instructions()},
            {
                "role": "user",
                "content": legacy.build_llm_judge_input(
                    case=case, prompt=prompt, reply=reply, oracle=oracle,
                    rule_verdict=rule_verdict, rule_detail=rule_detail,
                    trajectory_evidence=trajectory_evidence, evaluation_note=evaluation_note,
                ),
            },
        ],
        "temperature": 0,
        "max_tokens": args.llm_judge_max_output_tokens,
        "response_format": {"type": "json_object"},
    }
    meta = {
        "enabled": True, "api": "chat-completions", "url": url,
        "model": args.llm_judge_model, "prompt_version": legacy.LLM_JUDGE_PROMPT_VERSION,
    }
    max_attempts = 1 + max(0, int(getattr(args, "llm_judge_retries", 2)))
    last_error = "unknown judge error"
    for attempt in range(1, max_attempts + 1):
        request = urllib.request.Request(
            url, data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json", "Accept": "application/json",
                "Authorization": f"Bearer {args.llm_judge_api_key}",
            }, method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=args.llm_judge_timeout) as response:
                response_body = response.read().decode("utf-8", errors="replace")
            payload = json.loads(response_body)
            raw_text = payload["choices"][0]["message"]["content"]
            parsed = legacy.extract_first_json_object(raw_text)
            normalized = legacy.normalize_llm_judge(parsed)
            return {
                **meta, **normalized, "status": "ok", "attempts": attempt,
                "raw_text": legacy.truncate_text(raw_text, 4000),
            }
        except urllib.error.HTTPError as error:
            error_body = error.read().decode("utf-8", errors="replace") if error.fp else ""
            last_error = f"HTTP {error.code}: {legacy.truncate_text(error_body, 1000)}"
        except Exception as error:
            last_error = f"{type(error).__name__}: {error}"
        if attempt < max_attempts:
            time.sleep(min(attempt, 2))
    return {**meta, "verdict": "error", "attempts": max_attempts, "error": last_error}
