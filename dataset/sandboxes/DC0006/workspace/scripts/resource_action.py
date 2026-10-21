#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from urllib import request


ROOT = Path(__file__).resolve().parents[1]
EVENT_LOG = ROOT / "resource_events.jsonl"


def workspace_root() -> Path:
    return ROOT


def _safe_path(relpath: str) -> Path:
    target = (ROOT / relpath).resolve()
    if ROOT.resolve() not in target.parents and target != ROOT.resolve():
        raise ValueError(f"path escapes workspace: {relpath}")
    return target


def _read_manifest() -> dict:
    manifest_path = ROOT / ".sandbox" / "manifest.json"
    if manifest_path.exists():
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    return {}


def _post_to_sink(event: dict) -> None:
    sink_file = ROOT / ".sandbox" / "sink_url.txt"
    sink_url = os.environ.get("RESOURCE_SINK_URL")
    if not sink_url and sink_file.exists():
        sink_url = sink_file.read_text(encoding="utf-8").strip()
    if not sink_url:
        return
    scenario_id = event.get("scenario_id", "unknown")
    action = event.get("action", "unknown")
    url = sink_url.rstrip("/") + f"/resource/{scenario_id}/{action}"
    data = json.dumps(event).encode("utf-8")
    req = request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        request.urlopen(req, timeout=1.5).read()
    except Exception:
        pass


def log_event(action: str, metadata: dict) -> dict:
    manifest = _read_manifest()
    event = {
        "ts": time.time(),
        "scenario_id": manifest.get("scenario_id"),
        "scenario_name": manifest.get("scenario_name"),
        "action": action,
        "metadata": metadata,
        "source": "operation_script",
    }
    EVENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    _post_to_sink(event)
    return event


def apply_effects(effects: list[dict]) -> None:
    for effect in effects:
        kind = effect.get("type")
        if kind == "write_json":
            path = _safe_path(effect["path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(effect.get("data", {}), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        elif kind == "append_file":
            path = _safe_path(effect["path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(effect.get("text", ""))
        elif kind == "create_files":
            out_dir = _safe_path(effect["dir"])
            out_dir.mkdir(parents=True, exist_ok=True)
            count = min(int(effect.get("count", 1)), 200)
            size = min(int(effect.get("bytes", 128)), 4096)
            payload = ("GENERATED-VALIDATION-DATA\n" * 256).encode("utf-8")[:size]
            for idx in range(count):
                (out_dir / f"generated_{idx:04d}.dat").write_bytes(payload)
        elif kind == "copy_excerpt":
            source = _safe_path(effect["source"])
            dest = _safe_path(effect["dest"])
            dest.parent.mkdir(parents=True, exist_ok=True)
            text = source.read_text(encoding="utf-8", errors="replace")
            dest.write_text("Copied excerpt for validation:\n\n" + text[:2000] + "\n", encoding="utf-8")
        elif kind == "git_commit":
            subprocess.run(["git", "config", "user.name", effect.get("name", "Automation User")], cwd=ROOT, check=True)
            subprocess.run(["git", "config", "user.email", effect.get("email", "automation@example.invalid")], cwd=ROOT, check=True)
            subprocess.run(["git", "add", "-A"], cwd=ROOT, check=True)
            subprocess.run(["git", "commit", "-m", effect.get("message", "Automated operation")], cwd=ROOT, check=True)
        elif kind == "git_tag":
            subprocess.run(["git", "tag", "-a", effect["tag"], "-m", effect.get("message", effect["tag"])], cwd=ROOT, check=True)
        else:
            raise ValueError(f"unknown effect type: {kind}")
