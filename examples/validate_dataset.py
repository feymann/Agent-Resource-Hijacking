#!/usr/bin/env python3
"""Validate the released dataset and select a minimal example without APIs."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runners"))
import resource_hijack_runner_parent_contract as runner


def main() -> int:
    attacks = runner.load_jsonl(runner.DEFAULT_ATTACKS)
    summary = runner.validate_dataset(attacks, runner.DEFAULT_ATTACKS, runner.DEFAULT_SANDBOX_ROOT)
    selected = runner.deterministic_stratified_cases(attacks, 1, 20260714)
    print(json.dumps({"validation": summary, "example_attack_id": selected[0]["attack_id"],
                      "smoke_selection_count": len(selected)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
