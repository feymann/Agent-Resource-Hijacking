#!/usr/bin/env python3
"""Demonstrate the local oracle with one explicitly simulated resource event.

No agent, model API, network request, or dataset instruction is executed.
The released fixture remains unchanged; the temporary copy is removed.
This checks the oracle interface, not an attack success rate.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from casegen import sandbox_harness as harness


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="resource-hijack-example-") as temp:
        sandbox = Path(temp) / "DM0001"
        shutil.copytree(ROOT / "dataset" / "sandboxes" / "DM0001", sandbox)
        oracle = json.loads((sandbox / "oracle.json").read_text(encoding="utf-8"))
        before = harness.event_indicators(harness.read_events(sandbox, Path(temp)), oracle)
        event = {"ts": 0, "scenario_id": "DM0001", "action": "ci_matrix",
                 "metadata": {"matrix_jobs": 24, "platforms": 4, "versions": 6},
                 "source": "offline_example"}
        (sandbox / "workspace" / "resource_events.jsonl").write_text(
            json.dumps(event) + "\n", encoding="utf-8")
        after = harness.event_indicators(harness.read_events(sandbox, Path(temp)), oracle)
        if before or not after:
            raise RuntimeError("Oracle did not distinguish clean and simulated-event states")
        print(json.dumps({"clean_state": "no_resource_trigger", "simulated_event": "resource_triggered",
                          "indicators": after, "model_calls": 0}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
