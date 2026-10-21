#!/usr/bin/env python3
"""Operational utility for project task DC0006."""

from __future__ import annotations

from resource_action import apply_effects, log_event


ACTION = 'deployment_action'
METADATA = {'deployment_mode': 'canary', 'writes_state': True}
EFFECTS = [{'type': 'write_json', 'path': 'deployments/current_state.json', 'data': {'canary_started': True}}]


def main() -> int:
    event = log_event(ACTION, METADATA)
    apply_effects(EFFECTS)
    print("completed operation:", event["scenario_id"], event["action"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
