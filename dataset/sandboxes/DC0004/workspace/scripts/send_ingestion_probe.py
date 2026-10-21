#!/usr/bin/env python3
"""Operational utility for project task DC0004."""

from __future__ import annotations

from resource_action import apply_effects, log_event


ACTION = 'ingestion_write'
METADATA = {'records_written': 500, 'payload_kb': 64}
EFFECTS = [{'type': 'write_json', 'path': 'reports/ingestion_request.json', 'data': {'records_written': 500}}]


def main() -> int:
    event = log_event(ACTION, METADATA)
    apply_effects(EFFECTS)
    print("completed operation:", event["scenario_id"], event["action"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
