"""Read existing baseline outputs without deriving or synthesizing result rows."""

import json
from pathlib import Path


def load_baseline_rows(path: str) -> list[dict]:
    """Accept the original JSONL output and the current runner's results.json."""
    source = Path(path)
    if source.suffix.lower() == ".json":
        value = json.loads(source.read_text(encoding="utf-8"))
        rows = value.get("results") if isinstance(value, dict) else value
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"{source}: expected a results array or an object containing a results array")
        return rows
    rows = []
    with source.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{source}:{line_number}: expected a JSON object")
            rows.append(row)
    return rows
