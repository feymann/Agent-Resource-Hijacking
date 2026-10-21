"""analyze.py: summarize ResourceGuard blocks on the attack-success subset.

Outputs per resource category + overall:
  - subset size (origin OpenClaw attack successes)
  - BLOCK count / block rate
  - post-defense ASR = unblocked / evaluable total of the category (same denominator as the main table)
  - reason distribution
and writes the table to analysis/resource_guard_report.md.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

from baseline_io import load_baseline_rows

EXP_DIR = Path(__file__).resolve().parent

BASELINE_RESULTS = str(
    EXP_DIR.parent
    / "runs"
    / "resource_hijack_runs_900_parent_contract"
    / "baseline_agentdog_off"
    / "results.jsonl"
)

CATEGORIES = ["condition", "energy", "interaction", "knowledge", "material", "symbolic"]


def load_baseline_evaluable(path: str) -> dict[str, int]:
    by_cat: dict[str, int] = collections.Counter()
    for r in load_baseline_rows(path):
        if r.get("evaluation_status") == "evaluable":
            by_cat[r["resource_category"]] += 1
    return dict(by_cat)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--judgments", default=str(EXP_DIR / "outputs" / "judgments.jsonl"))
    ap.add_argument("--baseline", default=BASELINE_RESULTS)
    ap.add_argument("--report", default=str(EXP_DIR / "analysis" / "resource_guard_report.md"))
    args = ap.parse_args()

    for label, value in (("baseline results", args.baseline), ("guard judgments", args.judgments)):
        if not Path(value).is_file():
            ap.error(f"{label} not found: {value}; provide the existing evaluation output")

    evaluable_by_cat = load_baseline_evaluable(args.baseline)

    recs = []
    with open(args.judgments, encoding="utf-8") as f:
        for line in f:
            recs.append(json.loads(line))

    by_cat: dict[str, list] = collections.defaultdict(list)
    for r in recs:
        by_cat[r["resource_category"]].append(r)

    rows = []
    reason_counter: collections.Counter = collections.Counter()
    tot_n = tot_block = tot_eval = 0
    for cat in CATEGORIES:
        items = by_cat.get(cat, [])
        n = len(items)
        block = sum(1 for r in items if r["decision"] == "BLOCK")
        ev = evaluable_by_cat.get(cat, 0)
        resid_asr = (n - block) / ev * 100 if ev else 0.0
        rate = block / n * 100 if n else 0.0
        rows.append((cat, n, block, rate, ev, resid_asr))
        tot_n += n
        tot_block += block
        tot_eval += ev
        for r in items:
            reason_counter[r["reason"]] += 1

    lines = []
    lines.append("# ResourceGuard defense evaluation report (attack-success subset)")
    lines.append("")
    lines.append("| Resource Category | Subset n | Blocked | Block Rate (%) | Evaluable n | Residual ASR (%) |")
    lines.append("|---|---|---|---|---|---|")
    for cat, n, block, rate, ev, resid in rows:
        lines.append(f"| {cat} | {n} | {block} | {rate:.2f} | {ev} | {resid:.2f} |")
    o_rate = tot_block / tot_n * 100 if tot_n else 0.0
    o_resid = (tot_n - tot_block) / tot_eval * 100 if tot_eval else 0.0
    lines.append(f"| **Overall** | **{tot_n}** | **{tot_block}** | **{o_rate:.2f}** | **{tot_eval}** | **{o_resid:.2f}** |")
    lines.append("")
    lines.append("## BLOCK/ALLOW reason distribution")
    lines.append("")
    lines.append("| reason | count |")
    lines.append("|---|---|")
    for reason, cnt in reason_counter.most_common():
        lines.append(f"| {reason} | {cnt} |")
    lines.append("")

    report = "\n".join(lines)
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
