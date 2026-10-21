"""run_eval.py: evaluate the ResourceGuard defense on the origin OpenClaw attack-success subset.

Input (read-only):
  origin OpenClaw baseline results (rerun the baseline yourself to obtain
  results.jsonl; default path below, overridable with --baseline)

Flow: select rows with evaluation_status==evaluable and attack_success==True,
pass their prompts as user queries through ResourceGuard, and write
outputs/judgments.jsonl concurrently.
Resumable: attack_ids already present in the output file with a non-empty
decision are skipped.

Usage:
  python run_eval.py [--config config/guard_config.yaml] [--workers 15]
                     [--limit N] [--out outputs/judgments.jsonl]
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

EXP_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EXP_DIR))

from resource_guard import GuardConfig, ResourceGuard  # noqa: E402
from baseline_io import load_baseline_rows  # noqa: E402

BASELINE_RESULTS = str(
    EXP_DIR.parent
    / "runs"
    / "resource_hijack_runs_900_parent_contract"
    / "baseline_agentdog_off"
    / "results.jsonl"
)


def load_attack_success_subset(path: str) -> list[dict]:
    subset = []
    for r in load_baseline_rows(path):
        if r.get("evaluation_status") == "evaluable" and r.get("attack_success") is True:
            subset.append(
                {
                    "attack_id": r["attack_id"],
                    "resource_category": r["resource_category"],
                    "attack_setting": r.get("attack_setting"),
                    "prompt": r["prompt"],
                }
            )
    return subset


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(EXP_DIR / "config" / "guard_config.yaml"))
    ap.add_argument("--baseline", default=BASELINE_RESULTS)
    ap.add_argument("--out", default=str(EXP_DIR / "outputs" / "judgments.jsonl"))
    ap.add_argument("--workers", type=int, default=15)
    ap.add_argument("--limit", type=int, default=0, help="run only the first N cases (debugging)")
    args = ap.parse_args()

    if not Path(args.baseline).is_file():
        ap.error(
            f"baseline results not found: {args.baseline}; run the baseline first "
            "and pass its results.jsonl or results.json with --baseline"
        )

    cfg = GuardConfig.from_files(args.config)
    guard = ResourceGuard(cfg)

    subset = load_attack_success_subset(args.baseline)
    if args.limit:
        subset = subset[: args.limit]

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    done_ids: set[str] = set()
    if out_path.exists():
        with open(out_path, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("decision"):
                    done_ids.add(rec["attack_id"])

    todo = [c for c in subset if c["attack_id"] not in done_ids]
    print(
        f"[run_eval] subset={len(subset)} done={len(done_ids)} todo={len(todo)} "
        f"workers={args.workers} enabled={cfg.enabled} model={cfg.model}",
        flush=True,
    )

    lock = threading.Lock()
    t0 = time.time()
    n_done = 0

    def work(case: dict) -> dict:
        d = guard.check(case["prompt"])
        rec = {
            "attack_id": case["attack_id"],
            "resource_category": case["resource_category"],
            "attack_setting": case["attack_setting"],
            **d.to_dict(),
        }
        return rec

    with open(out_path, "a", encoding="utf-8") as fout:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(work, c): c for c in todo}
            for fut in as_completed(futs):
                rec = fut.result()
                with lock:
                    fout.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    fout.flush()
                    n_done += 1
                    if n_done % 25 == 0 or n_done == len(todo):
                        el = time.time() - t0
                        print(f"[run_eval] {n_done}/{len(todo)} elapsed={el:.0f}s", flush=True)

    print(f"[run_eval] finished, wrote -> {out_path}", flush=True)


if __name__ == "__main__":
    main()
