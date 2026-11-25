#!/usr/bin/env python3
"""End-to-end reference pipeline over the labelled dataset.

Runs the static-analysis engines on every contract, aggregates the findings,
matches them against the ground truth under both strict and lenient scoring,
and writes per-method metrics and a unified aggregated report.  This is the
non-NLP counterpart of the CodeBERT evaluation harness and, together with it,
produces the comparative evaluation of the proposal (S4.5).

Usage:
    python run_pipeline.py --dataset fixtures/ground_truth.json --out artifacts
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

from vulnscan.aggregation import FusionEngine
from vulnscan.evaluation import evaluate_method, groundtruth
from vulnscan.evaluation.matching import MatchMode
from vulnscan.schema.finding import Source
from vulnscan.static_analysis import StaticAnalysisService


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="fixtures/ground_truth.json")
    ap.add_argument("--out", default="artifacts")
    ap.add_argument("--no-smartcheck", action="store_true")
    args = ap.parse_args()

    out = Path(args.out)
    (out / "raw").mkdir(parents=True, exist_ok=True)

    labels = groundtruth.load(args.dataset)
    paths = groundtruth.load_map(args.dataset)

    svc = StaticAnalysisService(use_smartcheck=not args.no_smartcheck)
    fusion = FusionEngine()

    findings_by_method: dict[str, list] = defaultdict(list)
    all_findings: list = []
    run_info: dict = {}
    aggregated: dict = {}

    for cid, path in paths.items():
        if not path or not Path(path).exists():
            print(f"! skipping {cid}: missing source {path}")
            continue
        res = svc.analyse_file(path, contract_id=cid)
        run_info[cid] = {"run_info": res.run_info, "errors": res.errors}
        for f in res.findings:
            findings_by_method[f.source.value].append(f)
            all_findings.append(f)
        # aggregate this contract's findings across engines
        report = fusion.aggregate(res.findings, contract_id=cid)
        aggregated[cid] = report.to_dict()
        # persist raw normalised findings for reproducibility
        (out / "raw" / f"{cid}.json").write_text(
            json.dumps([f.to_dict() for f in res.findings], indent=2))
        print(f"* {cid}: "
              + ", ".join(f"{m}={len(res.by_source(Source(m)))}"
                          for m in ("slither", "smartcheck")
                          if any(x.source.value == m for x in res.findings))
              + f" | clusters={report.to_dict()['n_clusters']}"
              + f" consensus={report.to_dict()['n_consensus']}")

    # ---- evaluation: per method, strict + lenient --------------------------
    evaluation = {}
    for mode in (MatchMode.STRICT, MatchMode.LENIENT):
        evaluation[mode.value] = {}
        for method, fs in findings_by_method.items():
            ev = evaluate_method(fs, labels, method, mode)
            evaluation[mode.value][method] = ev.to_dict()

    (out / "aggregated_report.json").write_text(json.dumps(aggregated, indent=2))
    (out / "evaluation.json").write_text(json.dumps(evaluation, indent=2))
    (out / "run_info.json").write_text(json.dumps(run_info, indent=2))

    # ---- console summary ----------------------------------------------------
    print("\n=== Evaluation summary (micro precision/recall/F1) ===")
    for mode in ("strict", "lenient"):
        print(f"\n[{mode}]")
        for method, ev in evaluation[mode].items():
            m = ev["micro"]
            print(f"  {method:11} P={m['precision']:.3f} R={m['recall']:.3f} "
                  f"F1={m['f1']:.3f} (tp={m['tp']} fp={m['fp']} fn={m['fn']}) "
                  f"coverage={ev['coverage']:.2f} partial={ev['partial_matches']}")
    print(f"\nArtifacts written to {out}/")


if __name__ == "__main__":
    main()
