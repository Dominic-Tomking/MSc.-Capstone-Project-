#!/usr/bin/env python3
"""Full multi-engine demonstration on a single contract.

Runs static analysis (Slither + SmartCheck) and dynamic testnet validation on a
contract, folds the confirmed exploit in as an independent TESTNET finding, and
prints the unified, risk-ranked aggregation report.  This shows the three
non-NLP engines combining under the common schema; the CodeBERT engine plugs in
the same way.

    python demo_full.py [path/to/contract.sol] [ContractName] [reentrancy]
"""
from __future__ import annotations

import json
import sys

from vulnscan.aggregation import FusionEngine
from vulnscan.schema.finding import Finding, Location, Source
from vulnscan.schema.severity import Severity
from vulnscan.schema.taxonomy import VulnType, from_string
from vulnscan.static_analysis import StaticAnalysisService
from vulnscan.testnet import Outcome, TestnetValidationService


def main() -> None:
    target = sys.argv[1] if len(sys.argv) > 1 else \
        "vulnscan/testnet/scenarios_sol/VulnerableBank.sol"
    name = sys.argv[2] if len(sys.argv) > 2 else "VulnerableBank"
    vtype = from_string(sys.argv[3]) if len(sys.argv) > 3 else VulnType.REENTRANCY
    cid = name

    print(f"# Target: {target} ({name}), expected type {vtype.value}\n")

    sres = StaticAnalysisService().analyse_file(target, contract_id=cid)
    findings = list(sres.findings)
    print(f"[1] Static analysis: {len(findings)} findings from "
          f"{list(sres.run_info.keys())}")
    for f in findings:
        print(f"      [{f.source.value:10}] {f.vuln_type.value:16} "
              f"{f.severity.label:8} L{f.location.start_line}-{f.location.end_line}")

    tsvc = TestnetValidationService()
    if tsvc.available():
        tres = tsvc.validate(target, name, vtype, contract_id=cid)
        print(f"\n[2] Testnet validation: {tres.outcome.value}")
        for line in tres.trace:
            print(f"      {line}")
        if tres.outcome is Outcome.EXPLOIT_CONFIRMED:
            findings.append(Finding(
                cid, vtype, Severity.CRITICAL,
                Location(function=None, start_line=None, end_line=None),
                Source.TESTNET, confidence=1.0,
                evidence_ref="testnet:exploit_confirmed",
                message="dynamically confirmed on local EVM"))
    else:
        print("\n[2] Testnet validation: skipped (EVM venv not available)")

    report = FusionEngine().aggregate(findings, contract_id=cid)
    print("\n[3] Unified aggregated report (risk-ranked):")
    for c in report.ranked():
        d = c.to_dict()
        tag = "CONSENSUS" if d["consensus"] else "review"
        print(f"      {d['risk_score']:.3f}  {d['vuln_type']:16} "
              f"{d['severity']:8} [{tag}] methods={d['methods']}")

    print("\n" + json.dumps(report.to_dict(), indent=2))


if __name__ == "__main__":
    main()
