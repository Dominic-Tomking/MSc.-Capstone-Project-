"""Unit tests for the non-NLP framework components.

These tests exercise the pure-logic layers (schema, normalisation, parsing,
aggregation, matching, metrics) with fixtures, so they run without Slither,
SmartCheck or an EVM.  Integration with the real tools is covered by
``run_pipeline.py`` and ``test_integration.py``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vulnscan.aggregation import FusionEngine, deduplicate
from vulnscan.evaluation import evaluate_method
from vulnscan.evaluation.matching import MatchMode, match
from vulnscan.schema.finding import Finding, Location, Source
from vulnscan.schema.severity import Severity
from vulnscan.schema.taxonomy import VulnType, are_related, from_string
from vulnscan.static_analysis import slither_adapter, smartcheck_adapter
from vulnscan.static_analysis.normalizer import map_slither, map_smartcheck
from vulnscan.static_analysis import solc_manager


def mkf(vt, source, start=10, end=12, func="f", conf=0.9, cid="C1"):
    return Finding(cid, vt, Severity.HIGH,
                   Location(function=func, start_line=start, end_line=end),
                   source, confidence=conf)


# --------------------------------------------------------------------------- #
# taxonomy / schema
# --------------------------------------------------------------------------- #
def test_taxonomy_mapping_swc_cwe():
    f = mkf(VulnType.REENTRANCY, Source.SLITHER)
    assert "SWC-107" in f.swc
    assert f.cwe  # has a CWE

def test_from_string_aliases():
    assert from_string("reentrancy-eth") is VulnType.REENTRANCY
    assert from_string("integer_overflow") is VulnType.ARITHMETIC
    assert from_string("weak-prng") is VulnType.BAD_RANDOMNESS
    assert from_string("totally-unknown") is VulnType.OTHER

def test_related_types():
    assert are_related(VulnType.REENTRANCY, VulnType.UNCHECKED_CALLS)
    assert are_related(VulnType.BAD_RANDOMNESS, VulnType.TIME_MANIPULATION)
    assert not are_related(VulnType.REENTRANCY, VulnType.ARITHMETIC)

def test_location_overlap():
    a = Location(start_line=10, end_line=20)
    assert a.overlaps(Location(start_line=15, end_line=25))
    assert not a.overlaps(Location(start_line=21, end_line=30))

def test_contract_id_stable():
    src = "contract A { uint x; }"
    assert Finding.contract_id_from_source(src) == Finding.contract_id_from_source(src + "\n")


# --------------------------------------------------------------------------- #
# normalisation
# --------------------------------------------------------------------------- #
def test_slither_normaliser():
    assert map_slither("reentrancy-eth") is VulnType.REENTRANCY
    assert map_slither("tx-origin") is VulnType.ACCESS_CONTROL
    assert map_slither("naming-convention") is None       # dropped
    assert map_slither("some-new-detector") is VulnType.OTHER

def test_smartcheck_normaliser():
    assert map_smartcheck("SOLIDITY_TX_ORIGIN") is VulnType.ACCESS_CONTROL
    assert map_smartcheck("SOLIDITY_PRAGMAS_VERSION") is None


# --------------------------------------------------------------------------- #
# adapter parsing (fixtures, no tool execution)
# --------------------------------------------------------------------------- #
def test_slither_parse_json_fixture():
    data = {
        "success": True,
        "results": {"detectors": [
            {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
             "id": "abc", "description": "Reentrancy in withdraw",
             "elements": [
                 {"type": "function", "name": "withdraw",
                  "source_mapping": {"lines": [12, 13, 14], "filename_relative": "C.sol"}},
             ]},
            {"check": "naming-convention", "impact": "Informational",
             "confidence": "High", "elements": []},
        ]},
    }
    findings = slither_adapter.parse_json(data, "C1")
    assert len(findings) == 1                     # naming-convention dropped
    f = findings[0]
    assert f.vuln_type is VulnType.REENTRANCY
    assert f.location.function == "withdraw"
    assert f.location.start_line == 12 and f.location.end_line == 14
    assert 0 < f.confidence <= 1

def test_smartcheck_parse_output_fixture():
    text = (
        "ruleId: SOLIDITY_UNCHECKED_CALL\npatternId: f39eed\nseverity: 3\n"
        "line: 15\ncolumn: 19\ncontent: call.value(x)()\n\n"
        "ruleId: SOLIDITY_PRAGMAS_VERSION\npatternId: 23fc32\nseverity: 1\n"
        "line: 2\ncolumn: 16\ncontent: ^\n"
    )
    findings = smartcheck_adapter.parse_output(text, "C1")
    assert len(findings) == 1                     # pragma advisory dropped
    assert findings[0].vuln_type is VulnType.UNCHECKED_CALLS
    assert findings[0].severity is Severity.HIGH
    assert findings[0].location.start_line == 15


# --------------------------------------------------------------------------- #
# solc selection
# --------------------------------------------------------------------------- #
def test_solc_pragma_detection():
    assert solc_manager.detect_pragma("pragma solidity ^0.4.24;") == "^0.4.24"
    assert solc_manager.detect_pragma("no pragma here") is None


# --------------------------------------------------------------------------- #
# aggregation
# --------------------------------------------------------------------------- #
def test_deduplicate_same_method():
    f1 = mkf(VulnType.UNCHECKED_CALLS, Source.SLITHER)
    f2 = mkf(VulnType.UNCHECKED_CALLS, Source.SLITHER)   # same type+func -> dup
    out = deduplicate([f1, f2])
    assert len(out) == 1
    assert out[0].metadata.get("collapsed_duplicates") == 2

def test_consensus_across_methods():
    slither = mkf(VulnType.REENTRANCY, Source.SLITHER, start=12, end=17)
    smart = mkf(VulnType.REENTRANCY, Source.SMARTCHECK, start=15, end=15, func=None)
    report = FusionEngine().aggregate([slither, smart], "C1")
    assert len(report.clusters) == 1
    cl = report.clusters[0]
    assert cl.is_consensus and cl.n_methods == 2
    assert cl.risk_score() > 0.5

def test_conflict_single_method_flagged():
    only = mkf(VulnType.ARITHMETIC, Source.SLITHER)
    report = FusionEngine().aggregate([only], "C1")
    assert report.conflicts and not report.consensus

def test_location_less_finding_merges_by_exact_type_only():
    # A testnet confirmation with no location must merge with the SAME-type
    # static finding, and must NOT chain through a related type into another
    # cluster (regression for reentrancy -> unchecked -> DoS chaining).
    slither_re = mkf(VulnType.REENTRANCY, Source.SLITHER, start=7, end=13)
    slither_un = mkf(VulnType.UNCHECKED_CALLS, Source.SLITHER, start=7, end=13)
    smart_dos = mkf(VulnType.DENIAL_OF_SERVICE, Source.SMARTCHECK,
                    start=4, end=4, func=None)
    testnet = Finding("C1", VulnType.REENTRANCY, Severity.CRITICAL,
                      Location(function=None, start_line=None, end_line=None),
                      Source.TESTNET, confidence=1.0)
    report = FusionEngine().aggregate(
        [slither_re, slither_un, smart_dos, testnet], "C1")
    re_cluster = next(c for c in report.clusters if c.vuln_type == VulnType.REENTRANCY)
    assert Source.TESTNET in re_cluster.sources          # merged with reentrancy
    assert re_cluster.is_consensus
    dos_cluster = next(c for c in report.clusters
                       if c.vuln_type == VulnType.DENIAL_OF_SERVICE)
    assert dos_cluster.sources == {Source.SMARTCHECK}    # not polluted by chaining


# --------------------------------------------------------------------------- #
# matching + metrics
# --------------------------------------------------------------------------- #
def test_strict_true_positive():
    finding = mkf(VulnType.REENTRANCY, Source.SLITHER, start=12, end=17)
    label = mkf(VulnType.REENTRANCY, Source.GROUND_TRUTH, start=11, end=18)
    out = match([finding], [label], MatchMode.STRICT)
    assert out.counts["tp"] == 1 and out.counts["fp"] == 0 and out.counts["fn"] == 0

def test_strict_false_positive_no_overlap():
    finding = mkf(VulnType.REENTRANCY, Source.SLITHER, start=100, end=110)
    label = mkf(VulnType.REENTRANCY, Source.GROUND_TRUTH, start=11, end=18)
    out = match([finding], [label], MatchMode.STRICT)
    assert out.counts["tp"] == 0 and out.counts["fp"] == 1 and out.counts["fn"] == 1

def test_lenient_accepts_related_type():
    # unchecked-call finding where the label is reentrancy (related) -> TP lenient
    finding = mkf(VulnType.UNCHECKED_CALLS, Source.SLITHER, start=12, end=17)
    label = mkf(VulnType.REENTRANCY, Source.GROUND_TRUTH, start=12, end=17)
    strict = match([finding], [label], MatchMode.STRICT)
    lenient = match([finding], [label], MatchMode.LENIENT)
    assert strict.counts["tp"] == 0            # different type, strict fails
    assert lenient.counts["tp"] == 1           # related type accepted

def test_metrics_precision_recall():
    findings = [
        mkf(VulnType.REENTRANCY, Source.SLITHER, start=12, end=17, cid="C1"),
        mkf(VulnType.ARITHMETIC, Source.SLITHER, start=30, end=32, cid="C1"),  # FP
    ]
    labels = [
        mkf(VulnType.REENTRANCY, Source.GROUND_TRUTH, start=11, end=18, cid="C1"),
        mkf(VulnType.ACCESS_CONTROL, Source.GROUND_TRUTH, start=40, end=44, cid="C1"),  # FN
    ]
    ev = evaluate_method(findings, labels, "slither", MatchMode.STRICT)
    assert ev.micro["tp"] == 1
    assert ev.micro["fp"] == 1
    assert ev.micro["fn"] == 1
    assert ev.micro["precision"] == pytest.approx(0.5)
    assert ev.micro["recall"] == pytest.approx(0.5)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
