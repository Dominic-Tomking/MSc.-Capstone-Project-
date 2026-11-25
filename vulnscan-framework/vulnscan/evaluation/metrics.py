"""Evaluation metrics (proposal S4.5, Table 4).

Metrics are computed per vulnerability type and per detection method using the
classification rules in :mod:`vulnscan.evaluation.matching`.  Precision, recall
and F1 are reported per type and macro-averaged; coverage and a confusion
tally are also produced.  Every figure is accompanied by its instance count so
that small-sample results can be marked indicative rather than conclusive.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..schema.finding import Finding, Source
from ..schema.taxonomy import VulnType
from .matching import MatchMode, match

# Security types that form the taxonomy coverage denominator (excludes benign).
SECURITY_TYPES = [vt for vt in VulnType if vt not in (VulnType.BENIGN, VulnType.OTHER)]


def prf(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": tp + fn}


def _group_by_contract(items: Iterable[Finding]) -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = defaultdict(list)
    for f in items:
        out[f.contract_id].append(f)
    return out


@dataclass
class MethodEvaluation:
    method: str
    mode: str
    per_type: dict = field(default_factory=dict)
    macro: dict = field(default_factory=dict)
    micro: dict = field(default_factory=dict)
    coverage: float = 0.0
    partial: int = 0
    confusion: dict = field(default_factory=dict)  # label_type -> {pred_type: n}

    def to_dict(self) -> dict:
        return {
            "method": self.method, "mode": self.mode,
            "micro": self.micro, "macro": self.macro,
            "coverage": self.coverage, "partial_matches": self.partial,
            "per_type": {k.value if isinstance(k, VulnType) else k: v
                         for k, v in self.per_type.items()},
            "confusion": {k.value: {kk.value: vv for kk, vv in row.items()}
                          for k, row in self.confusion.items()},
        }


def evaluate_method(findings: Iterable[Finding], labels: Iterable[Finding],
                    method: str, mode: MatchMode = MatchMode.STRICT,
                    contract_ids: Optional[Iterable[str]] = None) -> MethodEvaluation:
    """Evaluate one detection method's findings against the label set."""
    # Collapse per-method duplicates before classification (proposal Table 3,
    # "Duplicate"): verbose tools are not penalised for repetition.
    from ..aggregation.fusion import deduplicate
    findings = deduplicate(list(findings))
    labels = list(labels)
    f_by_c = _group_by_contract(findings)
    l_by_c = _group_by_contract(labels)
    # evaluate over the union of contracts (so contracts with only labels count
    # their labels as false negatives).
    cids = set(contract_ids) if contract_ids else (set(f_by_c) | set(l_by_c))

    tp_t: dict = defaultdict(int)
    fp_t: dict = defaultdict(int)
    fn_t: dict = defaultdict(int)
    confusion: dict = defaultdict(lambda: defaultdict(int))
    partial_total = 0
    detected_types: set = set()

    for cid in cids:
        out = match(f_by_c.get(cid, []), l_by_c.get(cid, []), mode)
        partial_total += len(out.partial_pairs)
        for f, l in out.tp_pairs:
            tp_t[l.vuln_type] += 1
            confusion[l.vuln_type][f.vuln_type] += 1
            detected_types.add(f.vuln_type)
        for f in out.fp_findings:
            fp_t[f.vuln_type] += 1
            detected_types.add(f.vuln_type)
        for l in out.fn_labels:
            fn_t[l.vuln_type] += 1

    types = set(tp_t) | set(fp_t) | set(fn_t)
    per_type = {t: prf(tp_t[t], fp_t[t], fn_t[t]) for t in types}

    # macro over types that have support (appear as a label somewhere)
    supported = [t for t in types if per_type[t]["support"] > 0]
    def _avg(key):
        return round(sum(per_type[t][key] for t in supported) / len(supported), 4) if supported else 0.0
    macro = {"precision": _avg("precision"), "recall": _avg("recall"),
             "f1": _avg("f1"), "n_types": len(supported)}

    TP, FP, FN = sum(tp_t.values()), sum(fp_t.values()), sum(fn_t.values())
    micro = prf(TP, FP, FN)

    labelled_security = {t for t in types if per_type[t]["support"] > 0
                         and t in SECURITY_TYPES}
    coverage = round(len(detected_types & set(SECURITY_TYPES)) / len(SECURITY_TYPES), 4)

    return MethodEvaluation(
        method=method, mode=mode.value, per_type=per_type,
        macro=macro, micro=micro, coverage=coverage,
        partial=partial_total, confusion=confusion,
    )


def evaluate_all(findings_by_method: dict[str, list[Finding]],
                 labels: Iterable[Finding],
                 mode: MatchMode = MatchMode.STRICT) -> dict[str, MethodEvaluation]:
    labels = list(labels)
    cids = {l.contract_id for l in labels} | {
        f.contract_id for fs in findings_by_method.values() for f in fs}
    return {m: evaluate_method(fs, labels, m, mode, cids)
            for m, fs in findings_by_method.items()}
