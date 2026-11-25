"""Ground-truth matching (proposal S4.4.3, Table 3).

Each tool finding is compared against the ground-truth label set for the same
contract and classified as true positive, partial match, false positive or
false negative.  Two scoring configurations are provided (S4.4.4):

* **strict**  — exact type match *and* location overlap.
* **lenient** — related types accepted and location overlap not required
                (contract-level matching).

Matching is one-to-one and greedy: the best-quality candidate pairs are
assigned first, so neither labels nor findings are double-counted.  This whole
procedure is a versioned function rather than a manual step, so an evaluation
can be re-executed from raw tool outputs by a third party.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

from ..schema.finding import Finding
from ..schema.taxonomy import VulnType, are_related


class MatchMode(str, Enum):
    STRICT = "strict"
    LENIENT = "lenient"


class Outcome(str, Enum):
    TP = "true_positive"
    PARTIAL = "partial_match"
    FP = "false_positive"
    FN = "false_negative"


def _type_match(f: Finding, l: Finding, mode: MatchMode) -> bool:
    if f.vuln_type == l.vuln_type:
        return True
    if mode is MatchMode.LENIENT:
        return are_related(f.vuln_type, l.vuln_type)
    return False


def _location_match(f: Finding, l: Finding) -> bool:
    return f.location.overlaps(l.location) or f.location.same_function(l.location)


def _pair_quality(f: Finding, l: Finding) -> tuple:
    """Higher is better: exact type, then location overlap, then confidence."""
    return (
        1 if f.vuln_type == l.vuln_type else 0,
        1 if _location_match(f, l) else 0,
        f.confidence,
    )


def is_partial(f: Finding, l: Finding) -> bool:
    """Type matches (exact or related) but strict location/type test fails
    (proposal Table 3, "Partial match")."""
    if f.vuln_type == l.vuln_type and not f.location.overlaps(l.location):
        return True
    if f.vuln_type != l.vuln_type and are_related(f.vuln_type, l.vuln_type):
        return True
    return False


@dataclass
class MatchOutcome:
    mode: MatchMode
    tp_pairs: list[tuple[Finding, Finding]] = field(default_factory=list)   # (finding, label)
    partial_pairs: list[tuple[Finding, Finding]] = field(default_factory=list)
    fp_findings: list[Finding] = field(default_factory=list)
    fn_labels: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict:
        return {
            "tp": len(self.tp_pairs),
            "partial": len(self.partial_pairs),
            "fp": len(self.fp_findings),
            "fn": len(self.fn_labels),
        }


def _candidate_pairs(findings, labels, mode):
    pairs = []
    for fi, f in enumerate(findings):
        for li, l in enumerate(labels):
            if f.contract_id != l.contract_id:
                continue
            # strict (proposal Table 3): exact type AND line-range overlap.
            strict_ok = (f.vuln_type == l.vuln_type) and f.location.overlaps(l.location)
            # lenient: related types accepted; same-function or contract-level
            # matching accepted when line info is imperfect.
            lenient_ok = _type_match(f, l, MatchMode.LENIENT) and (
                _location_match(f, l) or mode is MatchMode.LENIENT
            )
            ok = strict_ok if mode is MatchMode.STRICT else (strict_ok or lenient_ok)
            if ok:
                pairs.append((_pair_quality(f, l), fi, li, strict_ok))
    pairs.sort(reverse=True)
    return pairs


def match(findings: Iterable[Finding], labels: Iterable[Finding],
          mode: MatchMode = MatchMode.STRICT) -> MatchOutcome:
    """Greedy one-to-one matching of one method's findings to labels."""
    findings = list(findings)
    labels = list(labels)
    outcome = MatchOutcome(mode=mode)

    used_f: set[int] = set()
    used_l: set[int] = set()
    for _q, fi, li, strict_ok in _candidate_pairs(findings, labels, mode):
        if fi in used_f or li in used_l:
            continue
        used_f.add(fi)
        used_l.add(li)
        f, l = findings[fi], labels[li]
        if strict_ok:
            outcome.tp_pairs.append((f, l))
        elif mode is MatchMode.LENIENT:
            # accepted under lenient scoring -> counts as TP, recorded as partial
            outcome.tp_pairs.append((f, l))
            outcome.partial_pairs.append((f, l))
        else:
            outcome.partial_pairs.append((f, l))

    for fi, f in enumerate(findings):
        if fi not in used_f:
            # a strict-mode partial (type match, no overlap) is still an FP in
            # the headline strict metric, but recorded as partial for reporting
            best = _best_partial(f, labels)
            if best is not None:
                outcome.partial_pairs.append((f, best))
            outcome.fp_findings.append(f)
    for li, l in enumerate(labels):
        if li not in used_l:
            outcome.fn_labels.append(l)
    return outcome


def _best_partial(f: Finding, labels) -> Optional[Finding]:
    for l in labels:
        if f.contract_id == l.contract_id and is_partial(f, l):
            return l
    return None
