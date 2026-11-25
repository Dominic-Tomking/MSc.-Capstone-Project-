"""Fusion engine — reconcile findings from all detection engines.

Implements the aggregation stage of the framework (proposal S4.2.4 / Figure 1
"Aggregation & Fusion Layer"):

1. **Deduplicate** findings within each method that refer to the same defect
   (same vulnerability type + overlapping location).
2. **Correlate** findings across methods into *clusters*, where a cluster is a
   group of findings of the same (or related) vulnerability type at an
   overlapping location.
3. **Consensus / conflict** — a cluster supported by two or more independent
   methods is a consensus finding; isolated findings are flagged for review.
4. **Risk score** — a confidence-weighted score combining engine agreement,
   calibrated confidence and severity, used to rank the unified report.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..schema.finding import Finding, Location, Source
from ..schema.severity import Severity, baseline
from ..schema.taxonomy import VulnType, are_related


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Collapse duplicate findings from the *same* method (proposal S4.4.3).

    Verbose tools are neither penalised nor rewarded for repetition: the
    highest-confidence representative of each (method, type, location) group is
    kept and the number collapsed is recorded in metadata.
    """
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.dedup_key(), []).append(f)
    out: list[Finding] = []
    for key, grp in groups.items():
        rep = max(grp, key=lambda x: (x.confidence, int(x.severity)))
        if len(grp) > 1:
            rep.metadata = {**rep.metadata, "collapsed_duplicates": len(grp)}
        out.append(rep)
    return out


def _no_location(loc) -> bool:
    return loc.start_line is None and loc.function is None


def _same_defect(a: Finding, b: Finding, lenient: bool) -> bool:
    """Do two findings (from different methods) describe the same defect?

    * **Exact type** — merge on location overlap; in lenient mode also merge
      when one side carries no location at all (e.g. a testnet confirmation),
      since a same-type finding cannot be placed elsewhere.
    * **Related type** — merge only on a concrete location overlap; relatedness
      alone is never enough (this prevents transitive chaining such as
      reentrancy → unchecked_calls → denial_of_service).
    """
    loc_overlap = a.location.overlaps(b.location) or a.location.same_function(b.location)
    if a.vuln_type == b.vuln_type:
        if loc_overlap:
            return True
        if lenient and (_no_location(a.location) or _no_location(b.location)):
            return True
        return False
    if lenient and are_related(a.vuln_type, b.vuln_type):
        return loc_overlap        # related types must share a concrete location
    return False


@dataclass
class Cluster:
    """A correlated group of findings believed to describe one defect."""

    contract_id: str
    vuln_type: VulnType
    findings: list[Finding] = field(default_factory=list)

    @property
    def sources(self) -> set[Source]:
        return {f.source for f in self.findings}

    @property
    def n_methods(self) -> int:
        return len(self.sources)

    @property
    def is_consensus(self) -> bool:
        """Reported by two or more *independent* detection methods."""
        return self.n_methods >= 2

    @property
    def location(self) -> Location:
        starts = [f.location.start_line for f in self.findings if f.location.start_line]
        ends = [f.location.end_line for f in self.findings if f.location.end_line]
        func = next((f.location.function for f in self.findings if f.location.function), None)
        return Location(function=func,
                        start_line=min(starts) if starts else None,
                        end_line=max(ends) if ends else None)

    @property
    def severity(self) -> Severity:
        return Severity(max(int(f.severity) for f in self.findings))

    @property
    def max_confidence(self) -> float:
        return max(f.confidence for f in self.findings)

    def risk_score(self) -> float:
        """Confidence- and agreement-weighted risk score in [0, 1].

        Combines: severity (normalised), best calibrated confidence, and an
        agreement bonus that grows with the number of independent methods.
        Consensus findings are boosted; single-method findings are damped.
        """
        sev = int(self.severity) / int(Severity.CRITICAL)
        agree = 1.0 - 0.5 ** self.n_methods          # 1 method .5, 2 .75, 3 .875
        score = 0.45 * sev + 0.35 * self.max_confidence + 0.20 * agree
        return round(min(1.0, score), 4)

    def to_dict(self) -> dict:
        return {
            "contract_id": self.contract_id,
            "vuln_type": self.vuln_type.value,
            "severity": self.severity.label,
            "location": {"function": self.location.function,
                         "start_line": self.location.start_line,
                         "end_line": self.location.end_line},
            "methods": sorted(s.value for s in self.sources),
            "n_methods": self.n_methods,
            "consensus": self.is_consensus,
            "risk_score": self.risk_score(),
            "max_confidence": round(self.max_confidence, 4),
            "evidence": [f.evidence_ref for f in self.findings],
        }


@dataclass
class AggregationReport:
    contract_id: str
    clusters: list[Cluster] = field(default_factory=list)

    @property
    def consensus(self) -> list[Cluster]:
        return [c for c in self.clusters if c.is_consensus]

    @property
    def conflicts(self) -> list[Cluster]:
        """Single-method clusters — flagged for manual review, not auto-resolved
        (proposal S4.2.4)."""
        return [c for c in self.clusters if not c.is_consensus]

    def ranked(self) -> list[Cluster]:
        return sorted(self.clusters, key=lambda c: c.risk_score(), reverse=True)

    def to_dict(self) -> dict:
        return {
            "contract_id": self.contract_id,
            "n_clusters": len(self.clusters),
            "n_consensus": len(self.consensus),
            "n_conflicts": len(self.conflicts),
            "findings": [c.to_dict() for c in self.ranked()],
        }


class FusionEngine:
    def __init__(self, lenient_correlation: bool = True):
        # Correlation across engines uses lenient (related-type) matching by
        # default so that, e.g., an unchecked-call finding and a reentrancy
        # finding on the same line are recognised as the same defect.
        self.lenient = lenient_correlation

    def aggregate(self, findings: Iterable[Finding],
                  contract_id: Optional[str] = None) -> AggregationReport:
        findings = deduplicate(findings)
        if contract_id is None:
            contract_id = findings[0].contract_id if findings else "unknown"

        clusters: list[Cluster] = []
        for f in sorted(findings, key=lambda x: (x.location.start_line or 1_000_000)):
            placed = False
            for c in clusters:
                if c.contract_id == f.contract_id and any(
                    _same_defect(f, g, self.lenient) for g in c.findings
                ):
                    c.findings.append(f)
                    # keep the most specific (non-OTHER) canonical type
                    if c.vuln_type == VulnType.OTHER and f.vuln_type != VulnType.OTHER:
                        c.vuln_type = f.vuln_type
                    placed = True
                    break
            if not placed:
                clusters.append(Cluster(f.contract_id, f.vuln_type, [f]))
        return AggregationReport(contract_id=contract_id, clusters=clusters)
