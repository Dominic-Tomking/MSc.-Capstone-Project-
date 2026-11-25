"""The common vulnerability schema (proposal S4.4.1, Table 2).

Every finding produced by any detection method, and every ground-truth label,
is expressed as a :class:`Finding` before comparison or aggregation.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from .severity import Severity
from .taxonomy import VulnType, entry


class Source(str, Enum):
    SLITHER = "slither"
    SMARTCHECK = "smartcheck"
    CODEBERT = "codebert"
    TESTNET = "testnet"
    GROUND_TRUTH = "ground_truth"

    def __str__(self) -> str:  # pragma: no cover
        return self.value


@dataclass
class Location:
    """Function name plus start/end line numbers in the original source."""

    function: Optional[str] = None
    start_line: Optional[int] = None
    end_line: Optional[int] = None
    file: Optional[str] = None

    def overlaps(self, other: "Location") -> bool:
        """True if the two line ranges overlap by at least one line.

        A missing range is treated as unknown and never forced to overlap;
        callers combine this with a same-function check for lenient matching.
        """
        if None in (self.start_line, self.end_line, other.start_line, other.end_line):
            return False
        return self.start_line <= other.end_line and other.start_line <= self.end_line

    def same_function(self, other: "Location") -> bool:
        if not self.function or not other.function:
            return False
        return self.function.strip() == other.function.strip()


@dataclass
class Finding:
    """One normalised finding or ground-truth label.

    Fields mirror Table 2 of the proposal: contract_id, vuln_type, severity,
    location, confidence, source, evidence_ref.
    """

    contract_id: str
    vuln_type: VulnType
    severity: Severity
    location: Location
    source: Source
    confidence: float = 1.0          # rescaled to [0, 1]; labels carry 1.0
    evidence_ref: str = ""           # citation (labels) or raw tool id (findings)
    raw_type: str = ""               # original tool check id, kept for traceability
    message: str = ""                # human-readable description
    metadata: dict = field(default_factory=dict)

    # -- derived identifiers -------------------------------------------------
    @property
    def swc(self) -> tuple[str, ...]:
        return entry(self.vuln_type).swc

    @property
    def cwe(self) -> tuple[str, ...]:
        return entry(self.vuln_type).cwe

    def dedup_key(self) -> str:
        """Key used to collapse duplicate findings from the *same* method.

        Two findings from one method with the same vulnerability type and
        overlapping location refer to the same underlying defect (proposal
        S4.4.3, "Duplicate").  We approximate overlapping location by the
        function name (or the start line bucket when no function is known).
        """
        loc = self.location.function or (
            f"L{self.location.start_line}" if self.location.start_line else "?"
        )
        return f"{self.source}|{self.contract_id}|{self.vuln_type}|{loc}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["vuln_type"] = self.vuln_type.value
        d["severity"] = self.severity.label
        d["source"] = self.source.value
        d["swc"] = list(self.swc)
        d["cwe"] = list(self.cwe)
        return d

    @staticmethod
    def contract_id_from_source(source_code: str) -> str:
        """Stable id derived from the SHA-256 hash of the normalised source
        (proposal S4.3 / Table 2 contract_id)."""
        normalised = "\n".join(
            line.rstrip() for line in source_code.strip().splitlines() if line.strip()
        )
        return "sha256:" + hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16]
