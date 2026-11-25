"""Canonical vulnerability taxonomy and cross-standard identifier mapping.

Every detection engine (Slither, SmartCheck, CodeBERT, testnet) and every
ground-truth label is expressed using a single canonical vulnerability type
drawn from :class:`VulnType`.  Each canonical type is mapped to the Smart
Contract Weakness Classification (SWC) registry, the Common Weakness
Enumeration (CWE) and the OWASP Smart Contract Top 10, so that findings remain
comparable across tools and against the wider literature (proposal S4.4.2).

The taxonomy is deliberately aligned with the ten categories used by the
CodeBERT component and the SmartBugs curated benchmark, so that all four
engines share one label space.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class VulnType(str, Enum):
    """Canonical vulnerability categories (the shared label space)."""

    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ARITHMETIC = "arithmetic"
    UNCHECKED_CALLS = "unchecked_calls"
    BAD_RANDOMNESS = "bad_randomness"
    DENIAL_OF_SERVICE = "denial_of_service"
    FRONT_RUNNING = "front_running"
    TIME_MANIPULATION = "time_manipulation"
    SHORT_ADDRESS = "short_address"
    OTHER = "other"
    BENIGN = "benign"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True)
class TaxonomyEntry:
    """Cross-standard mapping and metadata for one canonical vulnerability type."""

    vuln_type: VulnType
    title: str
    swc: tuple[str, ...] = field(default_factory=tuple)
    cwe: tuple[str, ...] = field(default_factory=tuple)
    owasp: Optional[str] = None
    # canonical parent/child relations used by the *lenient* matcher
    related: tuple[VulnType, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# The taxonomy table.  Fixed before evaluation begins and published with the
# dataset (proposal S4.4.2 / Weeks 3-4 deliverable "frozen vulnerability schema").
# ---------------------------------------------------------------------------
TAXONOMY: dict[VulnType, TaxonomyEntry] = {
    VulnType.REENTRANCY: TaxonomyEntry(
        VulnType.REENTRANCY, "Reentrancy",
        swc=("SWC-107",), cwe=("CWE-841",), owasp="SC05:2025-Reentrancy",
        related=(VulnType.UNCHECKED_CALLS,),
    ),
    VulnType.ACCESS_CONTROL: TaxonomyEntry(
        VulnType.ACCESS_CONTROL, "Access Control",
        swc=("SWC-105", "SWC-106", "SWC-115"), cwe=("CWE-284", "CWE-269"),
        owasp="SC01:2025-Access-Control",
    ),
    VulnType.ARITHMETIC: TaxonomyEntry(
        VulnType.ARITHMETIC, "Arithmetic (over/underflow)",
        swc=("SWC-101",), cwe=("CWE-682",), owasp="SC02:2025-Arithmetic",
    ),
    VulnType.UNCHECKED_CALLS: TaxonomyEntry(
        VulnType.UNCHECKED_CALLS, "Unchecked / low-level calls",
        swc=("SWC-104",), cwe=("CWE-252",), owasp="SC04:2025-Unchecked-Return",
        related=(VulnType.REENTRANCY, VulnType.DENIAL_OF_SERVICE),
    ),
    VulnType.BAD_RANDOMNESS: TaxonomyEntry(
        VulnType.BAD_RANDOMNESS, "Bad randomness / predictable source",
        swc=("SWC-120",), cwe=("CWE-330",), owasp="SC08:2025-Randomness",
        related=(VulnType.TIME_MANIPULATION,),
    ),
    VulnType.DENIAL_OF_SERVICE: TaxonomyEntry(
        VulnType.DENIAL_OF_SERVICE, "Denial of service",
        swc=("SWC-113", "SWC-128"), cwe=("CWE-400",), owasp="SC10:2025-DoS",
        related=(VulnType.UNCHECKED_CALLS,),
    ),
    VulnType.FRONT_RUNNING: TaxonomyEntry(
        VulnType.FRONT_RUNNING, "Front running / transaction ordering",
        swc=("SWC-114",), cwe=("CWE-362",), owasp="SC07:2025-Front-Running",
    ),
    VulnType.TIME_MANIPULATION: TaxonomyEntry(
        VulnType.TIME_MANIPULATION, "Time manipulation / block dependence",
        swc=("SWC-116",), cwe=("CWE-829",), owasp="SC08:2025-Randomness",
        related=(VulnType.BAD_RANDOMNESS,),
    ),
    VulnType.SHORT_ADDRESS: TaxonomyEntry(
        VulnType.SHORT_ADDRESS, "Short address / parameter",
        swc=("SWC-129",), cwe=("CWE-20",),
    ),
    VulnType.OTHER: TaxonomyEntry(
        VulnType.OTHER, "Other / uncategorised",
    ),
    VulnType.BENIGN: TaxonomyEntry(
        VulnType.BENIGN, "Benign (no weakness)",
    ),
}


def entry(vt: VulnType) -> TaxonomyEntry:
    return TAXONOMY[vt]


def are_related(a: VulnType, b: VulnType) -> bool:
    """True if two canonical types are the same or in a parent/child relation.

    Used by the lenient matcher, which accepts related types (proposal S4.4.3,
    e.g. an unchecked external call reported where the label is reentrancy).
    """
    if a == b:
        return True
    return b in TAXONOMY[a].related or a in TAXONOMY[b].related


def from_string(name: str) -> VulnType:
    """Best-effort parse of a free-form type string into a canonical type."""
    if name is None:
        return VulnType.OTHER
    key = name.strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "reentrancy_eth": VulnType.REENTRANCY,
        "reentrancy_no_eth": VulnType.REENTRANCY,
        "reentrancy_benign": VulnType.REENTRANCY,
        "reentrancy_events": VulnType.REENTRANCY,
        "integer_overflow": VulnType.ARITHMETIC,
        "integer_underflow": VulnType.ARITHMETIC,
        "overflow": VulnType.ARITHMETIC,
        "unchecked_lowlevel": VulnType.UNCHECKED_CALLS,
        "unchecked_send": VulnType.UNCHECKED_CALLS,
        "unchecked_call": VulnType.UNCHECKED_CALLS,
        "unchecked_low_level_calls": VulnType.UNCHECKED_CALLS,
        "tx_origin": VulnType.ACCESS_CONTROL,
        "suicidal": VulnType.ACCESS_CONTROL,
        "arbitrary_send": VulnType.ACCESS_CONTROL,
        "weak_prng": VulnType.BAD_RANDOMNESS,
        "block_timestamp": VulnType.TIME_MANIPULATION,
        "timestamp": VulnType.TIME_MANIPULATION,
        "time_dependency": VulnType.TIME_MANIPULATION,
        "dos": VulnType.DENIAL_OF_SERVICE,
        "denial_of_service": VulnType.DENIAL_OF_SERVICE,
    }
    if key in aliases:
        return aliases[key]
    for vt in VulnType:
        if vt.value == key:
            return vt
    return VulnType.OTHER
