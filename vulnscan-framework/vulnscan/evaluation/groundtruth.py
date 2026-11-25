"""Load the labelled ground-truth dataset into the common schema.

The dataset is a JSON file: a list of contract records, each carrying the
contract id, an optional source path, and a list of vulnerability-level labels
with SWC/CWE mappings, affected function + line range, severity and an evidence
citation (proposal S4.3).  Every label is traceable to a cited source.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..schema.finding import Finding, Location, Source
from ..schema.severity import Severity, baseline
from ..schema.taxonomy import VulnType, from_string


def label_to_finding(contract_id: str, label: dict) -> Finding:
    vt = from_string(label["vuln_type"])
    sev = (Severity.from_label(label["severity"]) if label.get("severity")
           else baseline(vt))
    loc = Location(
        function=label.get("function"),
        start_line=label.get("start_line"),
        end_line=label.get("end_line", label.get("start_line")),
        file=label.get("file"),
    )
    return Finding(
        contract_id=contract_id,
        vuln_type=vt,
        severity=sev,
        location=loc,
        source=Source.GROUND_TRUTH,
        confidence=1.0,
        evidence_ref=label.get("evidence_ref", ""),
        raw_type=label["vuln_type"],
        message=label.get("note", ""),
    )


def load(path: str) -> list[Finding]:
    data = json.loads(Path(path).read_text())
    records = data["contracts"] if isinstance(data, dict) else data
    labels: list[Finding] = []
    for rec in records:
        cid = rec["contract_id"]
        for lab in rec.get("labels", []):
            labels.append(label_to_finding(cid, lab))
    return labels


def load_map(path: str) -> dict[str, str]:
    """Return contract_id -> source_path for driving scans over the dataset."""
    data = json.loads(Path(path).read_text())
    records = data["contracts"] if isinstance(data, dict) else data
    return {rec["contract_id"]: rec.get("path", "") for rec in records}
