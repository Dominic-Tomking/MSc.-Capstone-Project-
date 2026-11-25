"""Bridge between the Django orchestration layer and the vulnscan engines.

Keeps Django thin: this module is the only place the orchestration app touches
the detection package.  It can either call the static-analysis microservice over
HTTP or run the engines in-process (controlled by ``STATIC_ANALYSIS_MODE``).
"""
from __future__ import annotations

from typing import Optional

from django.conf import settings

from vulnscan.aggregation import FusionEngine
from vulnscan.schema.finding import Finding as VFinding
from vulnscan.static_analysis import StaticAnalysisService


def run_static_analysis(source: str, contract_id: str) -> dict:
    """Return normalised findings + run info for a contract source."""
    if settings.STATIC_ANALYSIS_MODE == "http":
        import requests
        resp = requests.post(
            f"{settings.STATIC_ANALYSIS_URL}/analyse",
            json={"source": source, "contract_id": contract_id}, timeout=600)
        resp.raise_for_status()
        return resp.json()

    svc = StaticAnalysisService()
    result = svc.analyse_source(source, contract_id=contract_id)
    return {
        "contract_id": result.contract_id,
        "findings": [f.to_dict() for f in result.findings],
        "run_info": result.run_info,
        "errors": result.errors,
    }


def aggregate(findings_dicts: list[dict], contract_id: str) -> dict:
    """Aggregate a list of finding dicts (any source) into a fused report."""
    findings = [_finding_from_dict(d) for d in findings_dicts]
    report = FusionEngine().aggregate(findings, contract_id=contract_id)
    return report.to_dict()


def _finding_from_dict(d: dict) -> VFinding:
    from vulnscan.schema.finding import Location, Source
    from vulnscan.schema.severity import Severity
    from vulnscan.schema.taxonomy import from_string
    loc = d.get("location", {})
    return VFinding(
        contract_id=d["contract_id"],
        vuln_type=from_string(d["vuln_type"]),
        severity=Severity.from_label(d["severity"]),
        location=Location(function=loc.get("function"),
                          start_line=loc.get("start_line"),
                          end_line=loc.get("end_line")),
        source=Source(d["source"]),
        confidence=d.get("confidence", 1.0),
        evidence_ref=d.get("evidence_ref", ""),
        raw_type=d.get("raw_type", ""),
        message=d.get("message", ""),
    )
