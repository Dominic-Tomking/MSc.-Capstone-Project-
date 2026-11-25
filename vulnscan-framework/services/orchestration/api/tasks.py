"""Celery tasks: asynchronous scan orchestration.

A scan is dispatched as a task; the worker runs the static-analysis engines
(and, when requested, testnet validation), persists normalised findings and the
fused aggregation report, and marks the scan completed.
"""
from __future__ import annotations

from django.utils import timezone

try:
    from celery import shared_task
except Exception:  # pragma: no cover - allow import without celery installed
    def shared_task(*a, **k):
        def deco(fn):
            fn.delay = fn  # eager fallback
            return fn
        return deco

from . import services
from .models import (AggregatedFinding, Contract, Finding, Scan)


@shared_task
def run_scan(scan_id: int) -> dict:
    scan = Scan.objects.get(pk=scan_id)
    contract = scan.contract
    scan.status = "running"
    scan.save(update_fields=["status"])
    try:
        payload = services.run_static_analysis(contract.source, contract.contract_id)
        scan.run_info = payload.get("run_info", {})
        scan.errors = payload.get("errors", {})

        finding_dicts = payload.get("findings", [])
        Finding.objects.filter(scan=scan).delete()
        for d in finding_dicts:
            loc = d.get("location", {})
            Finding.objects.create(
                scan=scan, contract=contract, source=d["source"],
                vuln_type=d["vuln_type"], severity=d["severity"],
                function=loc.get("function"),
                start_line=loc.get("start_line"), end_line=loc.get("end_line"),
                confidence=d.get("confidence", 1.0),
                raw_type=d.get("raw_type", ""),
                evidence_ref=d.get("evidence_ref", ""),
                message=d.get("message", ""), metadata=d.get("metadata", {}),
            )

        agg = services.aggregate(finding_dicts, contract.contract_id)
        AggregatedFinding.objects.filter(scan=scan).delete()
        for c in agg.get("findings", []):
            loc = c.get("location", {})
            AggregatedFinding.objects.create(
                scan=scan, contract=contract, vuln_type=c["vuln_type"],
                severity=c["severity"], methods=c["methods"],
                consensus=c["consensus"], risk_score=c["risk_score"],
                function=loc.get("function"),
                start_line=loc.get("start_line"), end_line=loc.get("end_line"),
            )

        scan.status = "completed"
        scan.finished_at = timezone.now()
        scan.save()
        return {"scan_id": scan_id, "status": "completed",
                "n_findings": len(finding_dicts),
                "n_aggregated": len(agg.get("findings", []))}
    except Exception as exc:  # noqa: BLE001
        scan.status = "failed"
        scan.errors = {**(scan.errors or {}), "task": str(exc)}
        scan.save()
        raise
