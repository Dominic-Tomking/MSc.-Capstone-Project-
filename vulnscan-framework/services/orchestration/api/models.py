"""PostgreSQL schema for contracts, scans, findings, labels and metrics.

Mirrors the common vulnerability schema (proposal Table 2) and the entities the
evaluation pipeline needs (contracts, scans, findings, labels, metrics).
"""
from __future__ import annotations

from django.db import models


class Contract(models.Model):
    """A submitted or curated smart contract."""

    contract_id = models.CharField(max_length=128, unique=True, db_index=True)
    name = models.CharField(max_length=200, blank=True)
    source = models.TextField()
    solidity_version = models.CharField(max_length=32, blank=True)
    category = models.CharField(max_length=64, blank=True)  # DeFi / general-purpose
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:  # pragma: no cover
        return f"{self.name or self.contract_id}"


class Scan(models.Model):
    """One analysis run over a contract by one or more engines."""

    STATUS = [
        ("pending", "pending"), ("running", "running"),
        ("completed", "completed"), ("failed", "failed"),
    ]
    contract = models.ForeignKey(Contract, related_name="scans", on_delete=models.CASCADE)
    status = models.CharField(max_length=16, choices=STATUS, default="pending")
    engines = models.JSONField(default=list)          # ["slither","smartcheck","codebert"]
    run_info = models.JSONField(default=dict)         # per-engine timing/metadata
    errors = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)


class Finding(models.Model):
    """A normalised finding produced by a detection engine (schema Table 2)."""

    scan = models.ForeignKey(Scan, related_name="findings", on_delete=models.CASCADE)
    contract = models.ForeignKey(Contract, related_name="findings", on_delete=models.CASCADE)
    source = models.CharField(max_length=32)          # slither/smartcheck/codebert/testnet
    vuln_type = models.CharField(max_length=48)
    severity = models.CharField(max_length=16)
    function = models.CharField(max_length=200, blank=True, null=True)
    start_line = models.IntegerField(null=True, blank=True)
    end_line = models.IntegerField(null=True, blank=True)
    confidence = models.FloatField(default=1.0)
    raw_type = models.CharField(max_length=128, blank=True)
    evidence_ref = models.CharField(max_length=256, blank=True)
    message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)


class Label(models.Model):
    """A ground-truth vulnerability label with an evidence citation (S4.3)."""

    contract = models.ForeignKey(Contract, related_name="labels", on_delete=models.CASCADE)
    vuln_type = models.CharField(max_length=48)
    severity = models.CharField(max_length=16)
    function = models.CharField(max_length=200, blank=True, null=True)
    start_line = models.IntegerField(null=True, blank=True)
    end_line = models.IntegerField(null=True, blank=True)
    evidence_ref = models.CharField(max_length=256)
    note = models.TextField(blank=True)


class AggregatedFinding(models.Model):
    """A fused cluster from the aggregation engine (consensus / conflict)."""

    scan = models.ForeignKey(Scan, related_name="aggregated", on_delete=models.CASCADE)
    contract = models.ForeignKey(Contract, on_delete=models.CASCADE)
    vuln_type = models.CharField(max_length=48)
    severity = models.CharField(max_length=16)
    methods = models.JSONField(default=list)
    consensus = models.BooleanField(default=False)
    risk_score = models.FloatField(default=0.0)
    function = models.CharField(max_length=200, blank=True, null=True)
    start_line = models.IntegerField(null=True, blank=True)
    end_line = models.IntegerField(null=True, blank=True)


class ValidationRecord(models.Model):
    """Outcome of a testnet validation attempt (S4.2.2)."""

    contract = models.ForeignKey(Contract, related_name="validations", on_delete=models.CASCADE)
    vuln_type = models.CharField(max_length=48)
    scenario = models.CharField(max_length=48)
    outcome = models.CharField(max_length=32)         # exploit_confirmed / not_reproduced / needs_review
    detail = models.JSONField(default=dict)
    trace = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)


class MetricRecord(models.Model):
    """A per-method / per-mode evaluation metric snapshot (S4.5)."""

    method = models.CharField(max_length=32)
    mode = models.CharField(max_length=16)            # strict / lenient
    payload = models.JSONField(default=dict)          # per_type/macro/micro/coverage
    created_at = models.DateTimeField(auto_now_add=True)
