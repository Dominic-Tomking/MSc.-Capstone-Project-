"""REST API: submit contracts, trigger scans, retrieve reports."""
from __future__ import annotations

from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from vulnscan.schema.finding import Finding as VFinding

from .models import Contract, Scan
from .serializers import (ContractSerializer, ScanSerializer)
from .tasks import run_scan


class ContractViewSet(viewsets.ModelViewSet):
    queryset = Contract.objects.all().order_by("-created_at")
    serializer_class = ContractSerializer

    def perform_create(self, serializer):
        source = serializer.validated_data["source"]
        cid = serializer.validated_data.get("contract_id") \
            or VFinding.contract_id_from_source(source)
        serializer.save(contract_id=cid)

    @action(detail=True, methods=["post"])
    def scan(self, request, pk=None):
        """Kick off an asynchronous scan for this contract."""
        contract = self.get_object()
        engines = request.data.get("engines", ["slither", "smartcheck"])
        scan = Scan.objects.create(contract=contract, engines=engines)
        # dispatch to Celery (or run eagerly in dev/CI)
        async_result = run_scan.delay(scan.id)
        return Response(
            {"scan_id": scan.id, "status": scan.status,
             "task": getattr(async_result, "id", "eager")},
            status=status.HTTP_202_ACCEPTED)


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Scan.objects.all().order_by("-created_at")
    serializer_class = ScanSerializer

    @action(detail=True, methods=["get"])
    def report(self, request, pk=None):
        """Return the ranked, aggregated report for a completed scan."""
        scan = self.get_object()
        agg = [
            {"vuln_type": a.vuln_type, "severity": a.severity,
             "methods": a.methods, "consensus": a.consensus,
             "risk_score": a.risk_score,
             "location": {"function": a.function,
                          "start_line": a.start_line, "end_line": a.end_line}}
            for a in scan.aggregated.all().order_by("-risk_score")
        ]
        return Response({
            "scan_id": scan.id, "status": scan.status,
            "contract_id": scan.contract.contract_id,
            "n_findings": scan.findings.count(),
            "consensus": [a for a in agg if a["consensus"]],
            "all": agg,
        })
