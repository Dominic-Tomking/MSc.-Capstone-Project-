from rest_framework import serializers

from .models import (AggregatedFinding, Contract, Finding, Label, Scan,
                     ValidationRecord)


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = ["id", "source", "vuln_type", "severity", "function",
                  "start_line", "end_line", "confidence", "raw_type",
                  "evidence_ref", "message"]


class AggregatedFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = AggregatedFinding
        fields = ["id", "vuln_type", "severity", "methods", "consensus",
                  "risk_score", "function", "start_line", "end_line"]


class ScanSerializer(serializers.ModelSerializer):
    findings = FindingSerializer(many=True, read_only=True)
    aggregated = AggregatedFindingSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = ["id", "contract", "status", "engines", "run_info", "errors",
                  "created_at", "finished_at", "findings", "aggregated"]


class ContractSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contract
        fields = ["id", "contract_id", "name", "source", "solidity_version",
                  "category", "created_at"]
        read_only_fields = ["contract_id", "created_at"]


class LabelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Label
        fields = "__all__"


class ValidationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ValidationRecord
        fields = "__all__"
