"""StaticAnalysisService — run Slither and SmartCheck and return normalised
findings for a contract, together with per-tool run metadata.

This is the object wrapped by the containerised static-analysis microservice
(proposal S4.1 "Static analysis service").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..schema.finding import Finding
from . import slither_adapter, smartcheck_adapter


@dataclass
class StaticAnalysisResult:
    contract_id: str
    findings: list[Finding] = field(default_factory=list)
    run_info: dict = field(default_factory=dict)   # tool -> info
    errors: dict = field(default_factory=dict)     # tool -> error string

    def by_source(self, source) -> list[Finding]:
        return [f for f in self.findings if f.source == source]


class StaticAnalysisService:
    def __init__(self, use_slither: bool = True, use_smartcheck: bool = True,
                 timeout: int = 300):
        self.use_slither = use_slither
        self.use_smartcheck = use_smartcheck
        self.timeout = timeout

    def analyse_file(self, source_path: str,
                     contract_id: Optional[str] = None) -> StaticAnalysisResult:
        src = Path(source_path).read_text(encoding="utf-8", errors="ignore")
        cid = contract_id or Finding.contract_id_from_source(src)
        result = StaticAnalysisResult(contract_id=cid)

        if self.use_slither:
            try:
                f, info = slither_adapter.run(source_path, cid, timeout=self.timeout)
                result.findings += f
                result.run_info["slither"] = info
            except Exception as exc:                      # noqa: BLE001
                result.errors["slither"] = str(exc)

        if self.use_smartcheck:
            try:
                f, info = smartcheck_adapter.run(source_path, cid, timeout=self.timeout)
                result.findings += f
                result.run_info["smartcheck"] = info
            except Exception as exc:                      # noqa: BLE001
                result.errors["smartcheck"] = str(exc)

        return result

    def analyse_source(self, source_code: str,
                       contract_id: Optional[str] = None) -> StaticAnalysisResult:
        import tempfile
        cid = contract_id or Finding.contract_id_from_source(source_code)
        with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as tf:
            tf.write(source_code)
            path = tf.name
        try:
            return self.analyse_file(path, cid)
        finally:
            Path(path).unlink(missing_ok=True)
