"""Static-analysis microservice (proposal S4.1 "Static analysis service").

A thin FastAPI wrapper around :class:`vulnscan.static_analysis.StaticAnalysisService`.
It executes Slither and SmartCheck in this (isolated) container, normalises their
output to the common schema, and returns findings as JSON.  The Django
orchestration layer calls this service over HTTP when ``STATIC_ANALYSIS_MODE=http``.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the top-level vulnscan package importable inside the container.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI                      # noqa: E402
from pydantic import BaseModel                    # noqa: E402

from vulnscan.static_analysis import StaticAnalysisService  # noqa: E402

app = FastAPI(title="vulnscan static-analysis service", version="0.1.0")
_service = StaticAnalysisService()


class AnalyseRequest(BaseModel):
    source: str
    contract_id: str | None = None


@app.get("/health")
def health() -> dict:
    from vulnscan.static_analysis import smartcheck_adapter as sc
    return {"status": "ok", "smartcheck_available": sc.available()}


@app.post("/analyse")
def analyse(req: AnalyseRequest) -> dict:
    result = _service.analyse_source(req.source, contract_id=req.contract_id)
    return {
        "contract_id": result.contract_id,
        "findings": [f.to_dict() for f in result.findings],
        "run_info": result.run_info,
        "errors": result.errors,
    }
