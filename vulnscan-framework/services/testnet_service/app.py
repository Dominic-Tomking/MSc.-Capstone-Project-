"""Testnet validation microservice (proposal S4.1 "Testnet validation service").

A thin FastAPI wrapper around :class:`vulnscan.testnet.TestnetValidationService`.
Given a contract source and a reported vulnerability type, it deploys the
contract to a controlled local EVM, runs the matching exploit scenario, and
returns the outcome (exploit_confirmed / not_reproduced / needs_review) with a
reproducible trace.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from fastapi import FastAPI                       # noqa: E402
from pydantic import BaseModel                     # noqa: E402

from vulnscan.schema.taxonomy import from_string   # noqa: E402
from vulnscan.testnet import TestnetValidationService  # noqa: E402

app = FastAPI(title="vulnscan testnet service", version="0.1.0")
_service = TestnetValidationService()


class ValidateRequest(BaseModel):
    source: str
    contract_name: str
    vuln_type: str
    contract_id: str | None = None


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "evm_available": _service.available()}


@app.post("/validate")
def validate(req: ValidateRequest) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".sol", delete=False) as tf:
        tf.write(req.source)
        path = tf.name
    try:
        res = _service.validate(
            path, req.contract_name, from_string(req.vuln_type),
            contract_id=req.contract_id)
        return res.to_dict()
    finally:
        Path(path).unlink(missing_ok=True)
