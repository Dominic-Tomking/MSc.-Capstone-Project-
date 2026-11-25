"""Integration tests that invoke the real tools (Slither, SmartCheck, EVM).

Skipped automatically when a tool is not available, so the pure-logic suite can
still run in a minimal environment.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vulnscan.schema.taxonomy import VulnType
from vulnscan.static_analysis import StaticAnalysisService
from vulnscan.static_analysis import smartcheck_adapter as sc
from vulnscan.testnet import Outcome, TestnetValidationService

SAMPLES = ROOT / "contracts_samples"
SOL = ROOT / "vulnscan" / "testnet" / "scenarios_sol"


def _slither_ok() -> bool:
    import shutil
    return shutil.which("slither") is not None


@pytest.mark.skipif(not _slither_ok(), reason="slither not installed")
def test_static_analysis_reentrancy_real():
    svc = StaticAnalysisService(use_smartcheck=sc.available())
    res = svc.analyse_file(str(SAMPLES / "Reentrancy.sol"), contract_id="Reentrancy")
    types = {f.vuln_type for f in res.findings}
    assert VulnType.REENTRANCY in types
    assert "slither" in res.run_info


@pytest.mark.skipif(not TestnetValidationService().available(),
                    reason="EVM venv not available")
def test_testnet_reentrancy_confirmed_real():
    svc = TestnetValidationService()
    res = svc.validate(str(SOL / "VulnerableBank.sol"), "VulnerableBank",
                       VulnType.REENTRANCY, contract_id="VulnerableBank")
    assert res.outcome is Outcome.EXPLOIT_CONFIRMED
    assert res.detail["stolen_wei"] > 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
