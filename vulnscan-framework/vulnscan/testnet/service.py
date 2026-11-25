"""TestnetValidationService — dynamic confirmation of static/NLP findings.

Contracts selected for runtime validation are deployed to a controlled local
Ethereum environment and an exploit scenario is executed to confirm or refute
the reported vulnerability (proposal S4.2.2).  Each attempt records one of three
outcomes and preserves a trace so that every validation result is independently
reproducible.

The service delegates EVM execution to :mod:`vulnscan.testnet.worker`, run in an
isolated virtualenv, so that the EVM stack (``web3<7`` + ``eth-tester``) does
not collide with the analysis stack.  A Hardhat/Anvil backend is a drop-in
replacement (``hardhat_project/``) for validation against a full node.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from ..schema.taxonomy import VulnType

HERE = Path(__file__).resolve().parent
SOL_DIR = HERE / "scenarios_sol"
DEFAULT_VENV_PY = os.environ.get(
    "TESTNET_PYTHON", "/home/claude/.venv-testnet/bin/python")
DEFAULT_SOLC = os.environ.get(
    "TESTNET_SOLC",
    str(Path.home() / ".solc-select/artifacts/solc-0.8.19/solc-0.8.19"))


class Outcome(str, Enum):
    EXPLOIT_CONFIRMED = "exploit_confirmed"
    NOT_REPRODUCED = "not_reproduced"
    NEEDS_REVIEW = "needs_review"


# Which scenario handles which canonical vulnerability type.  Types without a
# scripted exploit fall back to a deploy-probe recorded for manual review.
SCENARIO_FOR_TYPE = {
    VulnType.REENTRANCY: "reentrancy",
}

# Bundled attacker contracts per scenario.
SCENARIO_ATTACKER = {
    "reentrancy": ("ReentrancyAttacker.sol", "ReentrancyAttacker"),
}


@dataclass
class ValidationResult:
    contract_id: str
    vuln_type: str
    scenario: str
    outcome: Outcome
    detail: dict = field(default_factory=dict)
    trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "contract_id": self.contract_id,
            "vuln_type": self.vuln_type,
            "scenario": self.scenario,
            "outcome": self.outcome.value,
            "detail": self.detail,
            "trace": self.trace,
        }


class TestnetValidationService:
    def __init__(self, venv_python: str = DEFAULT_VENV_PY,
                 solc: str = DEFAULT_SOLC, timeout: int = 180):
        self.venv_python = venv_python
        self.solc = solc
        self.timeout = timeout

    def available(self) -> bool:
        return Path(self.venv_python).exists() and Path(self.solc).exists()

    def validate(self, target_source: str, target_name: str,
                 vuln_type: VulnType, contract_id: Optional[str] = None,
                 **scenario_kwargs) -> ValidationResult:
        cid = contract_id or target_name
        scenario = SCENARIO_FOR_TYPE.get(vuln_type, "deploy_probe")
        job = {
            "solc": self.solc,
            "target_source": str(target_source),
            "target_name": target_name,
            "scenario": scenario,
            **scenario_kwargs,
        }
        if scenario in SCENARIO_ATTACKER:
            att_file, att_name = SCENARIO_ATTACKER[scenario]
            job["attacker_source"] = str(SOL_DIR / att_file)
            job["attacker_name"] = att_name

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(job, tf)
            job_path = tf.name
        try:
            proc = subprocess.run(
                [self.venv_python, str(HERE / "worker.py"), job_path],
                capture_output=True, text=True, timeout=self.timeout)
        finally:
            Path(job_path).unlink(missing_ok=True)

        try:
            payload = json.loads(proc.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            payload = {"outcome": "needs_review",
                       "error": (proc.stderr or proc.stdout)[-800:]}

        outcome = Outcome(payload.get("outcome", "needs_review"))
        trace = payload.pop("trace", [])
        return ValidationResult(
            contract_id=cid, vuln_type=vuln_type.value, scenario=scenario,
            outcome=outcome, detail=payload, trace=trace)
