"""Map tool-specific detector identifiers onto the canonical taxonomy.

Slither detector checks and SmartCheck rule ids are translated to
:class:`~vulnscan.schema.taxonomy.VulnType`.  Detectors that only concern style,
naming or gas (i.e. not a security weakness in the project's taxonomy) map to
``None`` and are dropped from the security comparison, though they are retained
in the raw archive for traceability.
"""
from __future__ import annotations

from typing import Optional

from ..schema.taxonomy import VulnType

# --- Slither: `check` field -> canonical type -------------------------------
# Keys are Slither detector `check` identifiers (stable machine-readable ids).
SLITHER_MAP: dict[str, Optional[VulnType]] = {
    # reentrancy family
    "reentrancy-eth": VulnType.REENTRANCY,
    "reentrancy-no-eth": VulnType.REENTRANCY,
    "reentrancy-benign": VulnType.REENTRANCY,
    "reentrancy-events": VulnType.REENTRANCY,
    "reentrancy-unlimited-gas": VulnType.REENTRANCY,
    # unchecked / low-level calls
    "unchecked-lowlevel": VulnType.UNCHECKED_CALLS,
    "unchecked-send": VulnType.UNCHECKED_CALLS,
    "unused-return": VulnType.UNCHECKED_CALLS,
    "low-level-calls": VulnType.UNCHECKED_CALLS,
    "mstore-callvalue": VulnType.UNCHECKED_CALLS,
    # access control
    "suicidal": VulnType.ACCESS_CONTROL,
    "arbitrary-send-eth": VulnType.ACCESS_CONTROL,
    "arbitrary-send": VulnType.ACCESS_CONTROL,
    "arbitrary-send-erc20": VulnType.ACCESS_CONTROL,
    "tx-origin": VulnType.ACCESS_CONTROL,
    "protected-vars": VulnType.ACCESS_CONTROL,
    "unprotected-upgrade": VulnType.ACCESS_CONTROL,
    "controlled-delegatecall": VulnType.ACCESS_CONTROL,
    "delegatecall-loop": VulnType.ACCESS_CONTROL,
    # arithmetic
    "divide-before-multiply": VulnType.ARITHMETIC,
    "tautology": VulnType.ARITHMETIC,
    "incorrect-equality": VulnType.ARITHMETIC,
    "integer-overflow": VulnType.ARITHMETIC,
    # randomness
    "weak-prng": VulnType.BAD_RANDOMNESS,
    # time / block dependence
    "timestamp": VulnType.TIME_MANIPULATION,
    "block-other-parameters": VulnType.TIME_MANIPULATION,
    # denial of service
    "calls-loop": VulnType.DENIAL_OF_SERVICE,
    "costly-loop": VulnType.DENIAL_OF_SERVICE,
    "locked-ether": VulnType.DENIAL_OF_SERVICE,
    "msg-value-loop": VulnType.DENIAL_OF_SERVICE,
    # uninitialised storage -> access-control-ish; keep as OTHER-ish security
    "uninitialized-state": VulnType.ACCESS_CONTROL,
    "uninitialized-storage": VulnType.ACCESS_CONTROL,
    # explicitly non-security (dropped from security comparison)
    "naming-convention": None,
    "solc-version": None,
    "pragma": None,
    "external-function": None,
    "constable-states": None,
    "immutable-states": None,
    "assembly": None,
    "dead-code": None,
    "similar-names": None,
    "too-many-digits": None,
    "missing-zero-check": None,
    "missing-inheritance": None,
    "reentrancy-benign-events": None,
    "unused-state": None,
    "shadowing-local": None,
    "shadowing-abstract": None,
    "var-read-using-this": None,
    "cyclomatic-complexity": None,
}

# --- SmartCheck: ruleId -> canonical type -----------------------------------
SMARTCHECK_MAP: dict[str, Optional[VulnType]] = {
    "SOLIDITY_UNCHECKED_CALL": VulnType.UNCHECKED_CALLS,
    "SOLIDITY_CALL_WITHOUT_DATA": VulnType.REENTRANCY,
    "SOLIDITY_CALL_VALUE": VulnType.UNCHECKED_CALLS,
    "SOLIDITY_SEND": VulnType.UNCHECKED_CALLS,
    "SOLIDITY_TRANSFER_IN_LOOP": VulnType.DENIAL_OF_SERVICE,
    "SOLIDITY_EXACT_TIME": VulnType.TIME_MANIPULATION,
    "SOLIDITY_GAS_LIMIT_IN_LOOPS": VulnType.DENIAL_OF_SERVICE,
    "SOLIDITY_TX_ORIGIN": VulnType.ACCESS_CONTROL,
    "SOLIDITY_OVERPOWERED_ROLE": VulnType.ACCESS_CONTROL,
    "SOLIDITY_UNINITIALIZED_STORAGE_POINTER": VulnType.ACCESS_CONTROL,
    "SOLIDITY_INTEGER_OVERFLOW": VulnType.ARITHMETIC,
    "SOLIDITY_DIV_MUL": VulnType.ARITHMETIC,
    "SOLIDITY_BLOCKHASH": VulnType.BAD_RANDOMNESS,
    "SOLIDITY_WEAK_RANDOM": VulnType.BAD_RANDOMNESS,
    "SOLIDITY_LOCKED_MONEY": VulnType.DENIAL_OF_SERVICE,
    "SOLIDITY_REENTRANCY": VulnType.REENTRANCY,
    "SOLIDITY_DOS_WITH_THROW": VulnType.DENIAL_OF_SERVICE,
    "SOLIDITY_FRONT_RUNNING": VulnType.FRONT_RUNNING,
    # non-security / upgrade advisories (dropped)
    "SOLIDITY_PRAGMAS_VERSION": None,
    "SOLIDITY_UPGRADE_TO_050": None,
    "SOLIDITY_DEPRECATED_CONSTRUCTIONS": None,
    "SOLIDITY_VISIBILITY": None,
    "SOLIDITY_ADDRESS_HARDCODED": None,
    "SOLIDITY_SHOULD_NOT_BE_PURE": None,
    "SOLIDITY_ERC20_APPROVE": None,
    "SOLIDITY_EXTRA_GAS_IN_LOOPS": None,
    "SOLIDITY_REDUNDANT_FALLBACK_REJECT": None,
    "SOLIDITY_USING_INLINE_ASSEMBLY": None,
}


def map_slither(check: str) -> Optional[VulnType]:
    if check in SLITHER_MAP:
        return SLITHER_MAP[check]
    # unknown detector: keep as OTHER so it is not silently lost
    return VulnType.OTHER


def map_smartcheck(rule_id: str) -> Optional[VulnType]:
    if rule_id in SMARTCHECK_MAP:
        return SMARTCHECK_MAP[rule_id]
    return VulnType.OTHER
