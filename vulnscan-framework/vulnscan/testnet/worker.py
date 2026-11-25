#!/usr/bin/env python3
"""Testnet validation worker (runs inside the isolated EVM virtualenv).

This script is executed by the ``web3<7`` + ``eth-tester`` virtualenv (kept
separate from the main environment so its dependencies do not collide with
Slither's).  It reads a job description on argv, compiles the target and any
attacker contract with the native ``solc``, deploys them to an in-process
PyEVM chain, runs the exploit scenario, and prints a JSON result describing one
of three outcomes: ``exploit_confirmed`` / ``not_reproduced`` / ``needs_review``
(proposal S4.2.2).

Deploying to a real Hardhat Network or Foundry Anvil node is a drop-in
alternative backend (see ``hardhat_project/``); the in-process chain is used
here because it needs no compiler download and is fully deterministic.
"""
from __future__ import annotations

import json
import subprocess
import sys
import traceback
from pathlib import Path

from web3 import Web3, EthereumTesterProvider


def compile_sources(solc: str, sources: list[str]) -> dict:
    proc = subprocess.run(
        [solc, "--combined-json", "abi,bin", *sources],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"solc failed: {proc.stderr.strip()[-500:]}")
    return json.loads(proc.stdout)["contracts"]


def _pick(contracts: dict, name: str):
    keys = [k for k in contracts if k.endswith(":" + name)]
    if not keys:
        raise RuntimeError(f"contract {name} not found in compiled output")
    c = contracts[keys[0]]
    return c["abi"], c["bin"]


def run_job(job: dict) -> dict:
    solc = job["solc"]
    target_src = job["target_source"]
    target_name = job["target_name"]
    scenario = job["scenario"]
    attacker_src = job.get("attacker_source")
    attacker_name = job.get("attacker_name")

    sources = [target_src] + ([attacker_src] if attacker_src else [])
    contracts = compile_sources(solc, sources)

    w3 = Web3(EthereumTesterProvider())
    deployer, victim_eoa, attacker_eoa = w3.eth.accounts[:3]
    w3.eth.default_account = deployer
    trace: list[str] = []

    def deploy(name, *args):
        abi, binn = _pick(contracts, name)
        ct = w3.eth.contract(abi=abi, bytecode=binn)
        rcpt = w3.eth.wait_for_transaction_receipt(
            ct.constructor(*args).transact({"from": deployer}))
        trace.append(f"deploy {name} -> {rcpt.contractAddress} (gas {rcpt.gasUsed})")
        return w3.eth.contract(address=rcpt.contractAddress, abi=abi)

    result = {"scenario": scenario, "outcome": "needs_review", "trace": trace}

    if scenario == "reentrancy":
        seed = int(job.get("seed_wei", Web3.to_wei(5, "ether")))
        stake = int(job.get("stake_wei", Web3.to_wei(1, "ether")))
        deposit_fn = job.get("deposit_fn", "deposit")
        withdraw_fn = job.get("withdraw_fn", "withdraw")

        bank = deploy(target_name)
        getattr(bank.functions, deposit_fn)().transact(
            {"from": victim_eoa, "value": seed})
        trace.append(f"honest deposit {seed} wei by {victim_eoa[:10]}")
        attacker = deploy(attacker_name, bank.address)
        before = w3.eth.get_balance(bank.address)
        try:
            attacker.functions.attack().transact(
                {"from": attacker_eoa, "value": stake})
        except Exception as exc:                      # noqa: BLE001
            trace.append(f"attack reverted: {exc}")
        after = w3.eth.get_balance(bank.address)
        drained = attacker.functions.drained().call()
        hits = attacker.functions.hits().call()
        trace.append(f"bank {before}->{after} wei; attacker holds {drained} wei; "
                     f"reentrant hits={hits}")
        stolen = before - after
        result.update({
            "bank_before_wei": before, "bank_after_wei": after,
            "attacker_balance_wei": drained, "reentrant_hits": hits,
            "stolen_wei": stolen,
            "outcome": "exploit_confirmed" if stolen > 0 else "not_reproduced",
        })

    elif scenario == "deploy_probe":
        # No scripted exploit: confirm the contract deploys and record for
        # manual review (used for types without an automated scenario).
        deploy(target_name)
        result["outcome"] = "needs_review"
        result["note"] = "deployed successfully; no automated exploit scenario"

    else:
        result["outcome"] = "needs_review"
        result["note"] = f"unknown scenario '{scenario}'"

    return result


def main() -> None:
    job = json.loads(Path(sys.argv[1]).read_text())
    try:
        print(json.dumps(run_job(job)))
    except Exception:                                  # noqa: BLE001
        print(json.dumps({"outcome": "needs_review",
                          "error": traceback.format_exc()[-1500:]}))


if __name__ == "__main__":
    main()
