# vulnscan — Automated Vulnerability-Scanning Framework for Ethereum Smart Contracts

Reference implementation of the **non-NLP segments** of the capstone framework:
the static-analysis service (Slither + SmartCheck), the testnet-validation
service (in-process EVM / Hardhat), the aggregation & fusion engine, the common
vulnerability schema, the ground-truth matching procedure and the evaluation
harness, plus the Django orchestration layer and Docker deployment.

The CodeBERT / NLP detection component is delivered separately; it plugs into
the same `Finding` schema and the same aggregation and evaluation code, so the
three engines can be compared head-to-head (proposal §4.5).

```
Solidity contract
   │
   ├─► Static analysis service ──► Slither  (JSON)  ─┐
   │                              SmartCheck (text) ─┤
   ├─► NLP service (CodeBERT) ───────────────────────┤ normalised Findings
   │                                                  ├─► Fusion engine ─► ranked report
   └─► Testnet validation ───► exploit simulation ───┘        │  (dedup / consensus / conflict)
                                                              ▼
                              Ground-truth matching (strict + lenient) ─► metrics
```

## What is implemented

| Segment | Module | Status |
|---|---|---|
| Common vulnerability schema (Table 2) | `vulnscan/schema/finding.py` | ✅ |
| Taxonomy + SWC/CWE/OWASP mapping (§4.4.2) | `vulnscan/schema/taxonomy.py` | ✅ |
| Severity normalisation (§4.4.2) | `vulnscan/schema/severity.py` | ✅ |
| Slither adapter (JSON) | `vulnscan/static_analysis/slither_adapter.py` | ✅ runs |
| SmartCheck adapter (Java 8) | `vulnscan/static_analysis/smartcheck_adapter.py` | ✅ runs |
| Per-contract solc selection | `vulnscan/static_analysis/solc_manager.py` | ✅ |
| Aggregation / fusion (§4.2.4) | `vulnscan/aggregation/fusion.py` | ✅ |
| Ground-truth matching, strict + lenient (§4.4.3–4.4.4) | `vulnscan/evaluation/matching.py` | ✅ |
| Evaluation metrics (§4.5) | `vulnscan/evaluation/metrics.py` | ✅ |
| Testnet validation (§4.2.2) | `vulnscan/testnet/` | ✅ runs (real exploit) |
| Django orchestration + Celery (§4.1) | `services/orchestration/` | ✅ |
| Static-analysis microservice | `services/static_analysis_service/` | ✅ |
| Testnet microservice | `services/testnet_service/` | ✅ |
| Docker / docker-compose (§7.2) | `docker/`, `docker-compose.yml` | ✅ |

## Repository layout

```
vulnscan/                 core library (engine-agnostic)
  schema/                 Finding, taxonomy, severity
  static_analysis/        Slither + SmartCheck adapters, normaliser, solc mgr
  aggregation/            fusion engine (dedup / correlate / consensus)
  evaluation/             matching (strict/lenient) + metrics + ground truth
  testnet/                EVM validation worker, scenarios, Hardhat project
services/
  orchestration/          Django REST API + Celery tasks + PostgreSQL models
  static_analysis_service/FastAPI microservice wrapping the static engines
  testnet_service/        FastAPI microservice wrapping testnet validation
contracts_samples/        sample vulnerable contracts (Solidity 0.4.x)
fixtures/ground_truth.json labelled dataset (schema of the 50–70 corpus)
tests/                    unit + integration tests
run_pipeline.py           end-to-end: scan → aggregate → evaluate
docker-compose.yml        db, redis, api, worker, microservices
```

## Quick start (local, no Docker)

Prerequisites installed by the tooling scripts: Python 3.11, Node 22, Java 8
(for SmartCheck), and one or more `solc` versions in the solc-select store.

```bash
pip install -r requirements.txt
bash docker/install_solc.sh                      # solc 0.4.26 / 0.5.17 / 0.6.12 / 0.8.19
npm install -g @smartdec/smartcheck              # SmartCheck jar
python -m venv .venv-testnet && .venv-testnet/bin/pip install -r requirements-testnet.txt

# run the full static-analysis + aggregation + evaluation pipeline
python run_pipeline.py --dataset fixtures/ground_truth.json --out artifacts

# run the tests
pytest -q
```

## Quick start (Docker)

```bash
docker compose build          # builds the shared tools image + all services
docker compose up             # db, redis, Django API (:8000), worker, microservices
```

Then submit a contract and scan it:

```bash
# create a contract
curl -s localhost:8000/api/contracts/ -H 'Content-Type: application/json' \
  -d '{"name":"Reentrancy","source":"<solidity source>"}'
# trigger a scan (async, dispatched to Celery)
curl -s -X POST localhost:8000/api/contracts/1/scan/ -d '{"engines":["slither","smartcheck"]}'
# fetch the aggregated report
curl -s localhost:8000/api/scans/1/report/
```

## Design notes

* **Isolation of the EVM stack.** Slither requires `web3>=7.10`, whereas
  `eth-tester` requires `web3<7`. The testnet worker therefore runs in its own
  virtualenv (`TESTNET_PYTHON`), invoked as a subprocess — the same isolation
  the containerised microservice architecture provides.
* **Compiler selection.** The solc manager parses each contract's
  `pragma solidity` and passes the matching `solc` to Slither with `--solc`, so
  contracts from 0.4.x to 0.8.x analyse correctly without global state.
* **Strict vs lenient scoring.** Both configurations are always reported so
  that no single scoring choice determines the conclusions (proposal §4.4.4).
  Strict requires exact type + line overlap; lenient accepts related types and
  same-function / contract-level matching.
* **Consensus & conflict.** A defect reported by ≥2 independent engines is a
  consensus finding; single-engine findings are surfaced for manual review
  rather than silently resolved.

## Verified behaviour

Reproduced in this environment on the sample contracts:

* Slither and SmartCheck both execute and normalise to the shared schema.
* The reentrancy sample drains from 5 ETH to 0 in the testnet validator
  (`exploit_confirmed`, 5 reentrant calls) — a genuine dynamic exploit.
* The Django scan task persists findings and produces a consensus reentrancy
  finding (both engines agree, risk score 0.915).
* `pytest` — 19 unit tests + 2 tool-integration tests pass.
```
