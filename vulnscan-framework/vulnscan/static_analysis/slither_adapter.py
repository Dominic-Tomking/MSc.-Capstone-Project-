"""Slither adapter: run Slither, parse its JSON, normalise to :class:`Finding`.

Slither (Feist, Grieco & Groce, 2019) is executed with its full detector set and
``--json``.  Its machine-readable output is parsed and every security-relevant
detector is mapped onto the common schema, preserving the original ``check`` id
for traceability (proposal S4.2.1).
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..schema.finding import Finding, Location, Source
from ..schema.severity import SLITHER_IMPACT, Severity, baseline
from . import normalizer, solc_manager

# Slither reports a qualitative confidence; rescale to [0, 1] for the schema.
_CONFIDENCE = {"high": 0.9, "medium": 0.6, "low": 0.3, "informational": 0.2}


class SlitherError(RuntimeError):
    pass


def _element_location(detector: dict) -> Location:
    """Extract a (function, start_line, end_line, file) location from a detector."""
    func_name: Optional[str] = None
    lines: list[int] = []
    fname: Optional[str] = None
    for el in detector.get("elements", []):
        sm = el.get("source_mapping", {}) or {}
        el_lines = sm.get("lines", []) or []
        if el.get("type") == "function" and func_name is None:
            func_name = el.get("name")
        if el.get("type") in ("function", "node") and not lines and el_lines:
            lines = el_lines
            fname = sm.get("filename_relative") or sm.get("filename_short")
        # fall back to enclosing function name recorded on nodes
        tf = (el.get("type_specific_fields") or {}).get("parent", {})
        if func_name is None and tf.get("type") == "function":
            func_name = tf.get("name")
    if not lines:
        for el in detector.get("elements", []):
            el_lines = (el.get("source_mapping", {}) or {}).get("lines", []) or []
            if el_lines:
                lines = el_lines
                fname = (el.get("source_mapping", {}) or {}).get("filename_relative")
                break
    return Location(
        function=func_name,
        start_line=min(lines) if lines else None,
        end_line=max(lines) if lines else None,
        file=fname,
    )


def parse_json(data: dict, contract_id: str) -> list[Finding]:
    """Parse a Slither ``--json`` payload into normalised findings."""
    findings: list[Finding] = []
    if not data.get("success", False):
        return findings
    detectors = (data.get("results") or {}).get("detectors", []) or []
    for det in detectors:
        check = det.get("check", "")
        vt = normalizer.map_slither(check)
        if vt is None:            # non-security detector (naming, pragma, ...)
            continue
        impact = str(det.get("impact", "low")).lower()
        conf = str(det.get("confidence", "medium")).lower()
        sev = SLITHER_IMPACT.get(impact, baseline(vt))
        loc = _element_location(det)
        findings.append(Finding(
            contract_id=contract_id,
            vuln_type=vt,
            severity=Severity(max(int(sev), int(baseline(vt))) if impact in ("high", "medium")
                              else int(sev)),
            location=loc,
            source=Source.SLITHER,
            confidence=_CONFIDENCE.get(conf, 0.5),
            evidence_ref=det.get("id", check),
            raw_type=check,
            message=(det.get("description", "") or "").strip().split("\n")[0][:300],
            metadata={"impact": impact, "confidence_label": conf},
        ))
    return findings


def run(source_path: str, contract_id: str,
        timeout: int = 300, extra_args: Optional[list[str]] = None) -> tuple[list[Finding], dict]:
    """Run Slither on a .sol file. Returns (findings, run_info).

    ``run_info`` records wall-clock time and the solc version used, supporting
    the scalability metric (proposal S4.2.1).
    """
    source_path = str(source_path)
    solc_bin = solc_manager.select_for_file(source_path)
    # Slither refuses to overwrite an existing --json target, so hand it a path
    # inside a fresh temp dir that does not yet exist.
    tmpdir = tempfile.mkdtemp(prefix="slither_")
    json_out = str(Path(tmpdir) / "out.json")
    cmd = ["slither", source_path, "--json", json_out]
    if solc_bin:
        cmd += ["--solc", solc_bin]
    if extra_args:
        cmd += extra_args
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    elapsed = time.perf_counter() - t0
    # Slither exits non-zero when it finds issues; rely on the JSON payload.
    try:
        data = json.loads(Path(json_out).read_text() or "{}")
    except (json.JSONDecodeError, FileNotFoundError):
        data = {}
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    if not data:
        raise SlitherError(f"Slither produced no JSON for {source_path}: "
                           f"{proc.stderr.strip()[-400:]}")
    findings = parse_json(data, contract_id)
    info = {
        "tool": "slither",
        "seconds": round(elapsed, 3),
        "solc": solc_bin,
        "returncode": proc.returncode,
        "n_detectors_raw": len((data.get("results") or {}).get("detectors", []) or []),
        "n_findings": len(findings),
    }
    return findings, info
