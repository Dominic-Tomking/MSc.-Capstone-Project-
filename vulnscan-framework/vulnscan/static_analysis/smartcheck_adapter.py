"""SmartCheck adapter: run SmartCheck, parse its output, normalise to Findings.

SmartCheck (Tikhomirov et al., 2018) is a Java tool that applies XPath rules
over an intermediate representation of Solidity.  It is distributed as a
"jar-with-dependencies" and, being built for the Java 8 / JAXB era, is invoked
with a Java 8 runtime.  Its textual report is parsed into the common schema,
preserving the original ruleId/patternId (proposal S4.2.1).
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from typing import Optional

from ..schema.finding import Finding, Location, Source
from ..schema.severity import SMARTCHECK_SEVERITY, Severity, baseline
from . import normalizer

def _find_java8() -> str:
    for c in ("/usr/lib/jvm/java-8-openjdk-amd64/bin/java",
              "/usr/lib/jvm/java-1.8.0-openjdk-amd64/bin/java"):
        if Path(c).exists():
            return c
    return "java"  # fall back to default runtime


def _find_jar() -> str:
    rel = ("lib/node_modules/@smartdec/smartcheck/jdeploy-bundle/"
           "smartcheck-2.0-jar-with-dependencies.jar")
    roots = [
        Path.home() / ".npm-global",
        Path("/home/claude/.npm-global"),
        Path("/root/.npm-global"),
        Path("/usr/local"),
        Path("/usr"),
    ]
    for r in roots:
        p = r / rel
        if p.exists():
            return str(p)
    # last resort: glob the filesystem-agnostic npm global root
    for base in ("/home/claude/.npm-global", "/root/.npm-global", "/usr/local"):
        hits = list(Path(base).glob("**/smartcheck-2.0-jar-with-dependencies.jar"))
        if hits:
            return str(hits[0])
    return str(Path.home() / rel)


# Configurable via environment for containerised deployment.
JAVA8 = os.environ.get("SMARTCHECK_JAVA") or _find_java8()
SMARTCHECK_JAR = os.environ.get("SMARTCHECK_JAR") or _find_jar()

# SmartCheck rules are deterministic pattern matches; assign a fixed confidence.
_CONFIDENCE = 0.7

_RECORD_RE = re.compile(
    r"ruleId:\s*(?P<rule>\S+)\s+"
    r"patternId:\s*(?P<pattern>\S+)\s+"
    r"severity:\s*(?P<sev>\d+)\s+"
    r"line:\s*(?P<line>\d+)\s+"
    r"column:\s*(?P<col>\d+)\s+"
    r"content:\s*(?P<content>.*)",
)


class SmartCheckError(RuntimeError):
    pass


def parse_output(text: str, contract_id: str) -> list[Finding]:
    """Parse SmartCheck's textual report into normalised findings."""
    findings: list[Finding] = []
    for m in _RECORD_RE.finditer(text):
        rule = m.group("rule")
        vt = normalizer.map_smartcheck(rule)
        if vt is None:                       # advisory / non-security rule
            continue
        sev_int = int(m.group("sev"))
        line = int(m.group("line"))
        sev = SMARTCHECK_SEVERITY.get(sev_int, baseline(vt))
        findings.append(Finding(
            contract_id=contract_id,
            vuln_type=vt,
            severity=sev,
            location=Location(function=None, start_line=line, end_line=line),
            source=Source.SMARTCHECK,
            confidence=_CONFIDENCE,
            evidence_ref=f"{rule}:{m.group('pattern')}",
            raw_type=rule,
            message=m.group("content").strip()[:300],
            metadata={"patternId": m.group("pattern"),
                      "column": int(m.group("col")), "raw_severity": sev_int},
        ))
    return findings


def available() -> bool:
    return Path(JAVA8).exists() and Path(SMARTCHECK_JAR).exists()


def run(source_path: str, contract_id: str, timeout: int = 300) -> tuple[list[Finding], dict]:
    """Run SmartCheck on a .sol file. Returns (findings, run_info)."""
    if not available():
        raise SmartCheckError(
            f"SmartCheck not available (java8={JAVA8}, jar={SMARTCHECK_JAR})")
    env = dict(os.environ)
    env.pop("JAVA_TOOL_OPTIONS", None)       # avoid proxy noise on stderr
    cmd = [JAVA8, "-jar", SMARTCHECK_JAR, "-p", str(source_path)]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    elapsed = time.perf_counter() - t0
    if proc.returncode != 0 and not proc.stdout.strip():
        raise SmartCheckError(f"SmartCheck failed: {proc.stderr.strip()[-400:]}")
    findings = parse_output(proc.stdout, contract_id)
    info = {
        "tool": "smartcheck",
        "seconds": round(elapsed, 3),
        "returncode": proc.returncode,
        "n_findings": len(findings),
    }
    return findings, info
