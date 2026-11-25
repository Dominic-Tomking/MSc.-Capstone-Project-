"""Solidity compiler selection.

Slither needs a solc version compatible with the contract under analysis.  The
manager reads the ``pragma solidity`` directive, picks the newest installed
version that satisfies it, and returns the path to that solc binary so the
adapter can pass ``--solc <path>`` per contract (deterministic, no global state).

Installed versions are discovered from the solc-select artefact store
(``~/.solc-select/artifacts/solc-<version>/solc-<version>``), which is how the
container images provision solc.
"""
from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Optional

# Minimal SemVer parsing/compare — enough for solidity pragmas.
_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^;]+);")


def _parse(v: str) -> tuple[int, int, int]:
    m = _VERSION_RE.search(v)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, 0, 0)


def artifacts_dir() -> Path:
    return Path(os.environ.get("SOLC_SELECT_HOME",
                               Path.home() / ".solc-select")) / "artifacts"


@lru_cache(maxsize=1)
def installed_versions() -> list[tuple[int, int, int]]:
    root = artifacts_dir()
    out: list[tuple[int, int, int]] = []
    if root.is_dir():
        for d in root.iterdir():
            if d.is_dir() and d.name.startswith("solc-"):
                out.append(_parse(d.name))
    return sorted(out)


def binary_for(version: tuple[int, int, int]) -> Optional[str]:
    vs = "%d.%d.%d" % version
    p = artifacts_dir() / f"solc-{vs}" / f"solc-{vs}"
    return str(p) if p.exists() else None


def _constraints(pragma_body: str) -> list[tuple[str, tuple[int, int, int]]]:
    """Return (operator, version) constraints from a pragma body."""
    cons = []
    for tok in re.findall(r"(\^|>=|<=|>|<|=|~)?\s*(\d+\.\d+\.\d+)", pragma_body):
        op, ver = tok[0] or "=", _parse(tok[1])
        cons.append((op, ver))
    # bare "0.4.24" without operator -> treat like caret for ^0.4.x style files
    return cons


def _satisfies(cand: tuple[int, int, int], pragma_body: str) -> bool:
    cons = _constraints(pragma_body)
    if not cons:
        return True
    ok = True
    for op, ver in cons:
        if op == "^":
            # ^0.4.24 -> >=0.4.24 <0.5.0 ; ^0.8.1 -> >=0.8.1 <0.9.0
            hi = (ver[0], ver[1] + 1, 0) if ver[0] else (0, ver[1] + 1, 0)
            ok &= (cand >= ver and cand < hi)
        elif op == "~":
            hi = (ver[0], ver[1] + 1, 0)
            ok &= (cand >= ver and cand < hi)
        elif op == ">=":
            ok &= cand >= ver
        elif op == "<=":
            ok &= cand <= ver
        elif op == ">":
            ok &= cand > ver
        elif op == "<":
            ok &= cand < ver
        else:  # "=" exact
            ok &= cand == ver
    return ok


def detect_pragma(source_code: str) -> Optional[str]:
    m = _PRAGMA_RE.search(source_code)
    return m.group(1).strip() if m else None


def select(source_code: str) -> Optional[str]:
    """Return the path to the best installed solc for this contract, or None."""
    pragma = detect_pragma(source_code)
    versions = installed_versions()
    if not versions:
        return None
    if not pragma:
        return binary_for(versions[-1])
    candidates = [v for v in versions if _satisfies(v, pragma)]
    chosen = candidates[-1] if candidates else versions[-1]
    return binary_for(chosen)


def select_for_file(path: str) -> Optional[str]:
    return select(Path(path).read_text(encoding="utf-8", errors="ignore"))
