"""CVSS v3.x base score computation.

Azure Linux advisories frequently ship a CVSS vector but no numeric score, and
NVD/Red Hat may not be reachable or rate-limited. Computing the base score
locally means VULNEX always has a defensible severity even fully offline.
"""

from __future__ import annotations

import math

__all__ = ["score_from_vector", "severity_from_score", "normalise_severity"]

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}


def score_from_vector(vector: str) -> float | None:
    """Compute the CVSS v3.0/3.1 base score from a vector string.

    Returns ``None`` if the vector is not a supported v3 vector.
    """
    if not vector:
        return None
    parts: dict[str, str] = {}
    segments = vector.strip().split("/")
    if not segments or not segments[0].startswith("CVSS:3"):
        return None
    for seg in segments[1:]:
        key, _, val = seg.partition(":")
        if key:
            parts[key.strip().upper()] = val.strip().upper()

    try:
        scope_changed = parts["S"] == "C"
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        ui = _UI[parts["UI"]]
        c = _CIA[parts["C"]]
        i = _CIA[parts["I"]]
        a = _CIA[parts["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)
    # CVSS rounds up to the nearest 0.1.
    return round(math.ceil(raw * 10) / 10, 1)


def severity_from_score(score: float | None) -> str:
    """Map a numeric CVSS score to the standard severity band."""
    if score is None:
        return "unknown"
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def normalise_severity(value: str | None) -> str:
    """Normalise vendor severities (Red Hat, GHSA, NVD) to our band names."""
    if not value:
        return "unknown"
    v = str(value).strip().lower()
    aliases = {
        "critical": "critical",
        "important": "high",
        "high": "high",
        "moderate": "medium",
        "medium": "medium",
        "low": "low",
        "negligible": "low",
        "none": "none",
        "unknown": "unknown",
    }
    return aliases.get(v, "unknown")
