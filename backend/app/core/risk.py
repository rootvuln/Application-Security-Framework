from __future__ import annotations

from collections.abc import Iterable
from typing import Any


_SEVERITY_RANK = {
    "unknown": 0,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def risk_level_for_findings(findings: Iterable[Any]) -> str:
    highest = "unknown"
    for finding in findings:
        severity = (
            finding.get("severity")
            if isinstance(finding, dict)
            else getattr(finding, "severity", "unknown")
        )
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK[highest]:
            highest = severity
    return highest
