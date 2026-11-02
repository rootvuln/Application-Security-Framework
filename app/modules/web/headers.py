from __future__ import annotations

import time
from typing import Any

import httpx

from app.modules.web.validators import validate_url
from app.schemas.analysis import Finding


def _header_findings(headers: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    csp = headers.get("content-security-policy", "")
    csp_directives = {
        part.split(None, 1)[0].lower(): part
        for part in csp.split(";")
        if part.strip()
    }
    frame_ancestors = csp_directives.get("frame-ancestors", "")
    x_frame_options = headers.get("x-frame-options", "").strip().lower()

    if not frame_ancestors and x_frame_options not in {"deny", "sameorigin"}:
        findings.append(
            Finding(
                title="Clickjacking protection may be missing",
                severity="medium",
                evidence="Neither CSP frame-ancestors nor a supported X-Frame-Options value was present",
            )
        )
    elif frame_ancestors and "*" in frame_ancestors:
        findings.append(
            Finding(
                title="Clickjacking policy allows any framing origin",
                severity="medium",
                evidence=f"CSP frame-ancestors policy: {frame_ancestors}",
            )
        )

    required_headers = (
        ("content-security-policy", "Content-Security-Policy", "medium"),
        ("strict-transport-security", "Strict-Transport-Security", "medium"),
        ("x-content-type-options", "X-Content-Type-Options", "low"),
        ("referrer-policy", "Referrer-Policy", "low"),
        ("permissions-policy", "Permissions-Policy", "low"),
    )
    for key, label, severity in required_headers:
        if key not in headers:
            findings.append(
                Finding(
                    title=f"Missing {label}",
                    severity=severity,
                    evidence=f"The response did not include {label}",
                )
            )
    return findings


def inspect_headers(target: str) -> tuple[dict[str, Any], list[Finding]]:
    url, hostname, addresses = validate_url(target)
    started = time.monotonic()
    with httpx.Client(
        follow_redirects=False,
        timeout=httpx.Timeout(8.0),
        headers={"User-Agent": "CyberSuite/0.1"},
    ) as client:
        response = client.get(url)
    headers = {key.lower(): value for key, value in response.headers.items()}
    details = {
        "url": str(response.url),
        "hostname": hostname,
        "addresses": addresses,
        "status_code": response.status_code,
        "headers": headers,
        "redirect_location": response.headers.get("location"),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }
    return details, _header_findings(headers)
