from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cryptography import x509

from app.modules.web.validators import validate_url


# Certificates expiring within this window are flagged as urgent.
EXPIRY_WARNING_DAYS = 30
WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def _from_der(der: bytes) -> dict[str, Any]:
    """
    Parse a DER-encoded certificate into the fields the API reports.

    ssl.getpeercert() returns an empty dict when verification is disabled, so an
    unverified handshake has to be decoded from the raw DER bytes instead. Only
    reported fields are read here; nothing in this function is a trust verdict.
    """
    cert = x509.load_der_x509_certificate(der)

    # not_valid_before_utc exists on cryptography >= 42; fall back for older.
    not_before = getattr(cert, "not_valid_before_utc", None) or (
        cert.not_valid_before.replace(tzinfo=timezone.utc)
    )
    not_after = getattr(cert, "not_valid_after_utc", None) or (
        cert.not_valid_after.replace(tzinfo=timezone.utc)
    )

    try:
        san_extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    return {
        "subject": cert.subject.rfc4514_string() or None,
        "issuer": cert.issuer.rfc4514_string() or None,
        "not_before": not_before,
        "not_after": not_after,
        "serial_number": f"{cert.serial_number:X}",
        "sans": list(sans),
    }


def _weakness_findings(
    protocol: str | None,
    cipher: str | None,
    days_remaining: int | None,
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if protocol and protocol in WEAK_PROTOCOLS:
        findings.append({
            "title": f"Deprecated TLS version negotiated: {protocol}",
            "severity": "medium",
            "evidence": f"The server negotiated {protocol}, which is deprecated and considered insecure.",
        })

    if cipher and any(marker in cipher.upper() for marker in WEAK_CIPHER_MARKERS):
        findings.append({
            "title": "Weak cipher suite negotiated",
            "severity": "high",
            "evidence": f"The negotiated cipher suite was {cipher}.",
        })

    if days_remaining is not None:
        if days_remaining < 0:
            findings.append({
                "title": "Certificate has expired",
                "severity": "high",
                "evidence": f"The certificate expired {abs(days_remaining)} day(s) ago.",
            })
        elif days_remaining <= 7:
            findings.append({
                "title": "Certificate expires within 7 days",
                "severity": "high",
                "evidence": f"The certificate expires in {days_remaining} day(s).",
            })
        elif days_remaining <= EXPIRY_WARNING_DAYS:
            findings.append({
                "title": f"Certificate expires within {EXPIRY_WARNING_DAYS} days",
                "severity": "low",
                "evidence": f"The certificate expires in {days_remaining} day(s).",
            })

    return findings


def _handshake(hostname: str, port: int, verify: bool, attempts: int = 2) -> tuple[bytes, Any, str | None]:
    """
    Perform the TLS handshake and return (certificate_der, cipher, protocol).

    When `verify` is False the chain is not validated. That is how an inspector
    can still read an expired, self-signed, or hostname-mismatched certificate
    instead of failing outright.

    A single retry absorbs the transient connection resets some servers emit;
    certificate-verification failures are never retried here.
    """
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            context = ssl.create_default_context()
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=8) as connection:
                with context.wrap_socket(connection, server_hostname=hostname) as secure:
                    der = secure.getpeercert(binary_form=True)
                    return der or b"", secure.cipher(), secure.version()
        except (ConnectionResetError, ssl.SSLEOFError, ssl.SSLZeroReturnError, ssl.SSLWantReadError) as exc:
            last_error = exc
            continue
    raise last_error if last_error is not None else OSError("TLS handshake failed")


def inspect_tls(target: str) -> dict[str, Any]:
    url, hostname, addresses = validate_url(target)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("TLS inspection requires an HTTPS URL")

    # Honour an explicit port in the URL instead of always assuming 443.
    port = parsed.port or 443

    started = time.monotonic()

    verified = True
    verification_error: str | None = None
    der: bytes = b""
    cipher: Any = None
    version: str | None = None

    try:
        der, cipher, version = _handshake(hostname, port, verify=True)
    except ssl.SSLCertVerificationError as exc:
        # Untrusted certificate (expired, self-signed, wrong host, unknown CA).
        # Reconnect without verification so the details can still be reported.
        verified = False
        verification_error = getattr(exc, "verify_message", None) or str(exc)
        try:
            der, cipher, version = _handshake(hostname, port, verify=False)
        except (OSError, ssl.SSLError) as retry_exc:
            # The peer accepted the verified attempt but dropped the unverified
            # one. Report what is known rather than failing the whole request.
            return {
                "status": "partial",
                "url": url,
                "hostname": hostname,
                "port": port,
                "addresses": addresses,
                "is_valid": False,
                "verified": False,
                "verification_error": verification_error,
                "error": str(retry_exc),
                "findings": [{
                    "title": "Certificate failed verification",
                    "severity": "high",
                    "evidence": verification_error,
                }],
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }

    meta: dict[str, Any] = {}
    if der:
        try:
            meta = _from_der(der)
        except (ValueError, TypeError):
            meta = {}

    not_before_dt: datetime | None = meta.get("not_before")
    not_after_dt: datetime | None = meta.get("not_after")
    now = datetime.now(timezone.utc)

    days_remaining: int | None = None
    if not_after_dt is not None:
        days_remaining = (not_after_dt - now).days

    expired = bool(not_after_dt is not None and not_after_dt < now)
    not_yet_valid = bool(not_before_dt is not None and not_before_dt > now)
    is_valid = verified and not expired and not not_yet_valid

    subject = meta.get("subject")
    issuer = meta.get("issuer")
    serial_number = meta.get("serial_number")
    sans = meta.get("sans") or []
    cipher_name = cipher[0] if cipher else None

    findings = _weakness_findings(version, cipher_name, days_remaining)
    if not verified:
        findings.insert(0, {
            "title": "Certificate failed verification",
            "severity": "high",
            "evidence": verification_error or "The certificate chain could not be validated.",
        })

    return {
        "status": "available",
        # ── Connection context ──────────────────────────────────────────
        "url": url,
        "hostname": hostname,
        "port": port,
        "addresses": addresses,
        # ── Negotiated parameters ───────────────────────────────────────
        "tls_version": version,
        "cipher": cipher_name,
        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
        # ── Certificate subject / issuer ────────────────────────────────
        "subject": subject,
        "issuer": issuer,
        "certificate_subject": subject,
        "certificate_issuer": issuer,
        "serial_number": serial_number,
        # ── Validity ────────────────────────────────────────────────────
        "not_before": not_before_dt.isoformat() if not_before_dt else None,
        "not_after": not_after_dt.isoformat() if not_after_dt else None,
        "expires": not_after_dt.isoformat() if not_after_dt else None,
        "expired": expired,
        "not_yet_valid": not_yet_valid,
        "is_valid": is_valid,
        "verified": verified,
        "verification_error": verification_error,
        "days_remaining": days_remaining,
        # ── Extensions ──────────────────────────────────────────────────
        "subject_alt_names": sans,
        "san": sans,
        # ── Observations ────────────────────────────────────────────────
        "findings": findings,
        "weak_protocol": bool(version in WEAK_PROTOCOLS),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }
