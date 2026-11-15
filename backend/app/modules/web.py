"""Web and network checks: DNS, HTTP headers, TLS, TCP ports and scanners."""

from __future__ import annotations

import errno
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import httpx
from cryptography import x509

from app.schemas.analysis import Finding


# ── dns.py ────────────────────────────────────────────────────────────────────

# Record types queried for every target. CNAME is included because the UI
# renders a row for it; a target without a CNAME simply returns an empty list.
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _text_values(answers: Any) -> list[str]:
    """Render an answer set as text, skipping records that cannot be decoded."""
    values: list[str] = []
    for answer in answers:
        try:
            values.append(answer.to_text())
        except (UnicodeError, ValueError):
            continue
    return values


def dns_records(target: str) -> dict[str, Any]:
    hostname, addresses = validate_hostname(target)
    records: dict[str, list[str]] = {}
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(hostname, record_type, lifetime=4)
        except dns.exception.DNSException:
            # NXDOMAIN / NoAnswer / timeout / no nameservers — the type simply
            # has no records. dnspython exposes these under dns.exception;
            # dns.resolver has no DNSException attribute in 2.x.
            records[record_type] = []
            continue
        except OSError:
            records[record_type] = []
            continue
        records[record_type] = _text_values(answers)
    return {"hostname": hostname, "addresses": addresses, "records": records}


# ── headers.py ────────────────────────────────────────────────────────────────

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


# ── tls.py ────────────────────────────────────────────────────────────────────

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


# ── tcp.py ────────────────────────────────────────────────────────────────────

MAX_SCAN_PORTS = 512
CONNECT_TIMEOUT_SECONDS = 1.0
MAX_WORKERS = 64

# Common services so the UI can label a port instead of showing a bare number.
# This is a static convenience map, not a guarantee of what is listening.
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    69: "tftp",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    123: "ntp",
    135: "msrpc",
    137: "netbios-ns",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "smtp-submission",
    636: "ldaps",
    873: "rsync",
    993: "imaps",
    995: "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    4444: "metasploit",
    5000: "http-alt",
    5173: "vite",
    5432: "postgresql",
    5601: "kibana",
    5900: "vnc",
    5985: "winrm",
    5986: "winrm-tls",
    6379: "redis",
    7001: "weblogic",
    8000: "http-alt",
    8080: "http-proxy",
    8081: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "http-alt",
    9200: "elasticsearch",
    9300: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
    50000: "sap",
}


def parse_ports(spec: Any) -> list[int]:
    """
    Expand a port specification into a validated, sorted list of port numbers.

    Accepts a mix of ints and strings, so all of these are equivalent:
        [80, 443]
        ["80", "443"]
        ["80,443"]
        ["80,443,1000-1010"]
        ["1:1024"]                      (colon form, like nmap)

    Raises ValueError with a human-readable message on anything invalid, so the
    API can surface it as a 400 instead of a stack trace.
    """
    if spec is None:
        raise ValueError("At least one port or port range is required")
    if isinstance(spec, (int, str)):
        spec = [spec]

    pairs: list[tuple[int, int]] = []
    for item in spec:
        if isinstance(item, bool):  # bool is an int subclass; reject explicitly
            raise ValueError("Ports must be numbers or ranges like 80 or 1000-1010")
        if isinstance(item, int):
            pairs.append((item, item))
            continue
        if not isinstance(item, str):
            raise ValueError("Ports must be numbers or ranges like 80 or 1000-1010")

        for chunk in item.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            separator = "-" if "-" in chunk else (":" if ":" in chunk else None)
            if separator is None:
                try:
                    value = int(chunk)
                except ValueError as exc:
                    raise ValueError(f"Invalid port: {chunk!r}") from exc
                pairs.append((value, value))
                continue

            bounds = chunk.split(separator)
            if len(bounds) != 2:
                raise ValueError(f"Invalid port range: {chunk!r}")
            try:
                start, end = int(bounds[0]), int(bounds[1])
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {chunk!r}") from exc
            if start > end:
                raise ValueError(
                    f"Port range start must not be greater than its end: {chunk!r}"
                )
            pairs.append((start, end))

    if not pairs:
        raise ValueError("At least one port or port range is required")

    for start, end in pairs:
        if start < 1 or end > 65535:
            raise ValueError("Ports must be between 1 and 65535")
        if end - start + 1 > MAX_SCAN_PORTS:
            raise ValueError(
                f"A single range may not exceed {MAX_SCAN_PORTS} ports"
            )

    ports = sorted({port for start, end in pairs for port in range(start, end + 1)})
    if len(ports) > MAX_SCAN_PORTS:
        raise ValueError(f"Provide at most {MAX_SCAN_PORTS} ports in total")
    return ports


def _probe(address: str, port: int) -> tuple[bool, int | None]:
    """
    Attempt a TCP connection.

    Returns (is_open, errno_code). A timeout or unreachable-host error yields
    errno code None with is_open False, which the caller reports as "filtered".
    """
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(CONNECT_TIMEOUT_SECONDS)
            code = connection.connect_ex((address, port))
    except TimeoutError:
        return False, None
    except OSError as exc:
        return False, exc.errno
    return code == 0, code


def _state(is_open: bool, code: int | None) -> str:
    if is_open:
        return "open"
    # An explicit refusal means something answered: the port is closed.
    if code in {errno.ECONNREFUSED, errno.ECONNRESET}:
        return "closed"
    # No answer at all (timeout, host/net unreachable) looks firewalled.
    return "filtered"


def _scan_port(addresses: list[str], port: int) -> dict[str, Any]:
    started = time.monotonic()
    state = "filtered"
    for address in addresses:
        is_open, code = _probe(address, port)
        state = _state(is_open, code)
        if is_open:
            break
    return {
        "port": port,
        "state": state,
        "status": state,  # alias so either field name works for callers
        "service": WELL_KNOWN_PORTS.get(port),
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }


def bounded_tcp_scan(target: str, ports: Any) -> dict[str, Any]:
    hostname, addresses = validate_hostname(target)
    unique_ports = parse_ports(ports)

    started = time.monotonic()

    # Ports are independent, so probe them concurrently to keep the total
    # response well under a client's timeout even for the full 32-port cap.
    workers = min(MAX_WORKERS, len(unique_ports))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda port: _scan_port(addresses, port), unique_ports))

    results.sort(key=lambda item: item["port"])
    open_ports = [item["port"] for item in results if item["state"] == "open"]

    return {
        "hostname": hostname,
        "target": hostname,
        "addresses": addresses,
        "ports": results,
        "results": results,  # alias
        "open_ports": open_ports,
        "scanned": len(results),
        "timeout_seconds": CONNECT_TIMEOUT_SECONDS,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "note": (
            "A single TCP connect is attempted per port. 'filtered' means no "
            "response was received, which may indicate a firewall or packet "
            "filter rather than a closed port. Accepts lists and ranges, "
            "e.g. [\"80,443,1000-1010\"]."
        ),
    }


# ── scanners.py ───────────────────────────────────────────────────────────────

COMMAND_TIMEOUT_SECONDS = 30


def scanner_capabilities() -> dict[str, Any]:
    configured = {
        "nmap": os.environ.get("CYBERSUITE_NMAP_PATH", "nmap"),
        "rustscan": os.environ.get("CYBERSUITE_RUSTSCAN_PATH", "rustscan"),
    }
    return {
        name: {"configured_path": path, "available": shutil.which(path) is not None}
        for name, path in configured.items()
    }


def _validate_ports(ports: Any) -> list[int]:
    # Shared with the TCP checker so ranges ("1000-1010") work here too.
    return parse_ports(ports)


def _run(command: list[str], tool: str) -> dict[str, Any]:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
        shell=False,
    )
    return {
        "tool": tool,
        "return_code": result.returncode,
        "stdout": result.stdout[:100_000],
        "stderr": result.stderr[:10_000],
    }


def run_nmap_profile(target: str, ports: list[int]) -> dict[str, Any]:
    hostname, _ = validate_hostname(target)
    unique_ports = _validate_ports(ports)
    executable = os.environ.get("CYBERSUITE_NMAP_PATH", "nmap")
    if shutil.which(executable) is None:
        raise RuntimeError("Nmap is not installed or configured")
    return _run(
        [
            executable,
            "-Pn",
            "-sT",
            "-sV",
            "--version-light",
            "-p",
            ",".join(str(port) for port in unique_ports),
            hostname,
        ],
        "nmap",
    )


def run_rustscan_profile(target: str, ports: list[int]) -> dict[str, Any]:
    hostname, _ = validate_hostname(target)
    unique_ports = _validate_ports(ports)
    executable = os.environ.get("CYBERSUITE_RUSTSCAN_PATH", "rustscan")
    if shutil.which(executable) is None:
        raise RuntimeError("RustScan is not installed or configured")
    return _run(
        [
            executable,
            "-a",
            hostname,
            "-p",
            ",".join(str(port) for port in unique_ports),
            "--timeout",
            "1500",
            "--batch-size",
            "100",
        ],
        "rustscan",
    )


# ── validators.py ─────────────────────────────────────────────────────────────

def _is_restricted(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def validate_hostname(target: str) -> tuple[str, list[str]]:
    if any(character.isspace() for character in target):
        raise ValueError("Hostname must not contain whitespace")
    hostname = target.strip().rstrip(".").lower()
    if not hostname or len(hostname) > 253:
        raise ValueError("A valid hostname is required")
    try:
        parsed = ipaddress.ip_address(hostname)
    except ValueError:
        parsed = None
    if parsed is not None:
        if _is_restricted(parsed):
            raise ValueError("Private, loopback, link-local, or reserved targets are not allowed")
        return hostname, [str(parsed)]

    try:
        results = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Target hostname could not be resolved") from exc
    addresses = sorted({result[4][0] for result in results})
    if not addresses:
        raise ValueError("Target hostname did not resolve")
    if any(_is_restricted(ipaddress.ip_address(address)) for address in addresses):
        raise ValueError("Private, loopback, link-local, or reserved targets are not allowed")
    return hostname, addresses


def validate_url(target: str) -> tuple[str, str, list[str]]:
    parsed = urlparse(target.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only HTTP and HTTPS URLs with a hostname are supported")
    if "@" in parsed.netloc or parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed")
    hostname, addresses = validate_hostname(parsed.hostname)
    return parsed.geturl(), hostname, addresses
