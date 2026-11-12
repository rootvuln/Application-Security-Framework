"""OSINT: passive reconnaissance of a domain or address."""

from __future__ import annotations

import ipaddress
import os
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver
import httpx

from app.modules.web import validate_hostname, validate_url


# ── parser.py ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ParsedTarget:
    original: str
    host: str
    target_type: str
    port: int | None


def parse_target(value: str) -> ParsedTarget:
    original = str(value or "").strip()
    if not original or any(character.isspace() for character in original):
        raise ValueError("Target must be a non-empty host or IP address without whitespace")
    if "://" in original or "/" in original:
        raise ValueError("URLs and paths are not valid OSINT targets")

    host: str
    port: int | None = None
    if original.startswith("["):
        closing = original.find("]")
        if closing < 0:
            raise ValueError("Bracketed IPv6 target is malformed")
        host = original[1:closing]
        suffix = original[closing + 1:]
        if suffix:
            if not suffix.startswith(":") or not suffix[1:]:
                raise ValueError("IPv6 port syntax must be [address]:port")
            port = _port(suffix[1:])
    else:
        try:
            ipaddress.ip_address(original)
            host = original
        except ValueError:
            if original.count(":") == 1:
                candidate_host, candidate_port = original.rsplit(":", 1)
                if not candidate_host or not candidate_port:
                    raise ValueError("Host and port must both be provided")
                host = candidate_host
                port = _port(candidate_port)
            elif original.count(":") > 1:
                try:
                    ipaddress.IPv6Address(original)
                except ValueError as exc:
                    raise ValueError("IPv6 targets with ports must use [address]:port syntax") from exc
                host = original
            else:
                host = original

    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        target_type = "domain"
    else:
        target_type = "ipv6" if parsed_ip.version == 6 else "ipv4"
    return ParsedTarget(original=original, host=host, target_type=target_type, port=port)


def _port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise ValueError("Port must be an integer from 1 to 65535") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Port must be an integer from 1 to 65535")
    return port


# ── port_intelligence.py ──────────────────────────────────────────────────────

def _probe_banner(connection: socket.socket, host: str, port: int) -> tuple[str, str | None]:
    connection.settimeout(1.0)
    try:
        data = connection.recv(256)
    except TimeoutError:
        data = b""
    if data.startswith(b"SSH-"):
        return "ssh", data.decode("ascii", "replace").strip()
    if data.startswith(b"220"):
        return "ftp", data.decode("ascii", "replace").strip()

    request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
    connection.sendall(request)
    data = connection.recv(512)
    if data.startswith((b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2")):
        return "http", data.split(b"\r\n", 1)[0].decode("ascii", "replace")
    return "unknown", None


def inspect_port(host: str, addresses: list[str], port: int) -> dict[str, Any]:
    started = time.monotonic()
    result: dict[str, Any] = {
        "port": port,
        "status": "closed",
        "connection_duration_ms": None,
        "service": "unknown",
        "service_identification_confidence": "none",
        "protocol": None,
        "banner": None,
        "validated_address": None,
    }
    for address in addresses:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((address, port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=host) as secure:
                    result.update({
                        "status": "open",
                        "validated_address": address,
                        "service": "https",
                        "protocol": "https",
                        "service_identification_confidence": "high",
                        "tls_protocol": secure.version(),
                    })
                    break
        except (OSError, ssl.SSLError, ValueError, TimeoutError):
            pass
        try:
            with socket.create_connection((address, port), timeout=3) as connection:
                result["status"] = "open"
                result["validated_address"] = address
                try:
                    protocol, banner = _probe_banner(connection, host, port)
                except (OSError, TimeoutError):
                    protocol, banner = "unknown", None
                result["service"] = protocol
                result["protocol"] = protocol if protocol != "unknown" else None
                result["banner"] = banner
                result["service_identification_confidence"] = (
                    "high" if protocol != "unknown" else "low"
                )
                break
        except (OSError, TimeoutError):
            continue
    result["connection_duration_ms"] = round((time.monotonic() - started) * 1000)
    return result


# ── analyzer.py ───────────────────────────────────────────────────────────────

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
MAX_WEBSITE_BYTES = 1_000_000
MAX_REDIRECTS = 5
RDAP_BASE_URL = "https://rdap.org"


def _finding(
    title: str,
    severity: str,
    description: str,
    evidence: str,
    category: str,
    confidence: str,
    data_source: str,
) -> dict[str, str]:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "category": category,
        "confidence": confidence,
        "data_source": data_source,
    }


def _records(hostname: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3
    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(hostname, record_type)
            result[record_type] = [answer.to_text() for answer in answers]
        except (dns.exception.DNSException, OSError):
            result[record_type] = []
    return result


def _validate_policy_record(value: str | None, kind: str) -> dict[str, Any]:
    if not value:
        return {"present": False, "valid": None, "value": None, "reason": f"No {kind} record observed"}
    normalized = value.strip().strip('"')
    lowered = normalized.lower()
    prefix = "v=spf1" if kind == "SPF" else "v=dmarc1"
    return {
        "present": True,
        "valid": lowered.startswith(prefix),
        "value": normalized,
        "reason": None if lowered.startswith(prefix) else f"{kind} record does not start with {prefix}",
    }


def _rdap(target: str, address: ipaddress._BaseAddress | None) -> dict[str, Any]:
    query = str(address) if address is not None else target
    url = f"{RDAP_BASE_URL}/ip/{query}" if address is not None else f"{RDAP_BASE_URL}/domain/{target}"
    try:
        with httpx.Client(
            timeout=httpx.Timeout(5.0),
            follow_redirects=False,
            headers={"User-Agent": "CyberSuite/1.0"},
        ) as client:
            response = client.get(url)
            for _ in range(3):
                if response.status_code not in {301, 302, 303, 307, 308}:
                    break
                location = response.headers.get("location")
                if not location:
                    break
                redirect = urljoin(str(response.url), location)
                parsed = urlparse(redirect)
                if parsed.scheme != "https" or not parsed.hostname:
                    raise ValueError("RDAP redirect must use HTTPS")
                validate_hostname(parsed.hostname)
                response = client.get(redirect)
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError, OSError) as exc:
        return {
            "status": "unavailable",
            "query": query,
            "error": str(exc),
            "registrar": None,
            "registration_date": None,
            "expiration_date": None,
            "last_updated": None,
            "nameservers": [],
        }

    events = {
        event.get("eventAction"): event.get("eventDate")
        for event in payload.get("events", [])
        if isinstance(event, dict)
    }
    registrar = None
    for entity in payload.get("entities", []):
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles", [])
        if "registrar" in roles or "registrant" in roles:
            registrar = entity.get("handle") or entity.get("vcardArray")
            if registrar:
                break
    nameservers = [
        item.get("ldhName") or item.get("unicodeName")
        for item in payload.get("nameservers", [])
        if isinstance(item, dict) and (item.get("ldhName") or item.get("unicodeName"))
    ]
    organization = payload.get("name")
    autnums = payload.get("autnums") or []
    asn = autnums[0] if autnums else None
    country = payload.get("country")
    return {
        "status": "available",
        "query": query,
        "domain_status": payload.get("status", []),
        "registrar": registrar,
        "registration_date": events.get("registration"),
        "expiration_date": events.get("expiration"),
        "last_updated": events.get("last changed") or events.get("last update of RDAP database"),
        "nameservers": nameservers,
        "redacted": not bool(registrar or events),
        "asn": asn,
        "isp": organization,
        "organization": organization,
        "country": country,
    }


class _PageMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title: str | None = None
        self._in_title = False
        self._title_parts: list[str] = []
        self.meta: dict[str, str] = {}
        self.links: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() == "meta":
            key = values.get("name") or values.get("property")
            content = values.get("content")
            if key and content:
                self.meta[key.lower()] = content[:2048]
        if tag.lower() == "link" and values.get("rel") and values.get("href"):
            self.links[values["rel"].lower()] = values["href"]

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
            self.title = "".join(self._title_parts).strip()[:2048]


def _safe_redirect(url: str) -> tuple[str, str, list[str]]:
    return validate_url(url)


def _website(
    hostname: str,
    scheme: str = "https",
    port: int | None = None,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    port_suffix = f":{port}" if port is not None else ""
    start_url = f"{scheme}://{hostname}{port_suffix}/"
    current_url = start_url
    chain: list[str] = []
    redirect_destination: str | None = None
    response: httpx.Response | None = None
    try:
        with httpx.Client(
            follow_redirects=False,
            timeout=httpx.Timeout(8.0),
            headers={"User-Agent": "CyberSuite/1.0"},
        ) as client:
            for _ in range(MAX_REDIRECTS + 1):
                validated_url, _, _ = _safe_redirect(current_url)
                response = client.get(validated_url)
                chain.append(str(response.url))
                if response.status_code not in {301, 302, 303, 307, 308}:
                    break
                location = response.headers.get("location")
                if not location:
                    break
                redirect_destination = urljoin(str(response.url), location)
                current_url = redirect_destination
            if response is None:
                raise ValueError("Website returned no response")
            content = response.content[:MAX_WEBSITE_BYTES]
    except (httpx.HTTPError, ValueError, OSError) as exc:
        return {
            "status": "unavailable",
            "error": str(exc),
            "final_url": chain[-1] if chain else None,
            "redirect_chain": chain,
            "location": redirect_destination,
            "redirect_destination": redirect_destination,
        }, []

    parser = _PageMetadataParser()
    try:
        parser.feed(content.decode(response.encoding or "utf-8", "replace"))
    except (UnicodeError, ValueError):
        parser.feed(content.decode("utf-8", "replace"))
    final_url = str(response.url)
    details = {
        "status": "available",
        "status_code": response.status_code,
        "final_url": final_url,
        "redirect_chain": chain,
        "location": response.headers.get("location"),
        "redirect_destination": (
            redirect_destination
            or (
                urljoin(final_url, response.headers["location"])
                if response.headers.get("location") else None
            )
        ),
        "title": parser.title,
        "meta_description": parser.meta.get("description"),
        "canonical_url": urljoin(final_url, parser.links["canonical"]) if parser.links.get("canonical") else None,
        "favicon_url": urljoin(final_url, parser.links["icon"]) if parser.links.get("icon") else None,
        "open_graph": {
            "title": parser.meta.get("og:title"),
            "description": parser.meta.get("og:description"),
            "image_url": urljoin(final_url, parser.meta["og:image"]) if parser.meta.get("og:image") else None,
        },
        "headers": {
            key: response.headers[key]
            for key in ("server", "content-type", "cache-control", "strict-transport-security")
            if key in response.headers
        },
    }
    return details, []


def _tls(hostname: str, port: int = 443) -> dict[str, Any]:
    started = time.monotonic()
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=8) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as secure:
                certificate = secure.getpeercert()
                not_before = certificate.get("notBefore")
                not_after = certificate.get("notAfter")
                expires = (
                    datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    if not_after else None
                )
                sans = [
                    value for kind, value in certificate.get("subjectAltName", [])
                    if kind == "DNS"
                ]
                return {
                    "status": "available",
                    "subject": certificate.get("subject"),
                    "issuer": certificate.get("issuer"),
                    "valid_from": not_before,
                    "valid_until": not_after,
                    "expired": expires is not None and expires < datetime.now(timezone.utc),
                    "subject_alternative_names": sans,
                    "tls_protocol": secure.version(),
                    "cipher": secure.cipher()[0] if secure.cipher() else None,
                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                }
    except (OSError, ssl.SSLError, ValueError) as exc:
        return {"status": "unavailable", "error": str(exc)}


def _reputation(target: str) -> dict[str, Any]:
    endpoint = os.getenv("CYBERSUITE_REPUTATION_URL")
    api_key = os.getenv("CYBERSUITE_REPUTATION_API_KEY")
    if not endpoint or not api_key:
        return {"status": "not_configured", "provider": None, "evidence": []}
    try:
        response = httpx.get(
            endpoint,
            params={"target": target},
            headers={"Authorization": f"Bearer {api_key}", "User-Agent": "CyberSuite/1.0"},
            timeout=httpx.Timeout(5.0),
        )
        response.raise_for_status()
        payload = response.json()
        return {
            "status": "available",
            "provider": endpoint.split("/", 3)[2],
            "lookup_time": datetime.now(timezone.utc).isoformat(),
            "evidence": payload.get("evidence", payload),
        }
    except (httpx.HTTPError, ValueError, OSError) as exc:
        return {"status": "unavailable", "provider": endpoint, "error": str(exc), "evidence": []}


def _risk(
    findings: list[dict[str, Any]],
    coverage: dict[str, dict[str, str]],
) -> dict[str, Any]:
    weighted = {"info": 0, "low": 10, "medium": 25, "high": 45, "critical": 70}
    seen: set[str] = set()
    reasons: list[str] = []
    score = 0
    for finding in findings:
        evidence = " ".join(str(finding.get("evidence", "")).casefold().split())
        if not evidence or evidence in seen:
            continue
        seen.add(evidence)
        weight = weighted.get(str(finding.get("severity", "info")), 0)
        if weight:
            score += weight
            reasons.append(str(finding.get("title", "")))
    score = min(score, 100)
    severity = (
        "critical" if score >= 80 else
        "high" if score >= 50 else
        "medium" if score >= 25 else
        "low" if score else "info"
    )
    if score == 0 and any(item["status"] in {"unavailable", "not_configured"} for item in coverage.values()):
        severity = "unknown"
    return {
        "score": score,
        "severity": severity,
        "confidence": "high" if len(reasons) >= 2 else "medium" if reasons else "low",
        "reasons": reasons,
        "evidence_count": len(seen),
        "confirmed_malicious": False,
        "explanation": (
            "No suspicious evidence was identified by the completed checks; this does not prove safety."
            if not reasons else
            "Risk reflects distinct evidence-backed findings only."
        ),
    }


def analyze_target(target: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed_target: ParsedTarget = parse_target(target)
    hostname = parsed_target.host.rstrip(".")
    if not hostname or len(hostname) > 253:
        raise ValueError("A valid domain or IP address is required")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None:
        if (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            raise ValueError("Private or reserved IP addresses are not allowed")
        addresses = [str(address)]
        try:
            reverse_name = socket.gethostbyaddr(str(address))[0]
        except (socket.herror, socket.gaierror, OSError):
            reverse_name = None
        records: dict[str, list[str]] = {}
        domain_intelligence: dict[str, Any] = {}
    else:
        hostname, addresses = validate_hostname(hostname)
        reverse_name = None
        records = _records(hostname)
        txt = records.get("TXT", [])
        spf = next((value for value in txt if value.strip().strip('"').lower().startswith("v=spf1")), None)
        dmarc_records = _records(f"_dmarc.{hostname}").get("TXT", [])
        dmarc = next((value for value in dmarc_records if value.strip().strip('"').lower().startswith("v=dmarc1")), None)
        domain_intelligence = {
            "resolution_status": "resolved" if addresses else "unresolved",
            "associated_ips": addresses,
            "nameservers": records.get("NS", []),
            "spf": _validate_policy_record(spf, "SPF"),
            "dmarc": _validate_policy_record(dmarc, "DMARC"),
        }
    rdap = _rdap(hostname, address)
    reputation = _reputation(hostname)
    findings: list[dict[str, Any]] = []
    port_details: dict[str, Any] = {"status": "not_applicable"}
    if parsed_target.port is not None:
        port_details = inspect_port(hostname, addresses, parsed_target.port)
    if parsed_target.port is not None and port_details.get("service") == "http":
        website, website_findings = _website(hostname, "http", parsed_target.port)
        findings.extend(website_findings)
    elif address is None:
        website, website_findings = _website(hostname)
        findings.extend(website_findings)
    else:
        website = {"status": "not_applicable"}
    if parsed_target.port is not None and port_details.get("service") == "https":
        tls = _tls(hostname, parsed_target.port)
    elif address is None:
        tls = _tls(hostname)
    else:
        tls = {"status": "not_applicable"}
    def _coverage_status(value: str | None) -> str:
        if value in {"completed", "unavailable", "not_applicable", "not_configured", "failed"}:
            return value
        if value == "available":
            return "completed"
        return "unavailable"
    coverage = {
        "input_validation": {"status": "completed", "explanation": "Target and optional port were validated."},
        "dns_intelligence": {
            "status": "completed" if address is None else "not_applicable",
            "explanation": "DNS records and resolved addresses were queried." if address is None else "DNS record lookup does not apply to a literal IP.",
        },
        "ip_intelligence": {
            "status": "completed",
            "explanation": "Public IP classification and reverse DNS were checked." if address is not None else "Resolved public addresses were recorded.",
        },
        "rdap": {        "status": _coverage_status(rdap.get("status")), "explanation": "RDAP response parsed or reported unavailable."},
        "port_intelligence": {
            "status": "completed" if parsed_target.port is not None else "not_applicable",
            "explanation": "Only the explicitly supplied port was checked." if parsed_target.port is not None else "No port was supplied.",
        },
        "website_intelligence": {
            "status": _coverage_status(website.get("status")),
            "explanation": "Bounded website metadata was retrieved." if website.get("status") == "available" else "Website metadata was unavailable.",
        },
        "tls_intelligence": {
            "status": _coverage_status(tls.get("status")),
            "explanation": "TLS certificate validation was attempted." if tls.get("status") == "available" else "TLS data was unavailable.",
        },
        "email_security": {
            "status": "completed" if address is None else "not_applicable",
            "explanation": "SPF and DMARC records were checked." if address is None else "Email security records apply to domains.",
        },
        "reputation": {
            "status": _coverage_status(reputation.get("status")),
            "explanation": "Optional provider result was returned." if reputation.get("status") == "available" else "No configured reputation provider result is available.",
        },
    }
    if port_details.get("status") == "open" and port_details.get("service") == "unknown":
        findings.append(_finding(
            "Open service with unknown protocol",
            "info",
            "The explicitly supplied TCP port accepted a connection, but no supported protocol banner was observed.",
            f"TCP port {parsed_target.port} accepted a connection",
            "port_intelligence",
            "high",
            "TCP connection probe",
        ))
    if not addresses:
        findings.append(_finding(
            "No public address resolved", "medium",
            "The target did not resolve to a public address.",
            f"{hostname} did not resolve to a public address",
            "resolution", "high", "DNS resolver",
        ))
    if address is not None and reverse_name is None:
        findings.append(_finding(
            "Reverse DNS lookup failed", "info",
            "No PTR hostname was returned for the public IP.",
            f"No PTR hostname was returned for {hostname}",
            "reverse_dns", "high", "local reverse-DNS resolver",
        ))
    risk = _risk(findings, coverage)
    ip_rdap = rdap
    if address is None and not ip_rdap.get("asn") and addresses:
        try:
            resolved_address = ipaddress.ip_address(addresses[0])
        except ValueError:
            resolved_address = None
        if resolved_address is not None:
            ip_rdap = _rdap(str(resolved_address), resolved_address)
    return {
        "target": hostname,
        "original_input": parsed_target.original,
        "target_host": hostname,
        "target_type": parsed_target.target_type,
        "port": parsed_target.port,
        "target_port": parsed_target.port,
        "addresses": addresses,
        "reverse_dns": reverse_name,
        "records": records,
        "domain_intelligence": domain_intelligence,
        "registration": rdap,
        "ip_intelligence": {
            "classification": "public" if address is not None else None,
            "asn": ip_rdap.get("asn"),
            "isp": ip_rdap.get("isp"),
            "organization": ip_rdap.get("organization"),
            "country": ip_rdap.get("country"),
            "region": None,
            "city": None,
            "geolocation_status": "not_configured",
        },
        "tls": tls,
        "website": website,
        "reputation": reputation,
        "port_intelligence": port_details,
        "risk_assessment": risk,
        "coverage": coverage,
        "data_sources": [
            *(
                ["DNS resolver"]
                if address is None else []
            ),
            *(
                ["local reverse-DNS resolver"]
                if address is not None else []
            ),
            "RDAP",
            *(
                ["HTTP metadata retrieval"]
                if website.get("status") != "not_applicable" else []
            ),
            *(
                ["TLS certificate retrieval"]
                if tls.get("status") != "not_applicable" else []
            ),
            *(
                ["bounded TCP connection probe"]
                if parsed_target.port is not None else []
            ),
        ],
        "limitations": [
            "Registration, TLS, and website data may be unavailable or redacted.",
            "ASN, ISP, and geolocation fields remain unavailable without a configured provider.",
            "Reputation data is queried only when both optional provider environment variables are configured.",
            "Results are passive observations and do not prove malicious activity.",
        ],
    }, findings
