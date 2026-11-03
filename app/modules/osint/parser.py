from __future__ import annotations

import ipaddress
from dataclasses import dataclass


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
