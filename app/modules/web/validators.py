from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def _is_restricted(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
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
