from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from app.modules.web.validators import validate_url


def inspect_tls(target: str) -> dict[str, Any]:
    url, hostname, addresses = validate_url(target)
    if urlparse(url).scheme != "https":
        raise ValueError("TLS inspection requires an HTTPS URL")
    started = time.monotonic()
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=8) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as secure:
            certificate = secure.getpeercert()
            cipher = secure.cipher()
            version = secure.version()
    expires = certificate.get("notAfter")
    expires_at = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").isoformat() if expires else None
    return {
        "url": url,
        "hostname": hostname,
        "addresses": addresses,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "certificate_subject": certificate.get("subject"),
        "certificate_issuer": certificate.get("issuer"),
        "expires": expires_at,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
    }
