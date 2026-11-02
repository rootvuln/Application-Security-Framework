from __future__ import annotations

import socket
import ssl
import time
from typing import Any


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
