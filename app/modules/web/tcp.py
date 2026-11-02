from __future__ import annotations

import socket
import time
from typing import Any

from app.modules.web.validators import validate_hostname


MAX_SCAN_PORTS = 32


def bounded_tcp_scan(target: str, ports: list[int]) -> dict[str, Any]:
    hostname, addresses = validate_hostname(target)
    unique_ports = sorted(set(ports))
    if not unique_ports or len(unique_ports) > MAX_SCAN_PORTS:
        raise ValueError(f"Provide between 1 and {MAX_SCAN_PORTS} ports")
    if any(port < 1 or port > 65535 for port in unique_ports):
        raise ValueError("Ports must be between 1 and 65535")

    results = []
    for port in unique_ports:
        state = "closed"
        started = time.monotonic()
        for address in addresses:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.settimeout(1)
                if connection.connect_ex((address, port)) == 0:
                    state = "open"
                    break
        results.append(
            {
                "port": port,
                "state": state,
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        )
    return {"hostname": hostname, "addresses": addresses, "ports": results}
