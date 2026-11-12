from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from app.modules.web.validators import validate_hostname


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
