from __future__ import annotations

import os
import shutil
import subprocess
from typing import Any

from app.modules.web.tcp import MAX_SCAN_PORTS, parse_ports
from app.modules.web.validators import validate_hostname


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
