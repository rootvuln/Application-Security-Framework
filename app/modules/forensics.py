"""Forensics: static file inspection, hashing, entropy and hex preview."""

from __future__ import annotations

import hashlib
import math
import mimetypes
import re
import struct
from collections import Counter
from pathlib import PurePath
from typing import Any

from app.core.config import MAX_FILE_SIZE as UPLOAD_LIMIT
from app.schemas.analysis import Finding


# ── analyzer.py ───────────────────────────────────────────────────────────────

MAX_FILE_SIZE = UPLOAD_LIMIT  # 10 MB upload cap (see app.core.config)
MAX_STRING_RESULTS = 100
MAX_STRING_LENGTH = 4096
MAX_CAPTURE_PACKETS = 100_000

SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"\xd4\xc3\xb2\xa1", "PCAP capture", "application/vnd.tcpdump.pcap"),
    (b"\xa1\xb2\xc3\xd4", "PCAP capture", "application/vnd.tcpdump.pcap"),
    (b"\x4d\x3c\xb2\xa1", "PCAP capture", "application/vnd.tcpdump.pcap"),
    (b"\xa1\xb2\x3c\x4d", "PCAP capture", "application/vnd.tcpdump.pcap"),
    (b"\x0a\x0d\x0d\x0a", "PCAPNG capture", "application/x-pcapng"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "image/png"),
    (b"\xff\xd8\xff", "JPEG image", "image/jpeg"),
    (b"GIF87a", "GIF image", "image/gif"),
    (b"GIF89a", "GIF image", "image/gif"),
    (b"%PDF-", "PDF document", "application/pdf"),
    (b"PK\x03\x04", "ZIP archive or Office document", "application/zip"),
    (b"MZ", "Windows executable", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "ELF executable", "application/x-elf"),
    (b"RIFF", "RIFF container", "application/octet-stream"),
)


def _signature(data: bytes, filename: str) -> dict[str, str | None]:
    for magic, description, mime_type in SIGNATURES:
        if data.startswith(magic):
            return {
                "description": description,
                "mime_type": mime_type,
                "extension": PurePath(filename).suffix.lower() or None,
            }
    guessed_type, _ = mimetypes.guess_type(filename)
    return {
        "description": "Unknown file signature",
        "mime_type": guessed_type,
        "extension": PurePath(filename).suffix.lower() or None,
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return -sum(
        (count / size) * math.log2(count / size)
        for count in counts.values()
    )


def _strings(
    data: bytes,
    min_length: int = 4,
    limit: int = MAX_STRING_RESULTS,
    max_length: int = MAX_STRING_LENGTH,
) -> list[str]:
    """Extract bounded printable ASCII runs.

    Callers that need a fuller listing (malware triage) pass a larger ``limit``;
    forensic analysis keeps the small default so the response stays compact.
    """
    results: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
            continue
        if len(current) >= min_length:
            results.append(current[:max_length].decode("ascii"))
        current.clear()
        if len(results) >= limit:
            break
    if len(current) >= min_length and len(results) < limit:
        results.append(current[:max_length].decode("ascii"))
    return results


def _capture_packet(data: bytes, link_type: int) -> dict[str, Any] | None:
    if link_type == 1:
        if len(data) < 14:
            return None
        ether_type = struct.unpack_from("!H", data, 12)[0]
        offset = 14
        if ether_type == 0x8100 and len(data) >= 18:
            ether_type = struct.unpack_from("!H", data, 16)[0]
            offset = 18
        if ether_type not in {0x0800, 0x86DD}:
            return {"protocol": f"EtherType 0x{ether_type:04x}"}
    elif link_type == 101:
        ether_type = 0x0800 if data and (data[0] >> 4) == 4 else 0x86DD
        offset = 0
    else:
        return {"protocol": f"link type {link_type}"}

    version = data[offset] >> 4 if len(data) > offset else 0
    if version == 4 and len(data) >= offset + 20:
        header_length = (data[offset] & 0x0F) * 4
        if len(data) < offset + header_length:
            return None
        protocol_number = data[offset + 9]
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
            protocol_number, f"IP protocol {protocol_number}"
        )
        result: dict[str, Any] = {
            "protocol": protocol,
            "source": ".".join(str(value) for value in data[offset + 12:offset + 16]),
            "destination": ".".join(str(value) for value in data[offset + 16:offset + 20]),
        }
        transport_offset = offset + header_length
        if protocol_number in {6, 17} and len(data) >= transport_offset + 4:
            result["source_port"], result["destination_port"] = struct.unpack_from(
                "!HH", data, transport_offset
            )
        return result
    if version == 6 and len(data) >= offset + 40:
        protocol_number = data[offset + 6]
        protocol = {6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(
            protocol_number, f"IPv6 protocol {protocol_number}"
        )
        result = {
            "protocol": protocol,
            "source": ":".join(f"{data[index]:02x}{data[index + 1]:02x}" for index in range(offset + 8, offset + 24, 2)),
            "destination": ":".join(f"{data[index]:02x}{data[index + 1]:02x}" for index in range(offset + 24, offset + 40, 2)),
        }
        transport_offset = offset + 40
        if protocol_number in {6, 17} and len(data) >= transport_offset + 4:
            result["source_port"], result["destination_port"] = struct.unpack_from(
                "!HH", data, transport_offset
            )
        return result
    return None


def _pcap_details(data: bytes) -> dict[str, Any]:
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return {
            "format": "PCAPNG",
            "packet_count": None,
            "protocols": {},
            "endpoints": [],
            "warnings": ["PCAPNG packet decoding is limited to format identification in this analyzer."],
        }
    if len(data) < 24:
        return {"format": "PCAP", "packet_count": 0, "protocols": {}, "endpoints": []}
    byte_order = "<" if data[:4] in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"} else ">"
    link_type = struct.unpack_from(f"{byte_order}I", data, 20)[0]
    offset = 24
    packets = 0
    protocols: Counter[str] = Counter()
    endpoints: Counter[tuple[str, str]] = Counter()
    ports: Counter[int] = Counter()
    while offset + 16 <= len(data) and packets < MAX_CAPTURE_PACKETS:
        _, _, captured_length, _ = struct.unpack_from(f"{byte_order}IIII", data, offset)
        offset += 16
        if captured_length > len(data) - offset:
            break
        packet = _capture_packet(data[offset:offset + captured_length], link_type)
        offset += captured_length
        packets += 1
        if not packet:
            continue
        protocols[packet["protocol"]] += 1
        if "source" in packet and "destination" in packet:
            endpoints[(packet["source"], packet["destination"])] += 1
        for key in ("source_port", "destination_port"):
            if key in packet:
                ports[packet[key]] += 1
    return {
        "format": "PCAP",
        "link_type": link_type,
        "packet_count": packets,
        "protocols": dict(protocols),
        "top_endpoints": [
            {"source": source, "destination": destination, "packets": count}
            for (source, destination), count in endpoints.most_common(20)
        ],
        "top_ports": [{"port": port, "packets": count} for port, count in ports.most_common(20)],
    }


def analyze_bytes(
    data: bytes,
    filename: str,
    declared_content_type: str | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("File exceeds the 10 MB limit")
    signature = _signature(data, filename)
    entropy = round(_entropy(data), 4)
    extracted_strings = _strings(data)
    findings: list[Finding] = []
    warnings = [
        "Static inspection only; the uploaded file was not executed.",
        "Metadata, entropy, and signatures are indicators and do not prove malicious activity.",
    ]
    capture_details = None
    if signature["description"] in {"PCAP capture", "PCAPNG capture"}:
        capture_details = _pcap_details(data)
        findings.append(
            Finding(
                title="Packet capture detected",
                severity="info",
                evidence=f"Static {capture_details['format']} metadata and packet summaries were extracted",
            )
        )
    if declared_content_type and signature["mime_type"] and declared_content_type != signature["mime_type"]:
        warnings.append("Declared content type differs from the detected signature type.")
        findings.append(
            Finding(
                title="Declared content type differs from detected type",
                severity="low",
                evidence=f"Declared {declared_content_type}; detected {signature['mime_type']}",
            )
        )
    if signature["description"] in {"ELF executable", "Windows executable"}:
        findings.append(
            Finding(
                title="Executable file detected",
                severity="info",
                evidence=f"Detected signature: {signature['description']}",
            )
        )
    if entropy >= 7.5:
        findings.append(
            Finding(
                title="High-entropy content detected",
                severity="low",
                evidence=f"Measured entropy: {entropy} bits per byte; this may indicate compression or encryption",
            )
        )
    flag_like = next(
        (value for value in extracted_strings if re.search(r"\b(?:CTF|FLAG)\{[^}]+\}", value, re.IGNORECASE)),
        None,
    )
    if flag_like:
        findings.append(
            Finding(
                title="Flag-like string detected",
                severity="info",
                evidence=f"Printable string matched a CTF/flag pattern: {flag_like}",
            )
        )
    details = {
        "filename": filename,
        "size_bytes": len(data),
        "declared_content_type": declared_content_type,
        "signature": signature,
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        },
        "entropy_bits_per_byte": entropy,
        "hex_preview": data[:256].hex(" "),
        "strings": extracted_strings,
        "warnings": warnings,
    }
    if capture_details is not None:
        details["capture"] = capture_details
    return details, findings
