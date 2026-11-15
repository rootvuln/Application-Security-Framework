"""Log and packet-capture analysis: threat detection and anomaly scoring."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import struct
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Iterator

from app.core.config import MAX_LOG_SIZE as LOG_UPLOAD_LIMIT


# ── pcap_analysis.py ──────────────────────────────────────────────────────────

MAX_CAPTURE_PACKETS = 200_000
MAX_HTTP_SAMPLES = 100
MAX_DNS_SAMPLES = 100
MAX_SNI_SAMPLES = 100
MAX_PAYLOAD_BYTES = 8_192
MAX_TIMELINE_EVENTS = 40

# Scan thresholds
CAPTURE_SCAN_MIN_DISTINCT_PORTS = 15
SCAN_MIN_SYN = 10
SYN_FLOOD_MIN_SYN = 100
LARGE_TRANSFER_BYTES = 5 * 1024 * 1024
ICMP_FLOOD_MIN = 200

SUSPICIOUS_PORTS = {
    23: "telnet",
    2323: "telnet-alt",
    4444: "metasploit",
    1337: "leet",
    31337: "back-orifice",
    6667: "irc",
    6660: "irc",
    6697: "ircs",
}

PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 110: "pop3", 123: "ntp",
    135: "msrpc", 137: "netbios", 139: "netbios", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "smtp", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 3306: "mysql", 3389: "rdp", 5060: "sip", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # nanosecond resolution
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

HTTP_METHOD_PREFIXES = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ",
)

TCP_SYN = 0x02
TCP_ACK = 0x10


# ── Capture containers ───────────────────────────────────────────────────────


def _iter_classic(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    magic = PCAP_MAGIC.get(data[:4])
    if magic is None or len(data) < 24:
        return
    byte_order, divisor = magic
    link_type = struct.unpack_from(f"{byte_order}I", data, 20)[0] & 0x0FFFFFFF
    offset = 24
    size = len(data)
    while offset + 16 <= size:
        seconds, fraction, captured, _original = struct.unpack_from(
            f"{byte_order}IIII", data, offset
        )
        offset += 16
        if captured > size - offset:
            break
        yield seconds + fraction / divisor, link_type, data[offset:offset + captured]
        offset += captured


def _iter_pcapng(data: bytes) -> Iterator[tuple[float, int, bytes]]:
    offset = 0
    size = len(data)
    order = "<"
    link_types: list[int] = []
    resolutions: list[int] = []
    while offset + 12 <= size:
        block_type, block_length = struct.unpack_from(f"{order}II", data, offset)
        if block_type == 0x0A0D0D0A:  # Section Header Block — may flip byte order
            if offset + 16 > size:
                break
            link_types, resolutions = [], []
            order = "<" if data[offset + 8:offset + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            block_type, block_length = struct.unpack_from(f"{order}II", data, offset)
        if block_length < 12 or block_length > size - offset:
            break
        body = data[offset + 8:offset + block_length - 4]
        if block_type == 0x00000001:  # Interface Description Block
            if len(body) < 8:
                offset += block_length
                continue
            link_type = struct.unpack_from(f"{order}H", body, 0)[0]
            resolution = 6  # default: microseconds
            position = 8  # skip link type + reserved + snaplen
            while position + 4 <= len(body):
                code, length = struct.unpack_from(f"{order}HH", body, position)
                position += 4
                if code == 0:
                    break
                if code == 9 and length >= 1:
                    resolution = body[position] & 0x7F
                position += length + ((4 - length % 4) % 4)
            link_types.append(link_type)
            resolutions.append(resolution)
        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) < 20:
                offset += block_length
                continue
            interface, high, low, captured, _original = struct.unpack_from(
                f"{order}IIIII", body, 0
            )
            if interface < len(link_types):
                payload = body[20:20 + captured]
                resolution = resolutions[interface] if interface < len(resolutions) else 6
                timestamp = ((high << 32) | low) / (10 ** resolution)
                yield timestamp, link_types[interface], payload
        elif block_type == 0x00000003 and link_types:  # Simple Packet Block
            if len(body) >= 4:
                captured = struct.unpack_from(f"{order}I", body, 0)[0]
                payload = body[4:4 + captured]
                if payload:
                    yield 0.0, link_types[0], payload
        offset += block_length


# ── Packet decoding ─────────────────────────────────────────────────────────


def _parse_ipv4(raw: bytes) -> dict[str, Any] | None:
    if len(raw) < 20:
        return None
    header_length = (raw[0] & 0x0F) * 4
    if header_length < 20 or len(raw) < header_length:
        return None
    protocol_number = raw[9]
    fragment_field = struct.unpack_from("!H", raw, 6)[0]
    fragmented = bool(fragment_field & 0x1FFF)
    total_length = struct.unpack_from("!H", raw, 2)[0]
    end = min(len(raw), total_length) if total_length >= header_length else len(raw)
    return _transport(
        "IPv4",
        protocol_number,
        str(ipaddress.ip_address(raw[12:16])),
        str(ipaddress.ip_address(raw[16:20])),
        raw[header_length:end],
        fragmented,
    )


def _parse_ipv6(raw: bytes) -> dict[str, Any] | None:
    if len(raw) < 40:
        return None
    next_header = raw[6]
    payload_length = struct.unpack_from("!H", raw, 4)[0]
    payload = raw[40:min(len(raw), 40 + payload_length)]
    offset = 0
    while next_header in (0, 43, 60) and offset + 2 <= len(payload):
        next_header, extension_length = payload[offset], payload[offset + 1]
        offset += (extension_length + 1) * 8
    return _transport(
        "IPv6",
        next_header,
        str(ipaddress.ip_address(raw[8:24])),
        str(ipaddress.ip_address(raw[24:40])),
        payload[offset:],
        False,
    )


def _transport(
    family: str,
    protocol_number: int,
    source: str,
    destination: str,
    payload: bytes,
    fragmented: bool,
) -> dict[str, Any]:
    protocol = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMPv6"}.get(
        protocol_number, f"IP protocol {protocol_number}"
    )
    result: dict[str, Any] = {
        "ip_version": family,
        "protocol": protocol,
        "source": source,
        "destination": destination,
    }
    if protocol_number not in (6, 17) or len(payload) < 4:
        return result
    source_port, destination_port = struct.unpack_from("!HH", payload, 0)
    result["source_port"] = source_port
    result["destination_port"] = destination_port

    if protocol_number == 6:
        if len(payload) < 20:
            return result
        result["tcp_flags"] = payload[13]
        transport_length = (payload[12] >> 4) * 4
        application = payload[transport_length:] if transport_length >= 20 else b""
    else:
        application = payload[8:] if len(payload) >= 8 else b""

    if fragmented:
        application = b""
    result["application"] = application[:MAX_PAYLOAD_BYTES]
    return result


def _parse_packet(raw: bytes, link_type: int) -> dict[str, Any] | None:
    if link_type == 1:  # Ethernet
        if len(raw) < 14:
            return None
        ether_type = struct.unpack_from("!H", raw, 12)[0]
        offset = 14
        while ether_type in (0x8100, 0x88A8) and len(raw) >= offset + 4:
            ether_type = struct.unpack_from("!H", raw, offset + 2)[0]
            offset += 4
        if ether_type == 0x0800:
            return _parse_ipv4(raw[offset:])
        if ether_type == 0x86DD:
            return _parse_ipv6(raw[offset:])
        if ether_type == 0x0806:
            return {"protocol": "ARP"}
        return {"protocol": f"EtherType 0x{ether_type:04x}"}
    if link_type == 101:  # Raw IP
        if not raw:
            return None
        version = raw[0] >> 4
        if version == 4:
            return _parse_ipv4(raw)
        if version == 6:
            return _parse_ipv6(raw)
        return None
    if link_type == 113:  # Linux cooked capture
        if len(raw) < 16:
            return None
        protocol = struct.unpack_from("!H", raw, 14)[0]
        if protocol == 0x0800:
            return _parse_ipv4(raw[16:])
        if protocol == 0x86DD:
            return _parse_ipv6(raw[16:])
        return {"protocol": f"Linux SLL 0x{protocol:04x}"}
    if link_type == 0:  # BSD loopback
        return _parse_ipv4(raw[4:]) if len(raw) > 4 else None
    return None


# ── Application protocols ───────────────────────────────────────────────────


def _dns_query(payload: bytes, over_tcp: bool) -> str | None:
    data = payload[2:] if over_tcp and len(payload) > 2 else payload
    if len(data) < 13:
        return None
    # QR bit set means a response, not a query
    if data[2] & 0x80:
        return None
    position = 12
    labels: list[str] = []
    while position < len(data):
        length = data[position]
        if length == 0:
            break
        if length > 63 or position + 1 + length > len(data):
            return None
        labels.append(data[position + 1:position + 1 + length].decode("latin-1", "replace"))
        position += 1 + length
        if len(labels) > 20:
            return None
    if not labels:
        return None
    return ".".join(labels)


def _http_request(payload: bytes) -> dict[str, Any] | None:
    if not payload.startswith(HTTP_METHOD_PREFIXES):
        return None
    head, _, body = payload.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request = lines[0].decode("latin-1", "replace").split()
    if len(request) < 2:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if separator:
            headers[name.decode("latin-1").strip().lower()] = value.decode(
                "latin-1", "replace"
            ).strip()
    authorization = headers.get("authorization", "")
    return {
        "method": request[0],
        "path": request[1][:300],
        "host": headers.get("host"),
        "user_agent": headers.get("user-agent"),
        "cleartext_basic_auth": authorization.lower().startswith("basic"),
        "password_in_body": b"password=" in body[:4096].lower(),
    }


def _tls_sni(payload: bytes) -> str | None:
    if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        position = 5 + 4 + 2 + 32  # record + handshake header + version + random
        position += 1 + payload[position]  # session id
        cipher_length = struct.unpack_from("!H", payload, position)[0]
        position += 2 + cipher_length
        position += 1 + payload[position]  # compression methods
        if position + 2 > len(payload):
            return None
        extensions_length = struct.unpack_from("!H", payload, position)[0]
        position += 2
        end = min(len(payload), position + extensions_length)
        while position + 4 <= end:
            extension_type, extension_length = struct.unpack_from(
                "!HH", payload, position
            )
            position += 4
            if extension_type == 0:
                list_end = min(len(payload), position + 2 + struct.unpack_from(
                    "!H", payload, position
                )[0])
                cursor = position + 2
                while cursor + 3 <= list_end:
                    name_type = payload[cursor]
                    name_length = struct.unpack_from("!H", payload, cursor + 1)[0]
                    cursor += 3
                    if name_type == 0 and cursor + name_length <= len(payload):
                        return payload[cursor:cursor + name_length].decode(
                            "latin-1", "replace"
                        )
                    cursor += name_length
                return None
            position += extension_length
    except (IndexError, struct.error):
        return None
    return None


# ── Correlation ─────────────────────────────────────────────────────────────


def _capture_timestamp(seconds: float) -> str | None:
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _capture_finding(
    title: str,
    severity: str,
    evidence: str,
    description: str,
    category: str,
    confidence: str = "medium",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "description": description,
        "category": category,
        "confidence": confidence,
        **extra,
    }


def analyze_capture(
    data: bytes, filename: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    is_pcapng = data.startswith(b"\x0a\x0d\x0d\x0a")
    packets = _iter_pcapng(data) if is_pcapng else _iter_classic(data)

    protocols: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    destinations: Counter[str] = Counter()
    conversations: Counter[tuple[str, str]] = Counter()
    destination_ports: Counter[int] = Counter()
    flow_bytes: Counter[tuple[str, str]] = Counter()
    dns_queries: Counter[str] = Counter()
    tls_names: Counter[str] = Counter()
    http_hosts: Counter[str] = Counter()

    per_source_ports: dict[str, set[int]] = defaultdict(set)
    per_source_syn: Counter[str] = Counter()
    per_source_ack: Counter[str] = Counter()
    first_seen: dict[str, float] = {}

    http_samples: list[dict[str, Any]] = []
    cleartext_credentials: list[dict[str, Any]] = []
    suspicious_services: list[dict[str, Any]] = []

    packet_count = 0
    decoded_count = 0
    byte_count = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None
    link_types_seen: set[int] = set()

    for timestamp, link_type, raw in packets:
        packet_count += 1
        if packet_count > MAX_CAPTURE_PACKETS:
            break
        byte_count += len(raw)
        if first_timestamp is None:
            first_timestamp = timestamp
        last_timestamp = timestamp
        link_types_seen.add(link_type)

        packet = _parse_packet(raw, link_type)
        if not packet:
            continue
        decoded_count += 1
        protocols[packet["protocol"]] += 1

        source = packet.get("source")
        destination = packet.get("destination")
        if not source or not destination:
            continue
        sources[source] += 1
        destinations[destination] += 1
        conversations[(source, destination)] += 1
        flow_bytes[(source, destination)] += len(raw)
        first_seen.setdefault(source, timestamp)

        source_port = packet.get("source_port")
        destination_port = packet.get("destination_port")
        application = packet.get("application") or b""

        if destination_port is not None:
            destination_ports[destination_port] += 1
            per_source_ports[source].add(destination_port)
            flags = packet.get("tcp_flags") or 0
            syn_only = bool(flags & TCP_SYN) and not bool(flags & TCP_ACK)
            # A scan probe aimed at port 23 is not "traffic to telnet"; only count
            # ports that carried application data or completed a handshake.
            if (
                destination_port in SUSPICIOUS_PORTS
                and not syn_only
                and len(suspicious_services) < 50
            ):
                suspicious_services.append(
                    {
                        "source": source,
                        "destination": destination,
                        "port": destination_port,
                        "service": SUSPICIOUS_PORTS[destination_port],
                        "timestamp": timestamp,
                    }
                )
        if packet["protocol"] == "TCP":
            flags = packet.get("tcp_flags", 0)
            if flags & TCP_SYN and not flags & TCP_ACK:
                per_source_syn[source] += 1
            if flags & TCP_ACK:
                per_source_ack[source] += 1

        if not application:
            continue

        if destination_port == 53 or source_port == 53:
            name = _dns_query(application, over_tcp=packet["protocol"] == "TCP")
            if name and len(dns_queries) < MAX_DNS_SAMPLES:
                dns_queries[name] += 1

        request = _http_request(application)
        if request:
            if len(http_samples) < MAX_HTTP_SAMPLES:
                http_samples.append(
                    {**request, "source": source, "destination": destination, "timestamp": timestamp}
                )
            if request.get("host"):
                http_hosts[request["host"]] += 1
            if request.get("cleartext_basic_auth") or request.get("password_in_body"):
                if len(cleartext_credentials) < 20:
                    cleartext_credentials.append(
                        {**request, "source": source, "destination": destination, "timestamp": timestamp}
                    )

        if destination_port == 443:
            name = _tls_sni(application)
            if name and len(tls_names) < MAX_SNI_SAMPLES:
                tls_names[name] += 1

    findings: list[dict[str, Any]] = []
    attacker_ips: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []

    def add_timeline(when: float | None, message: str, severity: str, source: str | None = None) -> None:
        if len(timeline) >= MAX_TIMELINE_EVENTS:
            return
        timeline.append(
            {
                "timestamp": _capture_timestamp(when) if when is not None else None,
                "message": message,
                "severity": severity,
                "source_ip": source,
            }
        )

    if packet_count == 0 and (is_pcapng or data[:4] in PCAP_MAGIC):
        findings.append(
            _capture_finding(
                "Capture could not be decoded",
                "info",
                "No packets were parsed from the uploaded file",
                description=(
                    "The file matched a capture signature but no packet records were "
                    "readable. It may be truncated or use an unsupported link type."
                ),
                category="capture",
                confidence="low",
            )
        )
    elif packet_count and not decoded_count:
        findings.append(
            _capture_finding(
                "Frames could not be decoded",
                "info",
                f"{packet_count} frame(s) present but no packet headers were readable "
                f"(link type(s): {', '.join(str(t) for t in sorted(link_types_seen)) or 'unknown'})",
                description=(
                    "The capture container was read but the link-layer format is not "
                    "one of Ethernet, raw IP, Linux SLL or loopback, so flows cannot "
                    "be correlated. Re-export the capture from your packet analyser "
                    "with Ethernet encapsulation."
                ),
                category="capture",
                confidence="low",
            )
        )

    # Port scans
    for source, ports in per_source_ports.items():
        if len(ports) < CAPTURE_SCAN_MIN_DISTINCT_PORTS:
            continue
        syns = per_source_syn.get(source, 0)
        if syns < SCAN_MIN_SYN:
            continue
        ordered = sorted(ports)
        findings.append(
            _capture_finding(
                "Possible port scan",
                "medium",
                f"{source} contacted {len(ports)} distinct destination ports ({syns} SYN packets)",
                description=(
                    "One source touched many destination ports in this capture. This is "
                    "characteristic of service discovery; confirm against authorised "
                    "scanning before treating it as hostile."
                ),
                category="network",
                confidence="medium",
                source_ip=source,
                distinct_destination_ports=ordered[:50],
                observed_count=len(ports),
            )
        )
        attacker_ips.append(
            {
                "ip": source,
                "failure_count": len(ports),
                "success_count": 0,
                "verdict": "scanner",
            }
        )
        add_timeline(
            first_seen.get(source),
            f"Port scan from {source}: {len(ports)} distinct destination ports",
            "medium",
            source,
        )

    # SYN flood
    for source, syns in per_source_syn.items():
        if syns < SYN_FLOOD_MIN_SYN:
            continue
        acknowledgements = per_source_ack.get(source, 0)
        if acknowledgements * 10 >= syns:
            continue
        findings.append(
            _capture_finding(
                "High SYN volume without completed handshakes",
                "high",
                f"{syns} SYN packets from {source} against {acknowledgements} ACK packets",
                description=(
                    "A large number of connection attempts never progressed to an "
                    "acknowledgement, which is consistent with a SYN flood or an "
                    "aggressive scan."
                ),
                category="network",
                confidence="medium",
                source_ip=source,
                observed_count=syns,
            )
        )
        if not any(item["ip"] == source for item in attacker_ips):
            attacker_ips.append(
                {
                    "ip": source,
                    "failure_count": syns,
                    "success_count": acknowledgements,
                    "verdict": "suspicious",
                }
            )
        add_timeline(
            first_seen.get(source),
            f"{syns} SYN packets without matching handshakes from {source}",
            "high",
            source,
        )

    # Cleartext credentials
    if cleartext_credentials:
        sample = cleartext_credentials[0]
        findings.append(
            _capture_finding(
                "Credentials sent over cleartext HTTP",
                "high",
                f"{len(cleartext_credentials)} HTTP request(s) carried Basic auth or a password field, first to {sample.get('host') or sample['destination']}",
                description=(
                    "HTTP Basic authentication and form passwords are readable by anyone "
                    "on the path; traffic should use HTTPS."
                ),
                category="credentials",
                confidence="high",
                source_ip=sample["source"],
                observed_count=len(cleartext_credentials),
            )
        )
        add_timeline(
            sample["timestamp"],
            f"Cleartext credential material to {sample.get('host') or sample['destination']}",
            "high",
            sample["source"],
        )

    # Suspicious service ports
    if suspicious_services:
        ports_seen = sorted({item["port"] for item in suspicious_services})
        findings.append(
            _capture_finding(
                "Traffic to commonly abused ports",
                "low",
                f"{len(suspicious_services)} packet(s) to port(s) {', '.join(str(p) for p in ports_seen)}",
                description=(
                    "These ports are frequently used by remote-access tools and botnet "
                    "command channels; the traffic may still be legitimate."
                ),
                category="network",
                confidence="low",
                observed_count=len(suspicious_services),
            )
        )

    # DNS tunnelling / abuse indicators
    long_labels = [
        name for name in dns_queries
        if any(len(label) >= 45 for label in name.split("."))
    ]
    if long_labels:
        findings.append(
            _capture_finding(
                "Unusually long DNS labels",
                "medium",
                f"{len(long_labels)} queried name(s) contain a label of 45+ characters, e.g. {long_labels[0][:120]}",
                description=(
                    "Long, high-entropy labels are a common sign of DNS tunnelling or "
                    "data exfiltration over DNS."
                ),
                category="dns",
                confidence="medium",
                observed_count=len(long_labels),
            )
        )
        add_timeline(None, f"Long DNS labels observed: {long_labels[0][:80]}", "medium")

    # Large transfers
    for (source, destination), total in flow_bytes.items():
        if total < LARGE_TRANSFER_BYTES:
            continue
        findings.append(
            _capture_finding(
                "Large data transfer",
                "low",
                f"{total / (1024 * 1024):.1f} MB from {source} to {destination}",
                description=(
                    "A single flow carried more than 5 MB. Confirm the destination is "
                    "expected before treating this as exfiltration."
                ),
                category="network",
                confidence="low",
                source_ip=source,
                observed_count=total,
            )
        )

    # ICMP flood
    icmp_total = protocols.get("ICMP", 0) + protocols.get("ICMPv6", 0)
    if icmp_total >= ICMP_FLOOD_MIN:
        findings.append(
            _capture_finding(
                "High ICMP volume",
                "low",
                f"{icmp_total} ICMP packets in this capture",
                description="Heavy ICMP traffic can indicate a flood or tunnel.",
                category="network",
                confidence="low",
                observed_count=icmp_total,
            )
        )

    first_iso = _capture_timestamp(first_timestamp) if first_timestamp is not None else None
    last_iso = _capture_timestamp(last_timestamp) if last_timestamp is not None else None
    duration = (
        round(last_timestamp - first_timestamp, 3)
        if first_iso and last_iso and first_timestamp is not None and last_timestamp is not None
        else None
    )

    if is_pcapng:
        container, container_label = "PCAPNG", "PCAPNG capture"
    elif data[:4] in PCAP_MAGIC:
        container, container_label = "PCAP", "PCAP capture"
    else:
        container, container_label = "Unknown", "unrecognised file"

    port_activity = [
        {
            "port": port,
            "count": count,
            "service": PORT_SERVICES.get(port),
        }
        for port, count in destination_ports.most_common(40)
    ]

    warnings = [
        "Packet captures are analyzed as network data, not text logs.",
        "Static packet summaries do not prove malicious activity.",
    ]
    if packet_count == 0 and (is_pcapng or data[:4] in PCAP_MAGIC):
        warnings.insert(0, "No packets could be decoded from this file.")

    details: dict[str, Any] = {
        "filename": filename,
        "file_size": len(data),
        "format": container,
        "source_format": container_label,
        "packet_count": packet_count,
        "bytes": byte_count,
        "first_timestamp": first_iso,
        "last_timestamp": last_iso,
        "duration_seconds": duration,
        "attacker_ips": attacker_ips,
        "timeline": timeline,
        "ip_statistics": {
            "top_source_ips": [{"ip": ip, "count": count} for ip, count in sources.most_common(10)],
            "top_dest_ips": [{"ip": ip, "count": count} for ip, count in destinations.most_common(10)],
            "top_conversations": [
                {"source": source, "destination": destination, "count": count}
                for (source, destination), count in conversations.most_common(10)
            ],
        },
        "port_activity": port_activity,
        "raw_stats": {
            "format": container,
            "packet_count": packet_count,
            "bytes": byte_count,
            "duration_seconds": duration,
            "protocols": dict(protocols.most_common()),
        },
        "capture": {
            "format": container,
            "packet_count": packet_count,
            "bytes": byte_count,
            "duration_seconds": duration,
            "protocols": dict(protocols.most_common()),
            "top_talkers": [
                {"source": source, "destination": destination, "packets": count}
                for (source, destination), count in conversations.most_common(15)
            ],
            "dns_queries": [{"name": name, "count": count} for name, count in dns_queries.most_common(50)],
            "http_requests": http_samples,
            "http_hosts": [{"host": host, "count": count} for host, count in http_hosts.most_common(20)],
            "tls_server_names": [{"name": name, "count": count} for name, count in tls_names.most_common(30)],
            "suspicious_services": [
                {
                    "source": item["source"],
                    "destination": item["destination"],
                    "port": item["port"],
                    "service": item["service"],
                }
                for item in suspicious_services[:20]
            ],
            "cleartext_credentials": [
                {
                    "source": item["source"],
                    "destination": item["destination"],
                    "method": item["method"],
                    "host": item.get("host"),
                    "path": item["path"],
                    "timestamp": item.get("timestamp"),
                }
                for item in cleartext_credentials[:20]
            ],
        },
        "hashes": {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha512": hashlib.sha512(data).hexdigest(),
        },
        "warnings": warnings,
    }
    return details, findings


# ── analyzer.py ───────────────────────────────────────────────────────────────

MAX_LOG_SIZE = LOG_UPLOAD_LIMIT  # 10 MB upload cap (see app.core.config)
MAX_LOG_LINES = 100_000
BRUTE_FORCE_WINDOW_SECONDS = 5 * 60
SCAN_MIN_DISTINCT_PORTS = 3
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FAILED_RE = re.compile(
    r"(failed password|authentication failure|login failed|invalid user)", re.I
)
SUCCESS_RE = re.compile(
    r"(accepted password|authentication successful|login successful)", re.I
)
SCAN_RE = re.compile(r"(nmap|masscan|rustscan|port scan|connection refused)", re.I)
PORT_RE = re.compile(r"\bport\s*[:=]?\s*(\d{1,5})\b", re.I)
TIMESTAMP_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\b"
)
SOURCE_HINT_RE = re.compile(
    r"\b(?:from|source|src)\s*[:=]?\s*((?:\d{1,3}\.){3}\d{1,3})\b", re.I
)
DESTINATION_HINT_RE = re.compile(
    r"\b(?:to|destination|dest)\s*[:=]?\s*((?:\d{1,3}\.){3}\d{1,3})\b", re.I
)
SYSLOG_TIMESTAMP_RE = re.compile(
    r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b"
)


def _decode_text(data: bytes) -> tuple[str, str]:
    if data.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        encodings = ("utf-32",)
    elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings = ("utf-16",)
    elif data.startswith(b"\xef\xbb\xbf"):
        encodings = ("utf-8-sig",)
    else:
        encodings = ("utf-8", "cp1252", "latin-1")
    for encoding in encodings:
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if text.count("\x00") > max(1, len(text) // 100):
            continue
        return text, encoding
    raise ValueError(
        "Log file encoding is unsupported; save it as UTF-8, UTF-16, or Windows-1252"
    )


def _json_lines(text: str) -> tuple[list[str], list[dict[str, Any] | None], int]:
    lines: list[str] = []
    records: list[dict[str, Any] | None] = []
    invalid = 0
    for raw in text.splitlines()[:MAX_LOG_LINES]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            invalid += 1
            lines.append(raw)
            records.append(None)
            continue
        if isinstance(record, dict):
            records.append(record)
            lines.append(json.dumps(record, sort_keys=True))
        else:
            invalid += 1
            lines.append(raw)
            records.append(None)
    return lines, records, invalid


def _lines(
    data: bytes, filename: str
) -> tuple[list[str], str, list[dict[str, Any] | None], int]:
    if len(data) > MAX_LOG_SIZE:
        raise ValueError("Log file exceeds the 10 MB limit")
    text, encoding = _decode_text(data)
    lower_name = filename.lower()
    if lower_name.endswith((".jsonl", ".ndjson")):
        lines, records, invalid = _json_lines(text)
        return lines, encoding, records, invalid
    if lower_name.endswith(".json"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON log") from exc
        if isinstance(parsed, list):
            records = [
                item if isinstance(item, dict) else None
                for item in parsed[:MAX_LOG_LINES]
            ]
            return (
                [json.dumps(item, sort_keys=True) for item in parsed[:MAX_LOG_LINES]],
                encoding,
                records,
                sum(item is None for item in records),
            )
        if isinstance(parsed, dict):
            return [json.dumps(parsed, sort_keys=True)], encoding, [parsed], 0
        raise ValueError("JSON log must contain an object or array")
    return [
        line for line in text.splitlines()[:MAX_LOG_LINES]
        if line.strip() and not line.lstrip().startswith("#")
    ], encoding, [], 0


def _valid_ipv4(value: str) -> str | None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(address) if address.version == 4 else None


def _record_value(record: dict[str, Any], names: tuple[str, ...]) -> Any:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for name in names:
        if name in lowered:
            return lowered[name]
    return None


def _timestamp(value: Any, line: str) -> tuple[str | None, datetime | None]:
    candidate = str(value) if value is not None else None
    match = TIMESTAMP_RE.search(candidate or line)
    if not match:
        match = SYSLOG_TIMESTAMP_RE.search(candidate or line)
    if not match:
        return None, None
    original = match.group(0)
    normalized = original.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return original, dt
    except ValueError:
        return original, None


def _ips(line: str) -> list[str]:
    candidates = IP_RE.findall(line)
    if len(candidates) == 1:
        valid = _valid_ipv4(candidates[0])
        return [valid] if valid is not None else []
    return list(dict.fromkeys(
        valid for candidate in candidates
        if (valid := _valid_ipv4(candidate)) is not None
    ))


def _event(
    line: str,
    record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = record or {}
    line_lower = line.lower()
    source_value = (
        _record_value(record, ("source_ip", "src_ip", "source", "client_ip", "remote_ip"))
        if record else None
    )
    destination_value = (
        _record_value(record, ("destination_ip", "dest_ip", "destination", "server_ip"))
        if record else None
    )
    source = _valid_ipv4(str(source_value)) if source_value is not None else None
    destination = _valid_ipv4(str(destination_value)) if destination_value is not None else None
    observed = _ips(line)
    source_hint = SOURCE_HINT_RE.search(line) if (
        source_value is None and any(token in line_lower for token in ("from", "source", "src"))
    ) else None
    destination_hint = DESTINATION_HINT_RE.search(line) if (
        destination_value is None and any(token in line_lower for token in ("to", "destination", "dest"))
    ) else None
    if source is None and source_value is None and source_hint:
        source = _valid_ipv4(source_hint.group(1))
    if destination is None and destination_value is None and destination_hint:
        destination = _valid_ipv4(destination_hint.group(1))
    if source is None and source_value is None and source_hint is None and destination_hint is None and len(observed) == 1 and (
        FAILED_RE.search(line) or SUCCESS_RE.search(line)
    ):
        source = observed[0]
    failed_match = FAILED_RE.search(line)
    failed = failed_match is not None
    success = False if failed else SUCCESS_RE.search(line) is not None
    scan_indicator = SCAN_RE.search(line) is not None
    port_value = (
        _record_value(record, ("destination_port", "dest_port", "port"))
        if record else None
    )
    port_match = PORT_RE.search(line) if "port" in line_lower else None
    try:
        port = int(port_value) if port_value is not None else (
            int(port_match.group(1)) if port_match else None
        )
    except (TypeError, ValueError):
        port = None
    timestamp_value = (
        _record_value(record, ("timestamp", "time", "datetime", "@timestamp"))
        if record else None
    )
    original_timestamp, parsed_timestamp = (
        _timestamp(timestamp_value, line)
        if timestamp_value is not None or (line and line[0].isdigit())
        else (None, None)
    )
    username_value = (
        _record_value(record, ("username", "user", "account", "target_user"))
        if record else None
    )
    username = str(username_value) if username_value is not None else None
    if username is None and (failed or success) and (
        " for " in line_lower or " user " in line_lower
    ):
        username_match = re.search(r"\b(?:for|user)\s+([A-Za-z0-9._@-]+)", line, re.I)
        username = username_match.group(1) if username_match else None
    if failed:
        category = "authentication_failure"
    elif success:
        category = "successful_authentication"
    elif scan_indicator and not re.search(r"connection refused", line, re.I):
        category = "scanning_activity"
    elif re.search(r"connection refused|connect(?:ion)? failed|timeout", line, re.I):
        category = "connection_failure"
    elif (
        _record_value(record, ("dns_query", "query", "qname", "rcode")) is not None
        or re.search(r"\b(?:dns|query|rcode|resolved|resolution)\b", line, re.I)
    ):
        category = "dns_event"
    elif re.search(r"\b(?:socket|tcp|udp|http|network)\b", line, re.I):
        category = "network_event"
    else:
        category = "other"
    return {
        "line": line,
        "category": category,
        "source_ip": source,
        "destination_ip": destination,
        "_observed_ips": observed,
        "_scan_indicator": scan_indicator,
        "port": port,
        "username": username,
        "timestamp": original_timestamp,
        "_time": parsed_timestamp,
    }


def _within_window(events: list[dict[str, Any]]) -> bool:
    times = [event["_time"] for event in events if event["_time"] is not None]
    if len(times) < 2:
        return True
    return (max(times) - min(times)).total_seconds() <= BRUTE_FORCE_WINDOW_SECONDS


def _finding(
    title: str,
    severity: str,
    evidence: str,
    *,
    description: str,
    category: str,
    confidence: str = "medium",
    **extra: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "description": description,
        "category": category,
        "confidence": confidence,
    }
    result.update(extra)
    return result


def _pcap_analysis(
    data: bytes, filename: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Decode a capture into flows, findings and log-analysis view models.

    Previously this delegated to the forensics analyser, which only identifies
    the file signature and hashes it - a .pcap upload therefore produced a
    single "Packet capture detected" finding and no network detail.
    """
    return analyze_capture(data, filename)


def analyze_bytes(data: bytes, filename: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    filename = str(filename or "uploaded-log")
    if data.startswith(
        (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        )
    ):
        return _pcap_analysis(data, filename)

    lines, encoding, records, invalid_json_records = _lines(data, filename)
    events = [
        _event(line, records[index] if index < len(records) else None)
        for index, line in enumerate(lines)
    ]
    failed = [event for event in events if event["category"] == "authentication_failure"]
    successful = [event for event in events if event["category"] == "successful_authentication"]
    scan_lines = [event for event in events if event["_scan_indicator"]]
    observed_roles: Counter[tuple[str, str]] = Counter()
    observed_ips: Counter[str] = Counter()
    for event in events:
        if event["source_ip"]:
            observed_roles[(event["source_ip"], "source")] += 1
            observed_ips[event["source_ip"]] += 1
        if event["destination_ip"]:
            observed_roles[(event["destination_ip"], "destination")] += 1
            observed_ips[event["destination_ip"]] += 1
        if not event["source_ip"] and not event["destination_ip"]:
            for address in event["_observed_ips"]:
                observed_roles[(address, "observed")] += 1
                observed_ips[address] += 1

    failed_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in failed:
        if event["source_ip"]:
            failed_by_source[event["source_ip"]].append(event)
    success_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in successful:
        if event["source_ip"]:
            success_by_source[event["source_ip"]].append(event)

    findings: list[dict[str, Any]] = []
    possible_brute_force: list[dict[str, Any]] = []
    for source, source_events in failed_by_source.items():
        if len(source_events) < 5 or not _within_window(source_events):
            continue
        usernames = sorted({event["username"] for event in source_events if event["username"]})
        item = {
            "source_ip": source,
            "failed_attempts": len(source_events),
            "time_window": "5 minutes",
            "targeted_usernames": usernames,
            "confidence": "medium",
        }
        possible_brute_force.append(item)
        findings.append(_finding(
            "Repeated authentication failures",
            "medium",
            f"{len(source_events)} failed authentication attempts from {source} within 5 minutes",
            description="Repeated authentication failures were observed from one source within the configured correlation window.",
            category="authentication",
            source_ip=source,
            failed_attempts=len(source_events),
            time_window="5 minutes",
            targeted_usernames=usernames,
            confidence="medium",
        ))
        findings.append(_finding(
            "Possible brute-force activity",
            "high",
            f"{len(source_events)} failed authentication attempts from {source} within 5 minutes",
            description="The volume and timing of failures from one source are consistent with possible password guessing, but do not prove compromise.",
            category="authentication",
            source_ip=source,
            failed_attempts=len(source_events),
            time_window="5 minutes",
            targeted_usernames=usernames,
            confidence="medium",
        ))

    for source, source_events in failed_by_source.items():
        successes = success_by_source.get(source, [])
        if not successes:
            continue
        failed_times = [event["_time"] for event in source_events if event["_time"]]
        success_times = [event["_time"] for event in successes if event["_time"]]
        correlated = (
            not failed_times or not success_times
            or any(0 <= (success_time - failed_time).total_seconds() <= BRUTE_FORCE_WINDOW_SECONDS
                   for failed_time in failed_times for success_time in success_times)
        )
        if correlated and len(source_events) >= 3:
            findings.append(_finding(
                "Repeated failures followed by successful authentication",
                "medium",
                f"{len(source_events)} failures followed by success from {source}",
                description="Successful authentication occurred AFTER repeated failures from the same source within the correlation window.",
                category="authentication",
                source_ip=source,
                failed_attempts=len(source_events),
                confidence="medium",
            ))

    port_events: dict[str, set[int]] = defaultdict(set)
    failed_ports: dict[str, set[int]] = defaultdict(set)
    for event in events:
        if event["source_ip"] and event["port"] is not None:
            port_events[event["source_ip"]].add(event["port"])
            if event["category"] == "connection_failure":
                failed_ports[event["source_ip"]].add(event["port"])
    possible_scanning: list[dict[str, Any]] = []
    for source, ports in port_events.items():
        if len(ports) < SCAN_MIN_DISTINCT_PORTS:
            continue
        item = {"source_ip": source, "distinct_destination_ports": sorted(ports)}
        possible_scanning.append(item)
        findings.append(_finding(
            "Possible scanning activity",
            "low",
            f"{source} contacted {len(ports)} distinct destination ports",
            description="One source contacted multiple destination ports; this is a possible scan indicator, not confirmation of scanning.",
            category="scanning",
            source_ip=source,
            distinct_destination_ports=sorted(ports),
            confidence="medium",
        ))
    connection_failures = [
        event for event in events if event["category"] == "connection_failure"
    ]
    if len(connection_failures) >= 3 and not possible_scanning:
        findings.append(_finding(
            "Repeated connection failures",
            "low",
            f"{len(connection_failures)} connection failures were observed without enough distinct ports to establish scanning activity",
            description="Repeated connection failures were observed, but the available evidence is insufficient to identify port scanning.",
            category="connection_failure",
            confidence="low",
        ))
    for address, count in observed_ips.items():
        if count >= 10:
            findings.append(_finding(
                "High-volume source observed",
                "low",
                f"{address} appeared {count} times in the log",
                description="A high-volume address was observed; frequency alone does not establish malicious activity.",
                category="network",
                source_ip=address,
                observed_count=count,
                confidence="low",
            ))

    suspicious_login_sequences: list[dict[str, Any]] = []
    for source, source_events in failed_by_source.items():
        successes = success_by_source.get(source, [])
        if not successes or len(source_events) < 3:
            continue
        if any(
            failure["_time"] is None
            or success["_time"] is None
            or 0 <= (success["_time"] - failure["_time"]).total_seconds() <= BRUTE_FORCE_WINDOW_SECONDS
            for failure in source_events
            for success in successes
        ):
            suspicious_login_sequences.append({
                "source_ip": source,
                "failed_attempts": len(source_events),
                "successful_authentications": len(successes),
                "targeted_usernames": sorted({
                    event["username"] for event in source_events + successes
                    if event["username"]
                }),
            })

    def timeline_key(item: tuple[int, dict[str, Any]]) -> tuple[bool, float, int]:
        index, event = item
        event_time = event["_time"]
        if event_time is None:
            return True, 0.0, index
        if event_time.tzinfo is None:
            comparable = event_time.replace(tzinfo=timezone.utc)
        else:
            comparable = event_time.astimezone(timezone.utc)
        return False, comparable.timestamp(), index

    ordered_events = (
        sorted(enumerate(events), key=timeline_key)
        if any(event["_time"] is not None for event in events)
        else list(enumerate(events))
    )
    timeline = [
        {
            "timestamp": event["timestamp"],
            "event_type": event["category"],
            "source_ip": event["source_ip"],
            "destination_ip": event["destination_ip"],
            "severity": "medium" if event["category"] in {
                "authentication_failure", "connection_failure"
            } else "info",
            "evidence": event["line"],
        }
        for _, event in ordered_events
    ]
    top_ips = [
        {
            "ip": address,
            "count": count,
            "role": max(
                ("source", "destination", "observed"),
                key=lambda role: observed_roles[(address, role)],
            ),
        }
        for address, count in observed_ips.most_common(20)
    ]
    failed_count = len(failed)
    success_count = len(successful)
    details: dict[str, Any] = {
        "filename": filename,
        "encoding": encoding,
        "line_count": len(lines),
        "failed_authentication_events": failed_count,
        "successful_authentication_events": success_count,
        "scan_indicator_lines": len(scan_lines),
        "top_source_ips": top_ips,
        "sample_failed_events": [event["line"] for event in failed[:10]],
        "invalid_json_records": invalid_json_records,
        "summary": {
            "total_events": len(lines),
            "failed_authentication_events": failed_count,
            "successful_authentication_events": success_count,
            "scan_indicator_lines": len(scan_lines),
            "unique_ips": len(observed_ips),
        },
        "authentication_analysis": {
            "top_failed_login_sources": [
                {"ip": source, "count": len(items)}
                for source, items in sorted(
                    failed_by_source.items(),
                    key=lambda item: len(item[1]),
                    reverse=True,
                )[:20]
            ],
            "possible_brute_force": possible_brute_force,
            "suspicious_login_sequences": suspicious_login_sequences,
        },
        "network_analysis": {
            "observed_ips": top_ips,
            "possible_scanning_sources": possible_scanning,
        },
        "timeline": timeline,
        "event_categories": dict(Counter(event["category"] for event in events)),
        "warnings": [
            "Pattern matching is heuristic and does not prove compromise.",
            *(
                [f"{invalid_json_records} JSON Lines record(s) could not be parsed."]
                if invalid_json_records
                else []
            ),
        ],
    }
    return details, findings
