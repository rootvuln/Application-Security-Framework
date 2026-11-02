from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from app.modules.forensics.analyzer import analyze_bytes as analyze_forensic_bytes

MAX_LOG_SIZE = 10 * 1024 * 1024
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
        return original, datetime.fromisoformat(normalized)
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
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    forensic_details, forensic_findings = analyze_forensic_bytes(
        data,
        filename,
        "application/vnd.tcpdump.pcap",
    )
    return {
        "filename": filename,
        "source_format": forensic_details["signature"]["description"],
        "capture": forensic_details.get("capture"),
        "hashes": forensic_details["hashes"],
        "warnings": [
            "Packet captures are analyzed as network data, not text logs.",
            "Static packet summaries do not prove malicious activity.",
        ],
    }, [finding.model_dump() for finding in forensic_findings]


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
