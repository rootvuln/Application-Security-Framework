from __future__ import annotations

from typing import Any

import dns.exception
import dns.resolver

from app.modules.web.validators import validate_hostname

# Record types queried for every target. CNAME is included because the UI
# renders a row for it; a target without a CNAME simply returns an empty list.
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _text_values(answers: Any) -> list[str]:
    """Render an answer set as text, skipping records that cannot be decoded."""
    values: list[str] = []
    for answer in answers:
        try:
            values.append(answer.to_text())
        except (UnicodeError, ValueError):
            continue
    return values


def dns_records(target: str) -> dict[str, Any]:
    hostname, addresses = validate_hostname(target)
    records: dict[str, list[str]] = {}
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(hostname, record_type, lifetime=4)
        except dns.exception.DNSException:
            # NXDOMAIN / NoAnswer / timeout / no nameservers — the type simply
            # has no records. dnspython exposes these under dns.exception;
            # dns.resolver has no DNSException attribute in 2.x.
            records[record_type] = []
            continue
        except OSError:
            records[record_type] = []
            continue
        records[record_type] = _text_values(answers)
    return {"hostname": hostname, "addresses": addresses, "records": records}
