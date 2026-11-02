from __future__ import annotations

from typing import Any

import dns.resolver

from app.modules.web.validators import validate_hostname


def dns_records(target: str) -> dict[str, Any]:
    hostname, addresses = validate_hostname(target)
    records: dict[str, list[str]] = {}
    for record_type in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            answers = dns.resolver.resolve(hostname, record_type, lifetime=4)
            records[record_type] = [answer.to_text() for answer in answers]
        except dns.resolver.DNSException:
            records[record_type] = []
    return {"hostname": hostname, "addresses": addresses, "records": records}
