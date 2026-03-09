from __future__ import annotations

from dns import exception, resolver


RECORD_TYPES = ("A", "MX", "TXT", "NS")


def query_dns(domain: str) -> dict[str, list[str]]:
    results: dict[str, list[str]] = {}

    for record_type in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, record_type, lifetime=4)
            values = sorted({str(answer).strip() for answer in answers})
            results[record_type] = values
        except (
            resolver.NoAnswer,
            resolver.NXDOMAIN,
            resolver.NoNameservers,
            resolver.LifetimeTimeout,
            exception.DNSException,
        ):
            results[record_type] = []

    return results
