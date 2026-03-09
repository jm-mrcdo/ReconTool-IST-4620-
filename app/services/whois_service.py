from __future__ import annotations

from datetime import datetime

import whois


def _normalize_date(value: object) -> str | None:
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, datetime):
        return value.isoformat()
    if value:
        return str(value)
    return None


def lookup_whois(domain: str) -> dict[str, object]:
    try:
        record = whois.whois(domain)
    except Exception:
        return {}

    registrar = record.get("registrar")
    nameservers = record.get("name_servers") or []
    if isinstance(nameservers, str):
        nameservers = [nameservers]

    return {
        "registrar": registrar,
        "creation_date": _normalize_date(record.get("creation_date")),
        "updated_date": _normalize_date(record.get("updated_date")),
        "expiration_date": _normalize_date(record.get("expiration_date")),
        "name_servers": sorted({str(item).lower() for item in nameservers if item}),
    }
