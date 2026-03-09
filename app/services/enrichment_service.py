from __future__ import annotations

import requests


def lookup_ip_context(ip_address: str | None) -> dict[str, str | None]:
    if not ip_address:
        return {"provider": None, "country": None}

    try:
        response = requests.get(
            f"https://ipapi.co/{ip_address}/json/",
            timeout=4,
            headers={"User-Agent": "SentinelSearch/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
    except Exception:
        return {"provider": None, "country": None}

    return {
        "provider": payload.get("org"),
        "country": payload.get("country_name"),
    }
