from __future__ import annotations

import requests


CRT_SH_URL = "https://crt.sh/"


def fetch_subdomains(domain: str) -> list[str]:
    try:
        response = requests.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=6,
            headers={"User-Agent": "SentinelSearch/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
    except Exception:
        return []

    subdomains: set[str] = set()
    for item in payload:
        name_value = str(item.get("name_value", "")).lower()
        for candidate in name_value.splitlines():
            candidate = candidate.strip().lstrip("*.") 
            if candidate.endswith(domain):
                subdomains.add(candidate)

    return sorted(subdomains)
