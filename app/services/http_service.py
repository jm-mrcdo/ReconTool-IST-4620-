from __future__ import annotations

import re

import requests

from app.config import settings


TITLE_PATTERN = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def fetch_headers_and_metadata(request_url: str) -> dict[str, object]:
    session = requests.Session()
    session.max_redirects = 1

    try:
        response = session.get(
            request_url,
            timeout=settings.http_timeout_seconds,
            allow_redirects=True,
            headers={"User-Agent": "SentinelSearch/1.0"},
        )
    except Exception:
        return {
            "url": request_url,
            "final_url": None,
            "status_code": None,
            "headers": {},
            "title": None,
            "html_excerpt": None,
        }

    title_match = TITLE_PATTERN.search(response.text[:4000])

    return {
        "url": request_url,
        "final_url": response.url,
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "title": title_match.group(1).strip() if title_match else None,
        "html_excerpt": response.text[:4000],
    }
