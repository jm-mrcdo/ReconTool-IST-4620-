from __future__ import annotations


TECH_SIGNATURES = {
    "react": "React",
    "next.js": "Next.js",
    "nginx": "Nginx",
    "apache": "Apache",
    "php": "PHP",
    "cloudflare": "Cloudflare",
    "wordpress": "WordPress",
    "express": "Express",
    "jquery": "jQuery",
    "socket.io": "Socket.IO",
    "node/": "Node.js",
}


def detect_technologies(headers: dict[str, str], html_excerpt: str | None) -> list[str]:
    haystack_parts = [
        " ".join(f"{key}: {value}" for key, value in headers.items()).lower(),
        (html_excerpt or "").lower(),
    ]
    haystack = " ".join(haystack_parts)

    detected = [label for needle, label in TECH_SIGNATURES.items() if needle in haystack]
    return sorted(set(detected))
