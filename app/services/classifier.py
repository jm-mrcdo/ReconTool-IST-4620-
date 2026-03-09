from __future__ import annotations

from datetime import datetime, timezone


SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS",
        "Tells browsers to enforce HTTPS for future visits.",
    ),
    "content-security-policy": (
        "CSP",
        "Reduces script injection and content loading risks.",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "Helps prevent clickjacking in framed contexts.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Prevents some MIME-type sniffing behavior.",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "Limits how much referrer information is shared.",
    ),
}


def _parse_date(value: object) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)

    text = str(value).strip()
    for candidate in (text.replace("Z", "+00:00"), text):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def classify_header(header_name: str, present: bool) -> tuple[str, str]:
    short_name, meaning = SECURITY_HEADERS[header_name]
    if present:
        return (
            "Informational",
            f"{short_name} is present. {meaning}",
        )
    return (
        "Hardening Opportunity",
        f"{short_name} is missing. {meaning} Review whether this header should be enabled.",
    )


def classify_generic(title: str) -> tuple[str, str]:
    return (
        "Informational",
        f"{title} contributes to public attack-surface awareness and documentation.",
    )


def classify_dns_record(record_type: str, values: list[str]) -> tuple[str, str]:
    if record_type == "MX":
        return (
            "Informational",
            "Mail exchange records confirm external email handling and should be reviewed as part of domain exposure inventory.",
        )
    if record_type == "TXT":
        return (
            "Informational",
            "TXT records often reveal mail policy, verification data, or service ownership details useful for defensive documentation.",
        )
    if record_type == "NS":
        return (
            "Informational",
            "Nameserver records identify delegated infrastructure and help defenders verify external dependencies.",
        )
    return (
        "Informational",
        "Address records identify publicly reachable infrastructure and should align with known asset ownership.",
    )


def classify_whois_field(field_name: str, value: object) -> tuple[str, str]:
    if field_name == "expiration_date":
        expires_at = _parse_date(value)
        if expires_at:
            remaining_days = (expires_at - datetime.now(timezone.utc)).days
            if remaining_days < 0:
                return (
                    "Hardening Opportunity",
                    "The registration appears expired, which can create operational and ownership risk if not addressed promptly.",
                )
            if remaining_days <= 30:
                return (
                    "Low-Risk",
                    "The registration is approaching expiration and should be monitored to avoid service disruption or ownership issues.",
                )
        return classify_generic("Expiration Date")

    if field_name == "updated_date":
        return (
            "Informational",
            "Registration update metadata helps validate whether ownership records appear maintained.",
        )

    if field_name == "creation_date":
        return (
            "Informational",
            "Creation date context can help correlate asset age with maintenance expectations.",
        )

    return (
        "Informational",
        "Registrar ownership data supports asset inventory and accountability review.",
    )


def classify_subdomains(count: int) -> tuple[str, str]:
    if count >= 15:
        return (
            "Low-Risk",
            "A larger number of observed subdomains may indicate broader externally visible attack surface that should be inventoried and reviewed.",
        )
    return (
        "Informational",
        "Observed subdomains help defenders identify public-facing assets that may require ownership review and hardening.",
    )


def classify_http_status(status_code: int) -> tuple[str, str]:
    if status_code >= 500:
        return (
            "Low-Risk",
            "A server-side error can indicate unstable configuration or error handling that warrants review.",
        )
    if status_code in {401, 403}:
        return (
            "Informational",
            "The endpoint is reachable but access-controlled, which is useful for external exposure mapping.",
        )
    if status_code >= 400:
        return (
            "Informational",
            "The endpoint returned a client error response, which still confirms externally visible behavior.",
        )
    return (
        "Informational",
        "A single response snapshot helps verify reachability without intrusive interaction.",
    )


def classify_banner(header_name: str, value: str) -> tuple[str, str]:
    normalized_name = header_name.lower()
    has_version = any(character.isdigit() for character in value)

    if normalized_name == "access-control-allow-origin" and value.strip() == "*":
        return (
            "Hardening Opportunity",
            "A wildcard cross-origin policy can be broader than necessary and should be reviewed against intended browser access requirements.",
        )

    if normalized_name in {"server", "x-powered-by", "x-backend-server"}:
        if has_version:
            return (
                "Hardening Opportunity",
                "Server banner disclosure includes version information that can aid external profiling and may be unnecessary to expose.",
            )
        return (
            "Low-Risk",
            "Server banner disclosure reveals implementation details that may be useful for asset profiling.",
        )

    return (
        "Informational",
        "This header provides externally visible metadata that can support defensive inventory and configuration review.",
    )


def classify_technology(technology: str) -> tuple[str, str]:
    normalized = technology.lower()
    if normalized in {"wordpress", "php"}:
        return (
            "Low-Risk",
            "Common web platforms increase the importance of patching discipline and plugin or module governance.",
        )
    return (
        "Informational",
        "Technology identification helps defenders validate patch coverage and ownership of public-facing components.",
    )
