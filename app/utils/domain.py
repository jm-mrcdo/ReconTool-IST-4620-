import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


DOMAIN_PATTERN = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+\.?$"
)
BLOCKED_SUFFIXES = (".local", ".internal", ".example", ".invalid", ".test")
LAB_SUFFIX = ".sslip.io"


@dataclass
class ReconTarget:
    hostname: str
    request_url: str
    original_input: str


def validate_recon_target(value: str) -> ReconTarget:
    raw_value = value.strip()
    if not raw_value:
        raise ValueError("Enter a valid public domain or lab URL.")

    parsed = urlparse(raw_value if "://" in raw_value else f"https://{raw_value}")
    hostname = (parsed.hostname or "").strip(".").lower()

    if hostname in {"localhost", ""}:
        raise ValueError("Enter a valid public domain or lab URL.")

    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// targets are supported.")
    if parsed.username or parsed.password:
        raise ValueError("Embedded credentials are not allowed in target URLs.")
    if parsed.fragment:
        raise ValueError("URL fragments are not supported for target validation.")
    if len(hostname) > 253:
        raise ValueError("The target hostname is too long.")

    try:
        ipaddress.ip_address(hostname)
        raise ValueError(
            "Raw IP addresses are not allowed. Use a domain or a lab hostname such as "
            "`alpha.127.0.0.1.sslip.io`."
        )
    except ValueError as exc:
        if "Raw IP addresses" in str(exc):
            raise

    if not DOMAIN_PATTERN.match(hostname):
        raise ValueError("Enter a valid public domain or lab URL.")
    if hostname.endswith(BLOCKED_SUFFIXES) and not hostname.endswith(LAB_SUFFIX):
        raise ValueError("Internal or reserved-only hostnames are not allowed.")
    if "." not in hostname:
        raise ValueError("Enter a fully qualified public domain or lab hostname.")

    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("Port values must be between 1 and 65535.") from exc

    if parsed_port is not None and not (1 <= parsed_port <= 65535):
        raise ValueError("Port values must be between 1 and 65535.")

    port = f":{parsed_port}" if parsed_port else ""
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    request_url = f"{parsed.scheme or 'https'}://{hostname}{port}{path}{query}"

    return ReconTarget(
        hostname=hostname,
        request_url=request_url,
        original_input=raw_value,
    )
