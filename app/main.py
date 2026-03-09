from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

from app.models import CategoryResult, Finding, KnowledgePanel, SearchRequest, SearchResponse
from app.services.ai_service import summarize_category, summarize_overall_target
from app.services.classifier import (
    SECURITY_HEADERS,
    classify_banner,
    classify_dns_record,
    classify_generic,
    classify_header,
    classify_http_status,
    classify_subdomains,
    classify_technology,
    classify_whois_field,
)
from app.services.ct_service import fetch_subdomains
from app.services.dns_service import query_dns
from app.services.enrichment_service import lookup_ip_context
from app.services.fingerprint_service import detect_technologies
from app.services.http_service import fetch_headers_and_metadata
from app.services.report_service import build_markdown_report
from app.services.whois_service import lookup_whois
from app.utils.domain import ReconTarget, validate_recon_target


app = FastAPI(title="SentinelSearch", version="1.0.0")
templates = Jinja2Templates(directory="app/templates")

DISCLAIMER = (
    "SentinelSearch is designed for educational use and authorized defensive assessments only. "
    "It performs passive reconnaissance and avoids exploit guidance, brute-forcing, directory "
    "busting, and port scanning."
)


def _fallback_finding(title: str, source: str, message: str) -> Finding:
    classification, insight = classify_generic(title)
    return Finding(
        title=title,
        value=message,
        classification=classification,
        defensive_insight=insight,
        source=source,
    )


def _build_dns_category(dns_records: dict[str, list[str]]) -> CategoryResult:
    findings: list[Finding] = []
    facts: list[str] = []

    for record_type, values in dns_records.items():
        if values:
            classification, insight = classify_dns_record(record_type, values)
            findings.append(
                Finding(
                    title=f"{record_type} Records",
                    value=", ".join(values[:10]),
                    classification=classification,
                    defensive_insight=insight,
                    source="DNS",
                )
            )
            facts.append(f"{record_type}: {', '.join(values[:5])}")

    if not findings:
        findings.append(_fallback_finding("DNS Records", "DNS", "No records were returned."))
        facts.append("No DNS records were returned.")

    return CategoryResult(
        name="DNS",
        summary=summarize_category("DNS", facts),
        findings=findings,
    )


def _build_whois_category(whois_data: dict[str, object]) -> CategoryResult:
    findings: list[Finding] = []
    facts: list[str] = []

    field_map = {
        "registrar": "Registrar",
        "creation_date": "Creation Date",
        "updated_date": "Updated Date",
        "expiration_date": "Expiration Date",
    }

    for key, label in field_map.items():
        value = whois_data.get(key)
        if value:
            classification, insight = classify_whois_field(key, value)
            findings.append(
                Finding(
                    title=label,
                    value=str(value),
                    classification=classification,
                    defensive_insight=insight,
                    source="WHOIS",
                )
            )
            facts.append(f"{label}: {value}")

    if not findings:
        findings.append(_fallback_finding("WHOIS", "WHOIS", "WHOIS details were unavailable."))
        facts.append("WHOIS details were unavailable.")

    return CategoryResult(
        name="WHOIS",
        summary=summarize_category("WHOIS", facts),
        findings=findings,
    )


def _build_ct_category(subdomains: list[str]) -> CategoryResult:
    if subdomains:
        classification, defensive_insight = classify_subdomains(len(subdomains))
        findings = [
            Finding(
                title="Observed Subdomains",
                value=", ".join(subdomains[:20]),
                classification=classification,
                defensive_insight=defensive_insight,
                source="crt.sh",
            )
        ]
        facts = [f"Observed {len(subdomains)} subdomains in certificate transparency logs."]
    else:
        findings = [
            _fallback_finding(
                "Observed Subdomains",
                "crt.sh",
                "No certificate transparency subdomains were returned.",
            )
        ]
        facts = ["No certificate transparency subdomains were returned."]

    return CategoryResult(
        name="Subdomains",
        summary=summarize_category("Certificate Transparency", facts),
        findings=findings,
    )


def _build_headers_category(http_data: dict[str, object]) -> CategoryResult:
    headers = {str(key).lower(): str(value) for key, value in (http_data.get("headers") or {}).items()}
    findings: list[Finding] = []
    facts: list[str] = []

    for header_name, (short_name, _) in SECURITY_HEADERS.items():
        present = header_name in headers
        classification, insight = classify_header(header_name, present)
        findings.append(
            Finding(
                title=short_name,
                value=headers.get(header_name, "Missing"),
                classification=classification,
                defensive_insight=insight,
                source="HTTP GET",
            )
        )
        facts.append(f"{short_name}: {'present' if present else 'missing'}")

    status_code = http_data.get("status_code")
    if status_code:
        classification, defensive_insight = classify_http_status(int(status_code))
        findings.append(
            Finding(
                title="HTTP Status",
                value=str(status_code),
                classification=classification,
                defensive_insight=defensive_insight,
                source="HTTP GET",
            )
        )
        facts.append(f"HTTP status code was {status_code}.")

    for banner_name in ("server", "x-powered-by", "x-backend-server", "access-control-allow-origin"):
        banner_value = headers.get(banner_name)
        if banner_value:
            classification, defensive_insight = classify_banner(banner_name, banner_value)
            findings.append(
                Finding(
                    title="-".join(part.capitalize() for part in banner_name.split("-")),
                    value=banner_value,
                    classification=classification,
                    defensive_insight=defensive_insight,
                    source="HTTP GET",
                )
            )
            facts.append(f"{banner_name}: {banner_value} ({classification})")

    return CategoryResult(
        name="Headers",
        summary=summarize_category("HTTP Headers", facts),
        findings=findings,
    )


def _build_tech_category(technologies: list[str]) -> CategoryResult:
    if technologies:
        findings = []
        for technology in technologies:
            classification, defensive_insight = classify_technology(technology)
            findings.append(
                Finding(
                    title=technology,
                    value=technology,
                    classification=classification,
                    defensive_insight=defensive_insight,
                    source="HTTP Metadata",
                )
            )
        facts = [f"Detected technologies: {', '.join(technologies)}"]
    else:
        findings = [
            _fallback_finding(
                "Detected Technologies",
                "HTTP Metadata",
                "No obvious technologies were detected from public metadata.",
            )
        ]
        facts = ["No obvious technologies were detected from public metadata."]

    return CategoryResult(
        name="Technologies",
        summary=summarize_category("Technology Fingerprinting", facts),
        findings=findings,
    )


def build_search_response(target: ReconTarget) -> SearchResponse:
    dns_records = query_dns(target.hostname)
    whois_data = lookup_whois(target.hostname)
    http_data = fetch_headers_and_metadata(target.request_url)
    subdomains = fetch_subdomains(target.hostname)
    technologies = detect_technologies(
        headers=http_data.get("headers", {}),
        html_excerpt=http_data.get("html_excerpt"),
    )

    resolved_ip = dns_records.get("A", [None])[0] if dns_records.get("A") else None
    ip_context = lookup_ip_context(resolved_ip)
    nameservers = dns_records.get("NS") or whois_data.get("name_servers") or []

    categories = [
        _build_dns_category(dns_records),
        _build_whois_category(whois_data),
        _build_ct_category(subdomains),
        _build_headers_category(http_data),
        _build_tech_category(technologies),
    ]
    all_findings = [finding for category in categories for finding in category.findings]
    hardening_count = sum(
        1 for finding in all_findings if finding.classification == "Hardening Opportunity"
    )
    overall_facts = [
        f"Resolved IP: {resolved_ip or 'Unavailable'}",
        f"Registrar: {whois_data.get('registrar') or 'Unavailable'}",
        (
            "Nameservers: "
            + (", ".join(nameservers[:4]) if nameservers else "Unavailable")
        ),
        (
            "Observed technologies: "
            + (", ".join(technologies) if technologies else "No obvious technologies detected")
        ),
        (
            "Certificate transparency subdomains: "
            + (str(len(subdomains)) if subdomains else "0")
        ),
    ]
    for category in categories:
        overall_facts.append(f"{category.name} summary: {category.summary}")
    for finding in all_findings[:8]:
        overall_facts.append(
            f"{finding.title}: {finding.value} ({finding.classification})"
        )
    overall_summary = summarize_overall_target(
        target=target.hostname,
        facts=overall_facts,
        hardening_count=hardening_count,
    )

    return SearchResponse(
        target=target.request_url,
        overall_summary=overall_summary,
        knowledge_panel=KnowledgePanel(
            domain=target.hostname,
            resolved_ip=resolved_ip,
            provider=ip_context.get("provider"),
            country=ip_context.get("country"),
            registrar=whois_data.get("registrar"),
            nameservers=list(nameservers),
        ),
        categories=categories,
        disclaimer=DISCLAIMER,
        raw={
            "dns": dns_records,
            "whois": whois_data,
            "http": {
                "url": http_data.get("url"),
                "final_url": http_data.get("final_url"),
                "status_code": http_data.get("status_code"),
                "headers": http_data.get("headers"),
            },
            "subdomains": subdomains,
            "technologies": technologies,
        },
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/api/search", response_model=SearchResponse)
def search(payload: SearchRequest) -> SearchResponse:
    if not payload.authorized:
        raise HTTPException(
            status_code=400,
            detail="You must confirm you are authorized to assess this target.",
        )

    try:
        target = validate_recon_target(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return build_search_response(target)


@app.post("/api/export/markdown", response_class=PlainTextResponse)
def export_markdown(result: SearchResponse) -> PlainTextResponse:
    markdown = build_markdown_report(result)
    headers = {"Content-Disposition": 'attachment; filename="sentinelsearch-report.md"'}
    return PlainTextResponse(content=markdown, headers=headers, media_type="text/markdown")
