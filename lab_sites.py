from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse


app = FastAPI(title="SentinelSearch Lab Sites")

LAB_SITES = {
    "alpha.127.0.0.1.sslip.io": {
        "title": "Alpha Benefits Portal",
        "subtitle": "Legacy HR self-service portal",
        "status_code": 200,
        "headers": {
            "Server": "Apache/2.4.49",
            "X-Powered-By": "PHP/5.6.40",
            "X-Backend-Server": "Ubuntu/18.04",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        "html": """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="generator" content="WordPress 5.4">
            <title>Alpha Benefits Portal</title>
            <script src="/assets/jquery-1.12.4.min.js"></script>
        </head>
        <body style="font-family: Arial, sans-serif; padding: 40px;">
            <h1>Alpha Benefits Portal</h1>
            <p>Legacy employee self-service for payroll and benefits management.</p>
            <!-- Legacy admin route retained for migration testing: /legacy-admin -->
            <!-- Backup archive historically exposed at /backup/payroll-2023.zip -->
            <p>Status: Operational</p>
        </body>
        </html>
        """,
        "vulnerability_note": "Severe legacy stack disclosure, wildcard CORS, and missing core security headers.",
    },
    "beta.127.0.0.1.sslip.io": {
        "title": "Beta Support Desk",
        "subtitle": "Single-page customer support dashboard",
        "status_code": 503,
        "headers": {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "Express/4.17.1",
            "X-Backend-Server": "Node/14.21.3",
            "X-Frame-Options": "SAMEORIGIN",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Referrer-Policy": "unsafe-url",
        },
        "html": """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Beta Support Desk</title>
            <script>window.__APP_FRAMEWORK__ = "react";</script>
            <script src="/static/socket.io.js"></script>
        </head>
        <body style="font-family: Arial, sans-serif; padding: 40px;">
            <h1>Beta Support Desk</h1>
            <p>Customer queue dashboard built with React.</p>
            <p>Public assets are served by an nginx edge cache.</p>
            <p>Current state: degraded service due to upstream exception handling faults.</p>
        </body>
        </html>
        """,
        "vulnerability_note": "Permissive cross-origin behavior, implementation disclosure, and unstable server response.",
    },
    "gamma.127.0.0.1.sslip.io": {
        "title": "Gamma Investor Portal",
        "subtitle": "Modern investor relations microsite",
        "status_code": 200,
        "headers": {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Server": "cloudflare",
            "X-Powered-By": "Next.js/12.3.1",
            "X-Backend-Server": "Node/16.14.0",
            "Access-Control-Allow-Origin": "https://staging.partner.example.com",
        },
        "html": """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="generator" content="Next.js 12">
            <title>Gamma Investor Portal</title>
        </head>
        <body style="font-family: Arial, sans-serif; padding: 40px;">
            <h1>Gamma Investor Portal</h1>
            <p>Static investor content with a lightweight Next.js frontend.</p>
            <script src="/_next/static/chunks/app.js"></script>
            <!-- Staging deployment was mirrored during the last release window -->
        </body>
        </html>
        """,
        "vulnerability_note": "Mixed posture with stronger transport controls but remaining disclosure and browser hardening gaps.",
    },
}

DEFAULT_HOST = "alpha.127.0.0.1.sslip.io"


def get_site_config(host_header: str) -> dict[str, object]:
    hostname = host_header.split(":", maxsplit=1)[0].lower()
    return LAB_SITES.get(hostname, LAB_SITES[DEFAULT_HOST])


@app.get("/", response_class=HTMLResponse)
def serve_home(request: Request) -> HTMLResponse:
    site = get_site_config(request.headers.get("host", ""))
    response = HTMLResponse(site["html"], status_code=site.get("status_code", 200))
    for header_name, header_value in site["headers"].items():
        response.headers[header_name] = header_value
    response.headers["X-Lab-Vulnerability-Note"] = site["vulnerability_note"]
    return response
