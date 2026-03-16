## SentinelSearch: Google-Inspired Passive Recon

SentinelSearch is a web-based tool designed for passive vulnerability discovery and defensive reconnaissance. It adapts the familiar "search engine" experience to cybersecurity education, helping users map a target’s public footprint to find hardening gaps and exposure indicators.

Instead of active scanning, it relies on passive data—DNS records, WHOIS data, certificate transparency, and HTTP headers. It then uses Gemini to translate these technical findings into professional, academic insights regarding a target's defensive posture.
Core Goals

    Search-First Workflow: A clean, Google-inspired UI for familiar interaction.

    Passive Discovery: Identifies vulnerabilities through public-facing signals.

    Educational Insights: Translates raw data into defensive lessons for students.

    Ethical Model: Focuses strictly on passive, non-intrusive assessment.

Features & Functionality

    AI Overviews: High-level summaries of a target’s security posture.

    Categorized Findings: Organized sections for DNS, WHOIS, Subdomains, Headers, and Tech stacks.

    Knowledge Panel: Quick metadata including IP, provider, registrar, and location.

    Automated Classification: Uses deterministic rules to tag findings as Informational, Low-Risk, or Hardening Opportunity.

    Academic Reporting: Export findings to Markdown for coursework or documentation.

    Local Lab: Includes three intentionally weak test sites for practice.

How Findings are Classified

Before the AI weighs in, SentinelSearch applies hardcoded rules to ensure consistency:
Trigger	Classification
Missing security headers (CSP, HSTS, etc.)	Hardening Opportunity
Wildcard CORS (*)	Hardening Opportunity
Version-disclosing server banners	Hardening Opportunity
Expired WHOIS registration	Hardening Opportunity
Near-expiry WHOIS or non-versioned banners	Low-Risk
Getting Started

1. Setup Environment
Bash

pip install -r requirements.txt
# Add your Gemini API key to a .env file

2. Launch the App
Bash

uvicorn app.main:app --reload

3. Run the Local Lab
To test against the included "vulnerable" sites, start the lab server:
Bash

py -3 -m uvicorn lab_sites:app --host 0.0.0.0 --port 8080

Then search for http://alpha.127.0.0.1.sslip.io:8080 to see a sample legacy stack disclosure.

Would you like me to help you draft the .env.example file or explain how to customize the classification rules?


Gemini is AI and can make mistakes.

# SentinelSearch: A Google-Inspired Interface for Passive Vulnerability Discovery

SentinelSearch is a web-based, Google-inspired interface for passive vulnerability discovery and defensive reconnaissance. The project was designed to adapt the familiar search-oriented interaction model of modern search engines to cybersecurity education, allowing a user to examine a target's public-facing footprint for visible weaknesses, hardening gaps, and exposure indicators.

Rather than functioning as a general-purpose search engine, SentinelSearch is specifically intended to search for vulnerabilities and security-relevant signals through strictly passive means. The system collects findings such as DNS records, WHOIS data, certificate transparency entries, HTTP security headers, and public technology indicators, then uses Gemini to generate a concise interpretation of the target's overall defensive posture in a professional academic tone.

## Project Goal

- Reproduce a clean Google-inspired user interface built around a familiar search-first workflow
- Enable users to search a target and identify passive indicators of vulnerability or weak hardening
- Translate technical reconnaissance findings into defensive insights suitable for student learning
- Maintain a passive, educational, and ethically constrained assessment model

## V1 Scope

- FastAPI backend with a single-page HTML and Tailwind frontend
- Passive modules for DNS, WHOIS, certificate transparency, HTTP headers, and basic tech fingerprinting
- Deterministic classification tags: `Informational`, `Low-Risk`, `Hardening Opportunity`
- Gemini-powered AI overview at the top of results plus defensive category summaries
- Markdown export for academic reporting

## Features

- Google-inspired landing page and search results layout
- AI-generated overview summarizing the target's visible security posture
- Category-based findings for `DNS`, `WHOIS`, `Subdomains`, `Headers`, and `Technologies`
- Knowledge panel presenting contextual metadata such as IP, provider, country, registrar, and nameservers
- Deterministic validation and classification rules applied before AI explanation
- Markdown export suitable for coursework, documentation, and academic reporting
- Local laboratory mode with three intentionally weak test sites

## Classification and Validation Rules

SentinelSearch applies deterministic application-side rules before invoking Gemini. This ensures that core classifications remain consistent, auditable, and aligned with the defensive goals of the project.

Classification rules currently include:

- Missing `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, or `Referrer-Policy` are labeled as `Hardening Opportunity`
- Wildcard `Access-Control-Allow-Origin: *` is labeled as `Hardening Opportunity`
- Version-disclosing server banners such as `Server`, `X-Powered-By`, or `X-Backend-Server` are labeled as `Hardening Opportunity`
- Non-versioned implementation banners are labeled as `Low-Risk`
- Expired WHOIS registration dates are labeled as `Hardening Opportunity`
- WHOIS registrations nearing expiration are labeled as `Low-Risk`
- Very broad certificate-transparency subdomain exposure is labeled as `Low-Risk`
- General DNS, registrar, nameserver, and technology observations remain `Informational` unless a stronger rule applies

Validation rules currently include:

- Only `http://` and `https://` targets are accepted
- Raw IP addresses are rejected
- `localhost` and reserved-only internal suffixes are rejected
- Embedded credentials and URL fragments are rejected
- A fully qualified hostname is required
- Lab hosts such as `*.sslip.io` remain allowed for controlled testing

## Project Structure

```text
app/
  main.py
  config.py
  models.py
  services/
  templates/
  utils/
requirements.txt
.env.example
```

## Run Locally

1. Create a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Optional: create a `.env` file from `.env.example` and add your Gemini API key.
4. Start the app:

```bash
uvicorn app.main:app --reload
```

5. Open `http://127.0.0.1:8000`

## Sharing and Reproducibility

This project can be shared on GitHub without uploading local or machine-specific files. Other users will still be able to run the application as long as the core source files and dependency list are included in the repository.

Files that should be included in the repository:

- `app/`
- `lab_sites.py`
- `README.md`
- `requirements.txt`
- `.env.example`
- `.gitignore`

Files that should not be uploaded:

- `.env`
- `.venv/`
- `__pycache__/`

These excluded files are not required for reproducibility:

- `.env` contains local secrets such as API keys
- `.venv/` is a machine-specific Python virtual environment
- `__pycache__/` contains automatically generated Python cache files

To run the project after cloning the repository, another user can install the dependencies and create a local environment file:

```bash
py -3 -m pip install -r requirements.txt
copy .env.example .env
```

After that, the user can place their own Gemini API key in `.env` and start the application:

```bash
py -3 -m uvicorn app.main:app --reload
```

If no Gemini API key is provided, the application can still run, but it will use fallback summary text instead of live AI-generated summaries.

## Why This Project Exists

SentinelSearch was developed to make passive reconnaissance more understandable in an academic environment. Many security tools present fragmented outputs or assume a high level of prior experience, which can create barriers for early learners. This project addresses that problem by presenting vulnerability-relevant findings in a format that is intentionally familiar, structured, and accessible. The Google-inspired interface is a deliberate design choice intended to reduce interface complexity while preserving a focus on defensive analysis rather than offensive exploitation.

## Local Lab Sites

You can also run three intentionally weak local sites for passive testing with SentinelSearch.

Start the lab server:

```bash
py -3 -m uvicorn lab_sites:app --host 0.0.0.0 --port 8080
```

Then use these addresses in SentinelSearch:

- `http://alpha.127.0.0.1.sslip.io:8080`
- `http://beta.127.0.0.1.sslip.io:8080`
- `http://gamma.127.0.0.1.sslip.io:8080`

Each host intentionally exposes a different passive hardening issue profile:

- `alpha`: severe legacy stack disclosure, wildcard CORS, outdated technologies, and missing core headers
- `beta`: permissive cross-origin behavior, unstable `503` response, and multiple exposed implementation banners
- `gamma`: stronger transport settings with remaining CSP, clickjacking, and banner disclosure concerns


## Screenshots

<img width="2009" height="1328" alt="image" src="https://github.com/user-attachments/assets/fd5b9a37-c0f3-45df-9c22-0ebe1dd85cd8" />

<img width="2009" height="1323" alt="image" src="https://github.com/user-attachments/assets/dea6b40b-d175-4af1-8c46-a31d3b30095b" />

<img width="2009" height="1267" alt="image" src="https://github.com/user-attachments/assets/d7127413-ea63-45af-9b1f-3802be3feafa" />

README.md
Displaying README.md.
