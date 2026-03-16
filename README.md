## SentinelSearch: Google-Inspired Passive Recon

SentinelSearch is a web-based tool designed for passive vulnerability discovery and defensive reconnaissance. It adapts the familiar "search engine" experience to cybersecurity education, helping users map a target’s public footprint to find hardening gaps and exposure indicators.

Instead of active scanning, it relies on passive data—DNS records, WHOIS data, certificate transparency, and HTTP headers. It then uses Gemini to translate these technical findings into professional, academic insights regarding a target's defensive posture.
Core Goals

    Search-First Workflow: A clean, Google-inspired UI for familiar interaction.

    Passive Discovery: Identifies vulnerabilities through public-facing signals.

    Educational Insights: Translates raw data into defensive lessons for students.

    Ethical Model: Focuses strictly on passive, non-intrusive assessment.

## Features & Functionality

    AI Overviews: High-level summaries of a target’s security posture.

    Categorized Findings: Organized sections for DNS, WHOIS, Subdomains, Headers, and Tech stacks.

    Knowledge Panel: Quick metadata including IP, provider, registrar, and location.

    Automated Classification: Uses deterministic rules to tag findings as Informational, Low-Risk, or Hardening Opportunity.

    Academic Reporting: Export findings to Markdown for coursework or documentation.

    Local Lab: Includes three intentionally weak test sites for practice.
    

## Getting Started

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

## Screenshots
<img width="2009" height="1328" alt="image" src="https://github.com/user-attachments/assets/fd5b9a37-c0f3-45df-9c22-0ebe1dd85cd8" />

<img width="2009" height="1323" alt="image" src="https://github.com/user-attachments/assets/dea6b40b-d175-4af1-8c46-a31d3b30095b" />

<img width="2009" height="1267" alt="image" src="https://github.com/user-attachments/assets/d7127413-ea63-45af-9b1f-3802be3feafa" />

