## SentinelSearch: Passive Recon for Education

SentinelSearch is a web tool built to make passive vulnerability discovery feel as familiar as a Google search. It’s designed for cybersecurity students and researchers to map out a target's public footprint—things like DNS records, WHOIS data, and HTTP headers—without ever touching the target's actual infrastructure.

The goal was to move away from the clunky, fragmented output of traditional security tools and create something structured, readable, and focused on defensive hardening.

What it does:

   Google-Style Search: A simple, familiar interface for reconnaissance.

   Passive Modules: Pulls data from DNS, WHOIS, certificate transparency logs, and technology fingerprints.

   AI Summaries: Uses Gemini to turn technical data into a professional overview of a site's security posture.

   Automatic Tagging: Findings are labeled as Informational, Low-Risk, or Hardening Opportunity based on built-in rules.

   Markdown Export: Generate reports instantly for academic or professional documentation.

   Built-in Lab: Includes three intentionally weak sites (alpha, beta, and gamma) to practice on locally.

## Quick Start

   Install dependencies:
   Setup your environment: (Create a .env file to add your API key for AI feature)
   Run The App


## Why I built this

Most security tools assume you already know exactly what you're looking for. SentinelSearch lowers that barrier by presenting findings in a clean layout with AI-generated context, helping learners understand why a missing security header or an exposed server banner actually matters.        


## Screenshots

<img width="2009" height="1328" alt="image" src="https://github.com/user-attachments/assets/fd5b9a37-c0f3-45df-9c22-0ebe1dd85cd8" />

<img width="2009" height="1323" alt="image" src="https://github.com/user-attachments/assets/dea6b40b-d175-4af1-8c46-a31d3b30095b" />

<img width="2009" height="1267" alt="image" src="https://github.com/user-attachments/assets/d7127413-ea63-45af-9b1f-3802be3feafa" />

