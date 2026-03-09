from __future__ import annotations

import requests

from app.config import settings


SYSTEM_PROMPT = """
You are SentinelSearch, a defensive security tutor.
Explain findings in a professional, academic, non-aggressive tone.
Do not provide payloads, exploit instructions, bypass methods, or offensive steps.
Return a concise paragraph focused on hardening value only.
""".strip()


def _call_gemini(prompt: str, fallback: str, max_output_tokens: int = 180) -> str:
    if not settings.gemini_api_key or settings.ai_provider.lower() != "gemini":
        return fallback

    try:
        response = requests.post(
            (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                f"{settings.gemini_model}:generateContent"
            ),
            params={"key": settings.gemini_api_key},
            headers={"Content-Type": "application/json"},
            json={
                "contents": [
                    {
                        "role": "user",
                        "parts": [{"text": prompt}],
                    }
                ],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": max_output_tokens,
                },
            },
            timeout=12,
        )
        response.raise_for_status()
        payload = response.json()
        content = payload["candidates"][0]["content"]["parts"][0]["text"].strip()
        return content or fallback
    except Exception:
        return fallback


def summarize_category(category: str, facts: list[str]) -> str:
    safe_fallback = (
        f"{category} findings were collected passively to help a defender understand "
        "public exposure, validate configuration choices, and prioritize hardening work."
    )
    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Category: {category}\n"
        f"Facts:\n- " + "\n- ".join(facts) + "\n\n"
        "Write a short defensive summary."
    )
    return _call_gemini(prompt, safe_fallback, max_output_tokens=180)


def summarize_overall_target(target: str, facts: list[str], hardening_count: int) -> str:
    if hardening_count >= 4:
        posture = "currently shows several visible hardening gaps."
    elif hardening_count >= 2:
        posture = "shows a mixed security posture with some clear improvement areas."
    else:
        posture = "appears relatively stronger from this limited passive snapshot, though gaps may still remain."

    safe_fallback = (
        f"This passive review suggests `{target}` {posture} The summary is based on public records, "
        "observed headers, certificate transparency data, and exposed technology indicators rather "
        "than intrusive testing."
    )
    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"Target: {target}\n"
        f"Observed facts:\n- " + "\n- ".join(facts) + "\n\n"
        "Write a short AI overview that appears before search results. Summarize the target's "
        "overall defensive health, mention the most important hardening themes, and stay concise."
    )
    return _call_gemini(prompt, safe_fallback, max_output_tokens=220)
