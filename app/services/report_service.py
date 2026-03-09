from __future__ import annotations

from app.models import SearchResponse


def build_markdown_report(result: SearchResponse) -> str:
    lines = [
        "# SentinelSearch Report",
        "",
        f"**Target:** `{result.target}`",
        "",
        "## AI Overview",
        "",
        result.overall_summary,
        "",
        "## Knowledge Panel",
        f"- Resolved IP: {result.knowledge_panel.resolved_ip or 'Unavailable'}",
        f"- Provider: {result.knowledge_panel.provider or 'Unavailable'}",
        f"- Country: {result.knowledge_panel.country or 'Unavailable'}",
        f"- Registrar: {result.knowledge_panel.registrar or 'Unavailable'}",
        f"- Nameservers: {', '.join(result.knowledge_panel.nameservers) or 'Unavailable'}",
        "",
    ]

    for category in result.categories:
        lines.extend(
            [
                f"## {category.name}",
                "",
                category.summary,
                "",
            ]
        )
        for finding in category.findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    f"- Value: {finding.value}",
                    f"- Classification: {finding.classification}",
                    f"- Defensive Insight: {finding.defensive_insight}",
                    f"- Source: {finding.source}",
                    "",
                ]
            )

    lines.extend(["## Disclaimer", "", result.disclaimer, ""])
    return "\n".join(lines)
