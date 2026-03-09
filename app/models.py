from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SearchRequest(BaseModel):
    domain: str
    authorized: bool = Field(
        ...,
        description="User affirms they have authorization to assess this target.",
    )


class Finding(BaseModel):
    title: str
    value: str
    classification: str
    defensive_insight: str
    source: str


class CategoryResult(BaseModel):
    name: str
    summary: str
    findings: list[Finding]


class KnowledgePanel(BaseModel):
    domain: str
    resolved_ip: str | None = None
    provider: str | None = None
    country: str | None = None
    registrar: str | None = None
    nameservers: list[str] = Field(default_factory=list)


class SearchResponse(BaseModel):
    target: str
    overall_summary: str
    knowledge_panel: KnowledgePanel
    categories: list[CategoryResult]
    disclaimer: str
    raw: dict[str, Any]
