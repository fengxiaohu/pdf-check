from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TextFragment:
    text: str
    location_type: str
    page: int | None = None
    object_id: int | None = None
    source: str | None = None


@dataclass
class Finding:
    category: str
    severity: str
    location_type: str
    page: int | None
    object_id: int | None
    evidence: str
    matched_rules: list[str] = field(default_factory=list)
    confidence: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "severity": self.severity,
            "location_type": self.location_type,
            "page": self.page,
            "object_id": self.object_id,
            "evidence": self.evidence,
            "matched_rules": self.matched_rules,
            "confidence": self.confidence,
        }

