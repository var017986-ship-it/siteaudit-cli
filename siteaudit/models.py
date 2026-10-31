from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def redact_url(url: str) -> str:
    """Keep query parameter names in reports but never persist their values."""
    try:
        parts = urlsplit(url)
        query = urlencode([(key, "[redacted]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
    except ValueError:
        return "<invalid-url>"


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    severity: str
    confidence: str
    url: str
    evidence: str
    recommendation: str
    category: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        finding = asdict(self)
        finding["url"] = redact_url(self.url)
        finding["references"] = [redact_url(reference) for reference in self.references]
        return finding
