"""Normalized domain models, exit codes, and secret redaction utilities."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

REDACTED_PLACEHOLDER = "[REDACTED]"

_SEVERITY_RANK: dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class Severity(StrEnum):
    """Normalized finding severity."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Return numeric rank for ordering and threshold comparisons."""
        return _SEVERITY_RANK[self.value]

    def meets_threshold(self, threshold: Severity) -> bool:
        """Return True if this severity is at least as severe as ``threshold``."""
        return self.rank >= threshold.rank


class FindingCategory(StrEnum):
    """High-level security finding classification."""

    SECRET = "SECRET"  # noqa: S105
    INJECTION = "INJECTION"
    COMPLIANCE = "COMPLIANCE"
    OTHER = "OTHER"


class ValidationStatus(StrEnum):
    """Credential live-validation state."""

    VERIFIED_ACTIVE = "VERIFIED_ACTIVE"
    VERIFIED_INACTIVE = "VERIFIED_INACTIVE"
    ASSUMED = "ASSUMED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"


class PluginStatus(StrEnum):
    """Execution status of an individual scanner plugin."""

    PASSED = "PASSED"
    FINDINGS = "FINDINGS"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class GateStatus(StrEnum):
    """Final compliance gate decision."""

    PASS = "PASS"  # noqa: S105
    WARN = "WARN"
    BLOCK = "BLOCK"


class EnforcementMode(StrEnum):
    """Gate policy enforcement mode."""

    ENFORCE = "enforce"
    WARN = "warn"


class ExecutionMode(StrEnum):
    """Orchestrator plugin scheduling strategy."""

    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"


class ExitCode(IntEnum):
    """Standardized CI exit codes."""

    PASS = 0
    BLOCK = 1
    WARN = 10


_URI_CREDENTIAL_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@")
_KNOWN_TOKEN_RE = re.compile(
    r"\b("
    r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{12,}"
    r"|github_pat_[A-Za-z0-9_]{16,}"
    r"|glpat-[A-Za-z0-9_-]{12,}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|sk_(?:live|test)_[A-Za-z0-9]{12,}"
    r"|sk-[A-Za-z0-9_-]{16,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"
    r"|AIza[0-9A-Za-z_-]{20,}"
    r"|ya29\.[0-9A-Za-z_-]{20,}"
    r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"
    r"|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r")\b"
)
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"
)
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|token|api_?key|access_?key|private_?key|"
    r"client_?secret|auth_?token|bearer)\b\s*[:=]\s*['\"]?)([^'\"\s,;}{]+)(['\"]?)"
)
_HIGH_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_=-]{16,}")


def redact_secret_text(
    text: str | None,
    *,
    raw_secret: str | None = None,
    aggressive: bool = False,
) -> str | None:
    """Redact credentials, tokens, and sensitive assignments from text.

    When ``aggressive=True`` (used for secret-scanner snippets), any remaining
    high-entropy token-like substring or standalone non-whitespace match is also
    replaced with ``[REDACTED]`` so raw secrets can never leak into logs or PRs.
    """
    if text is None:
        return None
    if not text:
        return text

    sanitized = text
    if raw_secret:
        sanitized = sanitized.replace(raw_secret, REDACTED_PLACEHOLDER)

    sanitized = _PEM_BLOCK_RE.sub(REDACTED_PLACEHOLDER, sanitized)
    sanitized = _URI_CREDENTIAL_RE.sub(
        rf"\1{REDACTED_PLACEHOLDER}:{REDACTED_PLACEHOLDER}@", sanitized
    )
    sanitized = _KNOWN_TOKEN_RE.sub(REDACTED_PLACEHOLDER, sanitized)
    sanitized = _SENSITIVE_ASSIGNMENT_RE.sub(rf"\1{REDACTED_PLACEHOLDER}\3", sanitized)

    if aggressive:
        stripped = sanitized.strip()
        if stripped and stripped != REDACTED_PLACEHOLDER and " " not in stripped:
            return REDACTED_PLACEHOLDER
        sanitized = _HIGH_ENTROPY_TOKEN_RE.sub(
            lambda m: (
                REDACTED_PLACEHOLDER
                if m.group(0) != REDACTED_PLACEHOLDER
                and (any(c.isdigit() for c in m.group(0)) or any(c in "+/_=-" for c in m.group(0)))
                else m.group(0)
            ),
            sanitized,
        )

    return sanitized


class Finding(BaseModel):
    """Normalized security finding emitted by any scanner plugin."""

    model_config = ConfigDict(frozen=True)

    plugin: str
    category: FindingCategory
    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line: int | None = None
    column: int | None = None
    fingerprint: str
    message: str
    redacted_snippet: str | None = None
    confidence: str | None = None
    validation_status: ValidationStatus = ValidationStatus.NOT_ATTEMPTED
    cwe: str | None = None
    remediation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_verified_secret(self) -> bool:
        """Return True if this finding is a live-verified active secret."""
        return (
            self.category == FindingCategory.SECRET
            and self.validation_status == ValidationStatus.VERIFIED_ACTIVE
        )


class PluginResult(BaseModel):
    """Result returned by a single scanner plugin invocation."""

    plugin: str
    status: PluginStatus
    findings: list[Finding] = Field(default_factory=list)
    duration_ms: float = 0.0
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class GateVerdict(BaseModel):
    """Aggregated compliance gate verdict across all executed plugins."""

    status: GateStatus
    exit_code: ExitCode
    mode: EnforcementMode
    target: str
    plugin_results: list[PluginResult]
    blocking_findings: list[Finding] = Field(default_factory=list)
    summary_reasons: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def all_findings(self) -> list[Finding]:
        """Return all normalized findings across all plugins."""
        return [finding for result in self.plugin_results for finding in result.findings]

    @property
    def total_findings(self) -> int:
        """Return total finding count across all plugins."""
        return len(self.all_findings)

    @property
    def counts_by_severity(self) -> dict[Severity, int]:
        """Return finding counts grouped by normalized severity."""
        counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for finding in self.all_findings:
            counts[finding.severity] += 1
        return counts

    @property
    def failed_plugins(self) -> list[PluginResult]:
        """Return plugin results that terminated with an execution error."""
        return [result for result in self.plugin_results if result.status == PluginStatus.ERROR]
