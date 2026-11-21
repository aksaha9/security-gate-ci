"""Redacted Markdown verdict table generator and file reporter."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from sec_gate.models import (
    Finding,
    GateStatus,
    GateVerdict,
    PluginStatus,
    Severity,
    ValidationStatus,
    redact_secret_text,
)
from sec_gate.reporters.base import BaseReporter

DEFAULT_COMMENT_MARKER = "<!-- sec-gate-verdict -->"

_STATUS_BADGE: dict[GateStatus, str] = {
    GateStatus.PASS: "PASS",
    GateStatus.WARN: "WARN",
    GateStatus.BLOCK: "BLOCK",
}

_STATUS_ICON: dict[GateStatus, str] = {
    GateStatus.PASS: ":white_check_mark:",
    GateStatus.WARN: ":warning:",
    GateStatus.BLOCK: ":x:",
}


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _format_location(finding: Finding) -> str:
    if finding.line is not None and finding.column is not None:
        return f"`{finding.file_path}:{finding.line}:{finding.column}`"
    if finding.line is not None:
        return f"`{finding.file_path}:{finding.line}`"
    return f"`{finding.file_path}`"


def _format_context(finding: Finding) -> str:
    parts: list[str] = []
    if finding.validation_status != ValidationStatus.NOT_ATTEMPTED:
        parts.append(finding.validation_status.value)
    if finding.cwe:
        parts.append(finding.cwe)
    if finding.confidence:
        parts.append(f"conf:{finding.confidence}")
    return ", ".join(parts) if parts else "-"


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            -f.severity.rank,
            0 if f.is_verified_secret else 1,
            f.plugin,
            f.file_path,
            f.line or 0,
            f.rule_id,
        ),
    )


def render_markdown_verdict(
    verdict: GateVerdict,
    *,
    marker: str = DEFAULT_COMMENT_MARKER,
    max_findings: int = 50,
) -> str:
    """Render a strict-redacted Markdown compliance verdict suitable for MR/PR notes."""
    badge = _STATUS_BADGE[verdict.status]
    icon = _STATUS_ICON[verdict.status]
    counts = verdict.counts_by_severity
    timestamp = verdict.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        marker,
        f"## {icon} Security Compliance Gate: **{badge}** (exit `{int(verdict.exit_code)}`)",
        "",
        (
            f"- **Mode:** `{verdict.mode.value}` | **Target:** `{verdict.target}` | "
            f"**Total Findings:** `{verdict.total_findings}` | "
            f"**Blocking:** `{len(verdict.blocking_findings)}` | **Evaluated:** `{timestamp}`"
        ),
        (
            "- **Severity Breakdown:** "
            f"CRITICAL `{counts[Severity.CRITICAL]}` | "
            f"HIGH `{counts[Severity.HIGH]}` | "
            f"MEDIUM `{counts[Severity.MEDIUM]}` | "
            f"LOW `{counts[Severity.LOW]}` | "
            f"INFO `{counts[Severity.INFO]}`"
        ),
        "",
        "### Plugin Execution Summary",
        "",
        "| Plugin | Status | Findings | Duration (ms) | Notes |",
        "| --- | --- | ---: | ---: | --- |",
    ]

    for result in verdict.plugin_results:
        if result.status == PluginStatus.ERROR and result.error:
            note = redact_secret_text(result.error) or "error"
        elif result.status == PluginStatus.SKIPPED:
            note = str(result.metadata.get("reason", "disabled"))
        elif ignored := result.metadata.get("ignored_findings"):
            note = f"{ignored} allowlisted finding(s) suppressed"
        else:
            note = str(result.metadata.get("note", "-"))
        lines.append(
            f"| `{_escape_cell(result.plugin)}` | `{result.status.value}` | "
            f"{len(result.findings)} | {result.duration_ms:.1f} | {_escape_cell(note)} |"
        )

    if verdict.summary_reasons:
        lines.extend(["", "### Policy Decision"])
        for reason in verdict.summary_reasons:
            safe_reason = redact_secret_text(reason) or ""
            lines.append(f"- {safe_reason}")

    ordered_findings = _sorted_findings(verdict.all_findings)
    if ordered_findings:
        displayed = ordered_findings[:max_findings]
        lines.extend(
            [
                "",
                "### Findings",
                "",
                "| Severity | Plugin | Rule | Location | Context | Details |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for finding in displayed:
            safe_msg = redact_secret_text(finding.message) or ""
            details = _escape_cell(safe_msg)
            if finding.redacted_snippet:
                safe_snippet = redact_secret_text(finding.redacted_snippet) or ""
                safe_snippet = _escape_cell(safe_snippet.replace("`", "'"))
                if len(safe_snippet) > 90:
                    safe_snippet = f"{safe_snippet[:87]}..."
                details = f"{details} (`{safe_snippet}`)"

            lines.append(
                f"| **{finding.severity.value}** | `{_escape_cell(finding.plugin)}` | "
                f"`{_escape_cell(finding.rule_id)}` | {_format_location(finding)} | "
                f"{_escape_cell(_format_context(finding))} | {details} |"
            )

        omitted = len(ordered_findings) - len(displayed)
        if omitted > 0:
            lines.append(
                f"\n_... and {omitted} additional finding(s) omitted (limit={max_findings})._"
            )

    return "\n".join(lines) + "\n"


class MarkdownFileReporter(BaseReporter):
    """Writes the rendered Markdown verdict table to a local file."""

    name: ClassVar[str] = "markdown-file"

    def __init__(
        self,
        output_path: Path,
        *,
        marker: str = DEFAULT_COMMENT_MARKER,
        max_findings: int = 50,
    ) -> None:
        self.output_path = output_path
        self.marker = marker
        self.max_findings = max_findings

    def report(self, verdict: GateVerdict) -> Path:
        """Render and write the Markdown verdict to ``self.output_path``."""
        rendered = render_markdown_verdict(
            verdict,
            marker=self.marker,
            max_findings=self.max_findings,
        )
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.write_text(rendered, encoding="utf-8")
        return self.output_path
