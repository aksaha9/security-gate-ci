"""Terminal and CI log summary reporter."""

from __future__ import annotations

import sys
from typing import ClassVar, TextIO

from sec_gate.models import GateVerdict, PluginStatus, redact_secret_text
from sec_gate.reporters.base import BaseReporter


class ConsoleReporter(BaseReporter):
    """Prints a concise, redacted compliance summary to a terminal stream."""

    name: ClassVar[str] = "console"

    def __init__(self, stream: TextIO | None = None) -> None:
        self.stream = stream

    def report(self, verdict: GateVerdict) -> str:
        """Format and write the verdict summary to the configured stream."""
        lines: list[str] = [
            (
                f"[sec-gate] Verdict: {verdict.status.value} "
                f"(exit={int(verdict.exit_code)}, mode={verdict.mode.value}, "
                f"findings={verdict.total_findings}, blocking={len(verdict.blocking_findings)})"
            ),
            f"[sec-gate] Target: {verdict.target}",
        ]

        for result in verdict.plugin_results:
            line = (
                f"  - plugin={result.plugin} status={result.status.value} "
                f"findings={len(result.findings)} duration={result.duration_ms:.1f}ms"
            )
            if result.status == PluginStatus.ERROR and result.error:
                safe_error = redact_secret_text(result.error) or ""
                line = f"{line} error={safe_error}"
            lines.append(line)

        for reason in verdict.summary_reasons:
            lines.append(f"  * {redact_secret_text(reason) or ''}")

        if verdict.all_findings:
            lines.append("[sec-gate] Findings:")
            for finding in verdict.all_findings:
                loc = (
                    f"{finding.file_path}:{finding.line}"
                    if finding.line is not None
                    else finding.file_path
                )
                safe_msg = redact_secret_text(finding.message) or ""
                entry = (
                    f"  [{finding.severity.value}] {finding.plugin}/{finding.rule_id} "
                    f"at {loc}: {safe_msg}"
                )
                if finding.redacted_snippet:
                    safe_snip = redact_secret_text(finding.redacted_snippet) or ""
                    entry = f"{entry} | snippet={safe_snip}"
                lines.append(entry)

        output = "\n".join(lines) + "\n"
        target_stream = self.stream or sys.stdout
        target_stream.write(output)
        target_stream.flush()
        return output
