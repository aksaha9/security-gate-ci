"""Compliance reporters and CI platform auto-detection."""

from __future__ import annotations

import os
from collections.abc import Mapping

from sec_gate.reporters.base import BaseReporter
from sec_gate.reporters.console import ConsoleReporter
from sec_gate.reporters.github import GitHubPRReporter
from sec_gate.reporters.gitlab import GitLabMRReporter
from sec_gate.reporters.markdown import (
    DEFAULT_COMMENT_MARKER,
    MarkdownFileReporter,
    render_markdown_verdict,
)


def detect_ci_reporter(
    env: Mapping[str, str] | None = None,
    *,
    marker: str = DEFAULT_COMMENT_MARKER,
    max_findings: int = 50,
) -> BaseReporter | None:
    """Auto-detect GitLab CI or GitHub Actions PR/MR context and build a reporter."""
    resolved = os.environ if env is None else env
    if GitLabMRReporter.is_applicable(resolved):
        return GitLabMRReporter.from_env(resolved, marker=marker, max_findings=max_findings)
    if GitHubPRReporter.is_applicable(resolved):
        return GitHubPRReporter.from_env(resolved, marker=marker, max_findings=max_findings)
    return None


__all__ = [
    "DEFAULT_COMMENT_MARKER",
    "BaseReporter",
    "ConsoleReporter",
    "GitHubPRReporter",
    "GitLabMRReporter",
    "MarkdownFileReporter",
    "detect_ci_reporter",
    "render_markdown_verdict",
]
