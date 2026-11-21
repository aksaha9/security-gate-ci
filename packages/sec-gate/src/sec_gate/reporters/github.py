"""GitHub Pull Request Comment reporter with idempotent upsert semantics."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

import httpx

from sec_gate.models import GateVerdict
from sec_gate.reporters.base import BaseReporter
from sec_gate.reporters.markdown import DEFAULT_COMMENT_MARKER, render_markdown_verdict

_PULL_REF_RE = re.compile(r"^refs/pull/(\d+)/")
_LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHubPRReporter(BaseReporter):
    """Posts or updates a single idempotent verdict comment on a GitHub Pull Request."""

    name: ClassVar[str] = "github"

    def __init__(
        self,
        *,
        api_url: str,
        repository: str,
        pr_number: int,
        token: str,
        marker: str = DEFAULT_COMMENT_MARKER,
        max_findings: int = 50,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.repository = repository
        self.pr_number = pr_number
        self.token = token
        self.marker = marker
        self.max_findings = max_findings
        self._client = client

    @staticmethod
    def resolve_pr_number(env: Mapping[str, str]) -> int | None:
        """Resolve the Pull Request number from GitHub Actions environment context."""
        for key in ("SEC_GATE_PR_NUMBER", "GITHUB_PR_NUMBER"):
            raw = env.get(key, "").strip()
            if raw.isdigit():
                return int(raw)

        if (ref := env.get("GITHUB_REF")) and (match := _PULL_REF_RE.match(ref.strip())):
            return int(match.group(1))

        if event_path := env.get("GITHUB_EVENT_PATH"):
            path = Path(event_path)
            if path.is_file():
                try:
                    payload = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    return None
                if isinstance(payload, dict):
                    pr = payload.get("pull_request")
                    if isinstance(pr, dict) and isinstance(pr.get("number"), int):
                        return pr["number"]
                    if isinstance(payload.get("number"), int):
                        return payload["number"]
        return None

    @classmethod
    def is_applicable(cls, env: Mapping[str, str] | None = None) -> bool:
        """Return True if GitHub Actions PR context and token are present."""
        resolved = os.environ if env is None else env
        token = resolved.get("SEC_GATE_GITHUB_TOKEN") or resolved.get("GITHUB_TOKEN")
        return (
            resolved.get("GITHUB_ACTIONS", "").lower() == "true"
            and bool(resolved.get("GITHUB_REPOSITORY"))
            and bool(token)
            and cls.resolve_pr_number(resolved) is not None
        )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        marker: str = DEFAULT_COMMENT_MARKER,
        max_findings: int = 50,
        client: httpx.Client | None = None,
    ) -> GitHubPRReporter:
        """Build a ``GitHubPRReporter`` from GitHub Actions environment variables."""
        resolved = os.environ if env is None else env
        repository = resolved.get("GITHUB_REPOSITORY", "")
        token = resolved.get("SEC_GATE_GITHUB_TOKEN") or resolved.get("GITHUB_TOKEN") or ""
        pr_number = cls.resolve_pr_number(resolved)
        if not repository or not token or pr_number is None:
            raise ValueError(
                "Missing required GitHub PR environment variables "
                "(GITHUB_REPOSITORY, GITHUB_TOKEN, and PR number/event context)."
            )
        api_url = resolved.get("GITHUB_API_URL") or "https://api.github.com"
        return cls(
            api_url=api_url,
            repository=repository,
            pr_number=pr_number,
            token=token,
            marker=marker,
            max_findings=max_findings,
            client=client,
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _issue_comments_url(self) -> str:
        return f"{self.api_url}/repos/{self.repository}/issues/{self.pr_number}/comments"

    def _comment_item_url(self, comment_id: int) -> str:
        return f"{self.api_url}/repos/{self.repository}/issues/comments/{comment_id}"

    def _list_comments(self, client: httpx.Client) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        next_url: str | None = f"{self._issue_comments_url()}?per_page=100"

        while next_url:
            resp = client.get(next_url, headers=self._headers())
            resp.raise_for_status()
            payload = resp.json()
            if isinstance(payload, list):
                comments.extend(item for item in payload if isinstance(item, dict))
            link_header = resp.headers.get("Link", "")
            match = _LINK_NEXT_RE.search(link_header)
            next_url = match.group(1) if match else None
        return comments

    def _upsert_comment(self, client: httpx.Client, body: str) -> dict[str, Any]:
        comments = self._list_comments(client)
        existing_id: int | None = None
        for comment in comments:
            if self.marker in str(comment.get("body", "")):
                comment_id = comment.get("id")
                if isinstance(comment_id, int):
                    existing_id = comment_id
                    break

        if existing_id is not None:
            resp = client.patch(
                self._comment_item_url(existing_id),
                headers=self._headers(),
                json={"body": body},
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "action": "updated",
                "comment_id": data.get("id", existing_id),
                "status_code": resp.status_code,
            }

        resp = client.post(
            self._issue_comments_url(),
            headers=self._headers(),
            json={"body": body},
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "action": "created",
            "comment_id": data.get("id"),
            "status_code": resp.status_code,
        }

    def report(self, verdict: GateVerdict) -> dict[str, Any]:
        """Upsert the Markdown verdict comment onto the active GitHub Pull Request."""
        body = render_markdown_verdict(
            verdict,
            marker=self.marker,
            max_findings=self.max_findings,
        )
        if self._client is not None:
            return self._upsert_comment(self._client, body)
        with httpx.Client(timeout=20.0) as client:
            return self._upsert_comment(client, body)
