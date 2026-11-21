"""GitLab Merge Request Note reporter with idempotent upsert semantics."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any, ClassVar
from urllib.parse import quote

import httpx

from sec_gate.models import GateVerdict
from sec_gate.reporters.base import BaseReporter
from sec_gate.reporters.markdown import DEFAULT_COMMENT_MARKER, render_markdown_verdict


class GitLabMRReporter(BaseReporter):
    """Posts or updates a single idempotent verdict note on a GitLab Merge Request."""

    name: ClassVar[str] = "gitlab"

    def __init__(
        self,
        *,
        api_url: str,
        project_id: str,
        mr_iid: str,
        token: str,
        auth_header: str = "PRIVATE-TOKEN",
        marker: str = DEFAULT_COMMENT_MARKER,
        max_findings: int = 50,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.project_id = project_id
        self.mr_iid = mr_iid
        self.token = token
        self.auth_header = auth_header
        self.marker = marker
        self.max_findings = max_findings
        self._client = client

    @classmethod
    def _resolve_auth(cls, env: Mapping[str, str]) -> tuple[str, str] | None:
        if token := (env.get("SEC_GATE_GITLAB_TOKEN") or env.get("GITLAB_TOKEN")):
            return token, "PRIVATE-TOKEN"
        if job_token := env.get("CI_JOB_TOKEN"):
            return job_token, "JOB-TOKEN"
        return None

    @classmethod
    def is_applicable(cls, env: Mapping[str, str] | None = None) -> bool:
        """Return True if GitLab CI MR context and credentials are available."""
        resolved = os.environ if env is None else env
        return (
            resolved.get("GITLAB_CI", "").lower() == "true"
            and bool(resolved.get("CI_PROJECT_ID"))
            and bool(resolved.get("CI_MERGE_REQUEST_IID"))
            and cls._resolve_auth(resolved) is not None
        )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        marker: str = DEFAULT_COMMENT_MARKER,
        max_findings: int = 50,
        client: httpx.Client | None = None,
    ) -> GitLabMRReporter:
        """Build a ``GitLabMRReporter`` from GitLab CI environment variables."""
        resolved = os.environ if env is None else env
        project_id = resolved.get("CI_PROJECT_ID", "")
        mr_iid = resolved.get("CI_MERGE_REQUEST_IID", "")
        auth = cls._resolve_auth(resolved)
        if not project_id or not mr_iid or auth is None:
            raise ValueError(
                "Missing required GitLab MR environment variables "
                "(CI_PROJECT_ID, CI_MERGE_REQUEST_IID, and GitLab token)."
            )
        token, auth_header = auth
        api_url = resolved.get("CI_API_V4_URL") or "https://gitlab.com/api/v4"
        return cls(
            api_url=api_url,
            project_id=project_id,
            mr_iid=mr_iid,
            token=token,
            auth_header=auth_header,
            marker=marker,
            max_findings=max_findings,
            client=client,
        )

    def _notes_endpoint(self) -> str:
        encoded_project = quote(self.project_id, safe="")
        return f"{self.api_url}/projects/{encoded_project}/merge_requests/{self.mr_iid}/notes"

    def _headers(self) -> dict[str, str]:
        return {
            self.auth_header: self.token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _list_notes(self, client: httpx.Client) -> list[dict[str, Any]]:
        notes: list[dict[str, Any]] = []
        endpoint = self._notes_endpoint()
        page = "1"
        while page:
            resp = client.get(
                endpoint,
                headers=self._headers(),
                params={"per_page": 100, "page": page},
            )
            resp.raise_for_status()
            payload = resp.json()
            if isinstance(payload, list):
                notes.extend(item for item in payload if isinstance(item, dict))
            next_page = resp.headers.get("X-Next-Page", "").strip()
            page = next_page if next_page and next_page != page else ""
        return notes

    def _upsert_note(self, client: httpx.Client, body: str) -> dict[str, Any]:
        notes = self._list_notes(client)
        existing_id: int | None = None
        for note in notes:
            if self.marker in str(note.get("body", "")):
                note_id = note.get("id")
                if isinstance(note_id, int):
                    existing_id = note_id
                    break

        endpoint = self._notes_endpoint()
        if existing_id is not None:
            resp = client.put(
                f"{endpoint}/{existing_id}",
                headers=self._headers(),
                json={"body": body},
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "action": "updated",
                "note_id": data.get("id", existing_id),
                "status_code": resp.status_code,
            }

        resp = client.post(
            endpoint,
            headers=self._headers(),
            json={"body": body},
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "action": "created",
            "note_id": data.get("id"),
            "status_code": resp.status_code,
        }

    def report(self, verdict: GateVerdict) -> dict[str, Any]:
        """Upsert the Markdown verdict note onto the active GitLab Merge Request."""
        body = render_markdown_verdict(
            verdict,
            marker=self.marker,
            max_findings=self.max_findings,
        )
        if self._client is not None:
            return self._upsert_note(self._client, body)
        with httpx.Client(timeout=20.0) as client:
            return self._upsert_note(client, body)
