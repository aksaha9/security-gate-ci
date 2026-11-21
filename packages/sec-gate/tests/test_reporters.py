"""Unit tests for Markdown, Console, GitLab MR, and GitHub PR reporters."""

from __future__ import annotations

import io
import json
from pathlib import Path

import httpx
import yaml

from sec_gate.models import (
    EnforcementMode,
    ExitCode,
    Finding,
    FindingCategory,
    GateStatus,
    GateVerdict,
    PluginResult,
    PluginStatus,
    Severity,
    ValidationStatus,
)
from sec_gate.reporters import (
    DEFAULT_COMMENT_MARKER,
    ConsoleReporter,
    GitHubPRReporter,
    GitLabMRReporter,
    detect_ci_reporter,
    render_markdown_verdict,
)

REPO_ROOT = Path(__file__).resolve().parents[3]


def _sample_verdict() -> GateVerdict:
    secret_finding = Finding(
        plugin="kingfisher",
        category=FindingCategory.SECRET,
        rule_id="github-pat",
        rule_name="GitHub Token",
        severity=Severity.CRITICAL,
        file_path="deploy/app.env",
        line=5,
        fingerprint="kf:123",
        message="GitHub Token secret exposure detected in deploy/app.env",
        redacted_snippet="TOKEN=[REDACTED]",
        confidence="high",
        validation_status=ValidationStatus.VERIFIED_ACTIVE,
        cwe="CWE-798",
    )
    inj_finding = Finding(
        plugin="injection",
        category=FindingCategory.INJECTION,
        rule_id="INJ-SQLI-001",
        rule_name="Dynamic SQL Query Execution",
        severity=Severity.HIGH,
        file_path="src/db.py",
        line=21,
        fingerprint="inj:456",
        message="Dynamic SQL passed to .execute() | pipe",
        redacted_snippet='cursor.execute(f"SELECT * FROM t WHERE id={uid}")',
        cwe="CWE-89",
    )
    return GateVerdict(
        status=GateStatus.BLOCK,
        exit_code=ExitCode.BLOCK,
        mode=EnforcementMode.ENFORCE,
        target=".",
        plugin_results=[
            PluginResult(
                plugin="kingfisher",
                status=PluginStatus.FINDINGS,
                findings=[secret_finding],
                duration_ms=42.5,
            ),
            PluginResult(
                plugin="injection",
                status=PluginStatus.FINDINGS,
                findings=[inj_finding],
                duration_ms=11.0,
            ),
        ],
        blocking_findings=[secret_finding, inj_finding],
        summary_reasons=["2 finding(s) breached enforcement policy."],
    )


def test_markdown_and_console_render_and_redact_inline_secrets() -> None:
    verdict = GateVerdict(
        status=GateStatus.WARN,
        exit_code=ExitCode.WARN,
        mode=EnforcementMode.WARN,
        target=".",
        plugin_results=[
            PluginResult(
                plugin="custom",
                status=PluginStatus.FINDINGS,
                findings=[
                    Finding(
                        plugin="custom",
                        category=FindingCategory.SECRET,
                        rule_id="leak",
                        rule_name="Leak",
                        severity=Severity.HIGH,
                        file_path="a.txt",
                        line=1,
                        fingerprint="fp-leak",
                        message="Found ghp_UnredactedTestToken1234567890",
                        redacted_snippet="password=superSecretValue999",
                    )
                ],
            )
        ],
        summary_reasons=["Warn mode active"],
    )

    md = render_markdown_verdict(verdict)
    assert md.startswith(DEFAULT_COMMENT_MARKER)
    assert "WARN" in md
    assert "ghp_UnredactedTestToken1234567890" not in md
    assert "superSecretValue999" not in md
    assert "[REDACTED]" in md

    buf = io.StringIO()
    ConsoleReporter(stream=buf).report(_sample_verdict())
    console_out = buf.getvalue()
    assert "Verdict: BLOCK (exit=1" in console_out
    assert "github-pat" in console_out
    assert "INJ-SQLI-001" in console_out


def test_gitlab_mr_reporter_creates_and_updates_idempotently() -> None:
    verdict = _sample_verdict()
    calls: list[tuple[str, str, str | None]] = []

    # Case 1: paginated GET finds no existing marker -> POST creates note
    def create_handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url), request.headers.get("PRIVATE-TOKEN")))
        if request.method == "GET" and request.url.params.get("page") == "1":
            return httpx.Response(
                200,
                json=[{"id": 10, "body": "Other review note"}],
                headers={"X-Next-Page": "2"},
            )
        if request.method == "GET" and request.url.params.get("page") == "2":
            return httpx.Response(200, json=[], headers={"X-Next-Page": ""})
        if request.method == "POST":
            payload = json.loads(request.content.decode("utf-8"))
            assert DEFAULT_COMMENT_MARKER in payload["body"]
            return httpx.Response(201, json={"id": 77, "body": payload["body"]})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with httpx.Client(transport=httpx.MockTransport(create_handler)) as client:
        reporter = GitLabMRReporter(
            api_url="https://gitlab.example.com/api/v4",
            project_id="group/repo",
            mr_iid="42",
            token="gl-token",
            client=client,
        )
        created = reporter.report(verdict)

    assert created == {"action": "created", "note_id": 77, "status_code": 201}
    assert all(tok == "gl-token" for _, _, tok in calls)

    # Case 2: existing marker found on page 2 -> PUT updates note 88
    def update_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.params.get("page") == "1":
            return httpx.Response(200, json=[], headers={"X-Next-Page": "2"})
        if request.method == "GET" and request.url.params.get("page") == "2":
            return httpx.Response(
                200,
                json=[{"id": 88, "body": f"{DEFAULT_COMMENT_MARKER}\nold verdict"}],
                headers={"X-Next-Page": ""},
            )
        if request.method == "PUT":
            assert request.url.path.endswith("/notes/88")
            return httpx.Response(200, json={"id": 88})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with httpx.Client(transport=httpx.MockTransport(update_handler)) as client:
        reporter = GitLabMRReporter(
            api_url="https://gitlab.example.com/api/v4",
            project_id="group/repo",
            mr_iid="42",
            token="job-tok",
            auth_header="JOB-TOKEN",
            client=client,
        )
        updated = reporter.report(verdict)

    assert updated == {"action": "updated", "note_id": 88, "status_code": 200}


def test_github_pr_reporter_creates_and_updates_idempotently(tmp_path: Path) -> None:
    verdict = _sample_verdict()

    # Case 1: Link pagination then POST
    def create_handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer gh-tok"
        if request.method == "GET" and "page=2" not in str(request.url):
            next_link = (
                '<https://api.github.com/repos/org/app/issues/9/comments?page=2>; rel="next"'
            )
            return httpx.Response(
                200,
                json=[{"id": 1, "body": "lint ok"}],
                headers={"Link": next_link},
            )
        if request.method == "GET" and "page=2" in str(request.url):
            return httpx.Response(200, json=[])
        if request.method == "POST":
            payload = json.loads(request.content.decode("utf-8"))
            assert DEFAULT_COMMENT_MARKER in payload["body"]
            return httpx.Response(201, json={"id": 501})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    with httpx.Client(transport=httpx.MockTransport(create_handler)) as client:
        reporter = GitHubPRReporter(
            api_url="https://api.github.com",
            repository="org/app",
            pr_number=9,
            token="gh-tok",
            client=client,
        )
        created = reporter.report(verdict)

    assert created == {"action": "created", "comment_id": 501, "status_code": 201}

    # Case 2: Existing marker comment -> PATCH
    def update_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                json=[{"id": 902, "body": f"{DEFAULT_COMMENT_MARKER}\nprevious"}],
            )
        if request.method == "PATCH":
            assert request.url.path == "/repos/org/app/issues/comments/902"
            return httpx.Response(200, json={"id": 902})
        raise AssertionError(f"Unexpected request: {request.method} {request.url}")

    event_file = tmp_path / "event.json"
    event_file.write_text(json.dumps({"pull_request": {"number": 17}}), encoding="utf-8")
    with httpx.Client(transport=httpx.MockTransport(update_handler)) as client:
        reporter = GitHubPRReporter.from_env(
            {
                "GITHUB_ACTIONS": "true",
                "GITHUB_REPOSITORY": "org/app",
                "GITHUB_TOKEN": "gh-tok",
                "GITHUB_EVENT_PATH": str(event_file),
            },
            client=client,
        )
        assert reporter.pr_number == 17
        updated = reporter.report(verdict)

    assert updated == {"action": "updated", "comment_id": 902, "status_code": 200}


def test_detect_ci_reporter_and_pr_number_resolution() -> None:
    assert detect_ci_reporter({}) is None

    gl = detect_ci_reporter(
        {
            "GITLAB_CI": "true",
            "CI_PROJECT_ID": "123",
            "CI_MERGE_REQUEST_IID": "7",
            "CI_JOB_TOKEN": "job-abc",
        }
    )
    assert isinstance(gl, GitLabMRReporter)
    assert gl.auth_header == "JOB-TOKEN"

    gh = detect_ci_reporter(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "org/app",
            "GITHUB_REF": "refs/pull/34/merge",
            "GITHUB_TOKEN": "tok-xyz",
        }
    )
    assert isinstance(gh, GitHubPRReporter)
    assert gh.pr_number == 34


def test_ci_templates_are_valid_yaml() -> None:
    gitlab_tpl = yaml.safe_load(
        (REPO_ROOT / "ci-templates/gitlab/sec-gate.gitlab-ci.yml").read_text(encoding="utf-8")
    )
    assert isinstance(gitlab_tpl, dict)
    assert "sec-gate" in gitlab_tpl
    assert gitlab_tpl[".sec-gate-base"]["allow_failure"]["exit_codes"] == [10]

    template_text = (REPO_ROOT / "ci-templates/github/sec-gate.workflow.yml").read_text(
        encoding="utf-8"
    )
    workflow_text = (REPO_ROOT / ".github/workflows/sec-gate.workflow.yml").read_text(
        encoding="utf-8"
    )
    assert template_text == workflow_text

    github_tpl = yaml.safe_load(workflow_text)
    assert isinstance(github_tpl, dict)
    assert "jobs" in github_tpl
    assert "sec-gate" in github_tpl["jobs"]
    assert True in github_tpl or "on" in github_tpl
