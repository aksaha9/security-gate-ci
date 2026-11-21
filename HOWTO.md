# How-To Guide: Deploying and Extending `sec-gate`

This guide walks through local verification, building the immutable container image, configuring compliance policies, and rolling out `sec-gate` across **GitLab CI** and **GitHub Actions**.

---

## Contents

1. [Prerequisites & Local Setup](#1-prerequisites--local-setup)
2. [Building & Publishing the Container Image](#2-building--publishing-the-container-image)
3. [Policy Configuration (`sec-gate.yaml` & Environment Overrides)](#3-policy-configuration-sec-gateyaml--environment-overrides)
4. [GitLab CI Integration](#4-gitlab-ci-integration)
5. [GitHub Actions Integration](#5-github-actions-integration)
6. [Extending `sec-gate` with Custom Plugins](#6-extending-sec-gate-with-custom-plugins)
7. [Troubleshooting & Operational Tips](#7-troubleshooting--operational-tips)

---

## 1. Prerequisites & Local Setup

### Requirements
- **Local CLI / Development:** Python `3.12+`, [`uv`](https://docs.astral.sh/uv/), and optionally the [`kingfisher`](https://github.com/mongodb/kingfisher/releases) binary if running secret scans outside the container.
- **Container Builds / CI Runners:** `podman` or `docker` (Docker Engine / Buildx).

### Run Locally via `uv`

```bash
git clone https://github.com/aksaha9/security-gate-ci.git
cd security-gate-ci

# Create .venv and install workspace dependencies
uv sync --python 3.12

# Verify plugin registration and local tool availability
uv run sec-gate list-plugins

# Run the unit test suite & linter
uv run ruff check .
uv run pytest -v
```

### Run a Local Scan

```bash
# Run injection checks only (useful on workstations without the kingfisher binary installed)
uv run sec-gate run /path/to/repo --plugin injection --no-comment

# Run all enabled plugins in warn mode (exits 10 on findings, 0 when clean)
uv run sec-gate run /path/to/repo \
  --config sec-gate.example.yaml \
  --mode warn \
  --no-comment \
  --json-out sec-gate-verdict.json \
  --markdown-out sec-gate-verdict.md
```

> **Note:** When running locally without `kingfisher` in your `$PATH`, `sec-gate list-plugins` reports `kingfisher` as `unavailable` and `sec-gate run` will report a plugin error (exit `1` when `fail_on_plugin_error: true`). Use the container image in CI/CD or install the `kingfisher` release binary for local secret scanning.

---

## 2. Building & Publishing the Container Image

[Containerfile](Containerfile) produces a single non-root (`UID 10001`) image containing Python 3.12, `sec-gate`, `git`, `ca-certificates`, `/usr/local/bin/kingfisher`, and required license/attribution files.

### Build with Podman or Docker

```bash
# Build with Podman
podman build -f Containerfile -t ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0 .

# Or build with Docker
docker build -f Containerfile -t ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0 .
```

To pin immutable upstream digests in regulated environments:

```bash
docker build -f Containerfile \
  --build-arg KINGFISHER_IMAGE=ghcr.io/mongodb/kingfisher@sha256:<digest> \
  --build-arg UV_IMAGE=ghcr.io/astral-sh/uv@sha256:<digest> \
  -t ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0 .
```

### Push to Your Registry

**GitHub Container Registry (GHCR):**
```bash
echo "$GITHUB_PAT" | docker login ghcr.io -u <username> --password-stdin
docker push ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0
```

**GitLab Container Registry:**
```bash
docker login registry.gitlab.com -u <username> -p "$GITLAB_PAT"
docker tag ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0 \
  registry.gitlab.com/<group>/<project>/sec-gate:0.1.0
docker push registry.gitlab.com/<group>/<project>/sec-gate:0.1.0
```

### Run the Container Against Any Local Directory

```bash
docker run --rm \
  -v "$(pwd):/workspace:ro" \
  ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0 \
  run /workspace --mode enforce --no-comment
```

---

## 3. Policy Configuration (`sec-gate.yaml` & Environment Overrides)

Copy [sec-gate.example.yaml](sec-gate.example.yaml) to `sec-gate.yaml` at the root of each repository you want to protect (auto-discovered filenames: `sec-gate.yaml`, `sec-gate.yml`, `.sec-gate.yaml`), or specify an explicit file with `--config path/to/policy.yaml`.

### Exit Code Contract

| Exit Code | Gate Status | Behavior |
| --- | --- | --- |
| `0` | `PASS` | Clean scan or all findings are below configured blocking thresholds / allowlisted. |
| `1` | `BLOCK` | In `enforce` mode: blocking finding detected (e.g., active verified secret, finding `>= fail_on_severity`, or plugin error when `fail_on_plugin_error: true`). |
| `10` | `WARN` | In `warn` mode: findings or plugin errors detected. Pipelines configured to allow exit code `10` surface warnings without breaking builds. |
| `2` | Config Error | Missing explicit `--config` path or invalid YAML/environment configuration. |

### Recommended Rollout Strategy

1. **Phase 1 — Observation (`mode: warn`):** Enable `sec-gate` across repositories in `warn` mode for 1–2 sprints so teams review MR/PR comments and tune false positives without blocking deployments.
2. **Phase 2 — Enforcement (`mode: enforce`):** Switch to `enforce` mode with `fail_on_verified_secret: true` and `fail_on_severity: HIGH`.

### Key Policy Controls

- **Secret validation policies (`policy` & `plugins.kingfisher.validate_secrets`):**
  - `plugins.kingfisher.validate_secrets` defaults to **`false`** (`--no-validate`). Live validation is disabled by default so CI pipelines never send unsolicited authentication probes to external provider APIs against credentials you may not own or lack explicit permission to test (such as public fork PRs or third-party fixtures).
  - `fail_on_verified_secret: true` — Blocks immediately on live-validated active secrets (`VERIFIED_ACTIVE`) when `validate_secrets: true` is opted in.
  - `fail_on_unverified_secret: false` — With `validate_secrets: false`, findings carry `NOT_ATTEMPTED`; set `fail_on_unverified_secret: true` (or `SEC_GATE_FAIL_ON_UNVERIFIED_SECRET=true`) to block on static detections without making outbound API calls.
  - `fail_on_inactive_secret: false` — Set to `true` if historical/revoked credentials must still block merges.
  - **Responsibility Disclaimer:** Because `validate_secrets` defaults to `false` (and static scanning cannot guarantee detection of every secret format), any undetected, unverified, or unblocked secret exposure or resulting secret leakage is solely the responsibility of the consuming repository owner and operator—not `security-gate-ci` or its contributors.
- **Allowlisting & inline suppressions:**
  - Suppress specific findings by fingerprint in `policy.ignore_fingerprints` (visible in JSON output) or globally by rule ID in `policy.ignore_rules`.
  - Suppress individual injection lines inline by adding `sec-gate: ignore` in a comment on that line (e.g., `# sec-gate: ignore`, `// sec-gate: ignore`, or `<!-- sec-gate: ignore -->`).
- **Authorized Live Validation Opt-In:** Set `plugins.kingfisher.validate_secrets: true` (or `SEC_GATE_KINGFISHER_VALIDATE=true`) only on owned/authorized repositories with outbound network access where live credential probing is approved.

### Environment Variable Overrides

| Variable | Overrides | Example |
| --- | --- | --- |
| `SEC_GATE_MODE` | `policy.mode` | `enforce` or `warn` |
| `SEC_GATE_EXECUTION_MODE` | `execution_mode` | `parallel` or `sequential` |
| `SEC_GATE_FAIL_ON_SEVERITY` | `policy.fail_on_severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `SEC_GATE_FAIL_ON_VERIFIED_SECRET` | `policy.fail_on_verified_secret` | `true` / `false` |
| `SEC_GATE_FAIL_ON_UNVERIFIED_SECRET` | `policy.fail_on_unverified_secret` | `true` / `false` |
| `SEC_GATE_FAIL_ON_PLUGIN_ERROR` | `policy.fail_on_plugin_error` | `true` / `false` |
| `SEC_GATE_POST_COMMENT` | `reporters.post_comment` | `true` / `false` |
| `SEC_GATE_PLUGINS` | Enabled plugin allowlist | `kingfisher,injection` |
| `SEC_GATE_KINGFISHER_VALIDATE` | `plugins.kingfisher.validate_secrets` | `true` / `false` |
| `SEC_GATE_KINGFISHER_CONFIDENCE` | `plugins.kingfisher.confidence` | `low`, `medium`, `high` |
| `SEC_GATE_KINGFISHER_BINARY` | `plugins.kingfisher.binary` | `/usr/local/bin/kingfisher` |
| `SEC_GATE_JSON_OUTPUT` | `reporters.json_output` | `sec-gate-verdict.json` |
| `SEC_GATE_MARKDOWN_OUTPUT` | `reporters.markdown_output` | `sec-gate-verdict.md` |

---

## 4. GitLab CI Integration

The reusable template at [ci-templates/gitlab/sec-gate.gitlab-ci.yml](ci-templates/gitlab/sec-gate.gitlab-ci.yml) runs on Merge Request pipelines and default-branch builds, treats exit code `10` as a non-blocking warning (`allow_failure.exit_codes: [10]`), and archives `sec-gate-verdict.json` and `sec-gate-verdict.md` as job artifacts.

### Step 1: Configure MR Comment Authentication

`sec-gate` automatically detects `GITLAB_CI=true`, `CI_PROJECT_ID`, and `CI_MERGE_REQUEST_IID` and looks for a token in this order:
1. `SEC_GATE_GITLAB_TOKEN` (`PRIVATE-TOKEN` header)
2. `GITLAB_TOKEN` (`PRIVATE-TOKEN` header)
3. `CI_JOB_TOKEN` (`JOB-TOKEN` header)

> **Recommended:** Create a **Project Access Token** (or Group Access Token) with the `api` scope and **Developer** or **Reporter** role, then add it under **Settings → CI/CD → Variables** as `GITLAB_TOKEN` (marked **Masked** and **Protected** only if needed on protected branches—leave unprotected if feature-branch MRs need MR comments). Standard `CI_JOB_TOKEN` frequently lacks permission to list/post MR notes on GitLab.

### Step 2: Include the Template in `.gitlab-ci.yml`

**Option A — Include directly from GitHub (`remote:`):**

```yaml
stages:
  - test

include:
  - remote: "https://raw.githubusercontent.com/aksaha9/security-gate-ci/main/ci-templates/gitlab/sec-gate.gitlab-ci.yml"

sec-gate:
  variables:
    SEC_GATE_IMAGE: "ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0"
    SEC_GATE_MODE: "enforce"
    # Optional custom policy file:
    # SEC_GATE_CONFIG: ".ci/sec-gate.yaml"
```

**Option B — Mirror into your internal GitLab instance (`project:`):**

```yaml
include:
  - project: "platform-security/security-gate-ci"
    ref: "v0.1.0"
    file: "/ci-templates/gitlab/sec-gate.gitlab-ci.yml"

sec-gate:
  variables:
    SEC_GATE_IMAGE: "registry.gitlab.example.com/platform-security/sec-gate:0.1.0"
```

### Step 3: Verify in a Merge Request

1. Open a Merge Request targeting your default branch.
2. Confirm the `sec-gate` job executes in the `test` stage:
   - Passing MRs show green (`exit 0`).
   - Warn-mode findings show yellow warning icon (`exit 10`, allowed failure).
   - Policy violations fail the job (`exit 1`) and block merge when **Pipelines must succeed** is enabled.
3. Verify a single verdict comment (`<!-- sec-gate-verdict -->`) is created on the first MR pipeline and updated in place on subsequent commits.

---

## 5. GitHub Actions Integration

The reusable workflow is published at both [.github/workflows/sec-gate.workflow.yml](.github/workflows/sec-gate.workflow.yml) (directly callable via `uses:`) and [ci-templates/github/sec-gate.workflow.yml](ci-templates/github/sec-gate.workflow.yml).

### Step 1: Add Caller Workflow to Target Repositories

Create `.github/workflows/security-gate.yml` in the consumer repository:

```yaml
name: Security Compliance Gate

on:
  pull_request:
    branches: ["main"]
  push:
    branches: ["main"]

permissions:
  contents: read
  pull-requests: write

jobs:
  sec-gate:
    uses: aksaha9/security-gate-ci/.github/workflows/sec-gate.workflow.yml@main
    with:
      image: "ghcr.io/aksaha9/security-gate-ci/sec-gate:0.1.0"
      target: "."
      mode: "enforce"
      fail-on-severity: "HIGH"
      post-comment: true
      upload-artifacts: true
    secrets:
      github-token: ${{ secrets.GITHUB_TOKEN }}
```

> **Enterprise / Private Mirrors:** If your organization restricts cross-repo workflow references, copy `ci-templates/github/sec-gate.workflow.yml` into your organization's shared `.github` or tooling repository and point `uses:` to that internal path.

### Reusable Workflow Inputs

| Input | Default | Description |
| --- | --- | --- |
| `image` | `ghcr.io/aksaha9/security-gate-ci/sec-gate:latest` | Immutable container image containing `sec-gate` and `kingfisher` |
| `target` | `.` | Relative path inside `$GITHUB_WORKSPACE` to scan |
| `config-path` | `""` | Optional explicit path to a `sec-gate.yaml` policy file |
| `mode` | `enforce` | `enforce` (`1` on block) or `warn` (`10` mapped to `::warning::` annotation) |
| `fail-on-severity` | `HIGH` | Minimum severity threshold for non-secret findings |
| `post-comment` | `true` | Upsert a single redacted Markdown PR comment (`<!-- sec-gate-verdict -->`) |
| `upload-artifacts` | `true` | Upload `sec-gate-verdict.json` and `sec-gate-verdict.md` via `actions/upload-artifact@v4` |

### Fork PRs & Permissions Notes

- On `pull_request` workflows triggered from **public forks**, GitHub downgrades `secrets.GITHUB_TOKEN` to read-only. In that case, either pass `post-comment: false` for fork PRs (results still appear in `$GITHUB_STEP_SUMMARY` and logs) or ensure your workflow configuration fits your repository security model.
- In `warn` mode, exit code `10` is caught by the workflow runner, emits a GitHub `::warning::` annotation, appends the full verdict table to the job summary, and marks the check green so PRs are not blocked.

---

## 6. Extending `sec-gate` with Custom Plugins

New compliance or SAST scanners require **zero edits** to `ScanOrchestrator`, `PolicyEvaluator`, or `config.py`.

### Step 1: Subclass `BaseScannerPlugin`

```python
from pathlib import Path
from typing import ClassVar

from sec_gate.models import Finding, FindingCategory, PluginResult, PluginStatus, Severity
from sec_gate.plugins.base import BaseScannerPlugin


class DockerfilePolicyPlugin(BaseScannerPlugin):
    name: ClassVar[str] = "dockerfile-policy"
    description: ClassVar[str] = "Checks containers for root USER directives"
    category: ClassVar[FindingCategory] = FindingCategory.COMPLIANCE
    version: ClassVar[str] = "0.1.0"

    def scan(self, target: Path) -> PluginResult:
        allow_root = bool(self.raw_options.get("allow_root", False))
        # Implement checks and emit normalized Finding objects...
        findings: list[Finding] = []
        if not allow_root and ...:
            findings.append(
                Finding(
                    plugin=self.name,
                    category=self.category,
                    rule_id="DOCKER-001",
                    rule_name="Missing Non-Root USER",
                    severity=Severity.HIGH,
                    file_path="Dockerfile",
                    line=1,
                    fingerprint="docker:DOCKER-001:Dockerfile",
                    message="Container image runs as root.",
                )
            )
        status = PluginStatus.FINDINGS if findings else PluginStatus.PASSED
        return PluginResult(plugin=self.name, status=status, findings=findings)
```

### Step 2: Advertise via Python Entry Points

In your plugin package's `pyproject.toml`:

```toml
[project.entry-points."sec_gate.plugins"]
dockerfile-policy = "my_org_plugins.docker:DockerfilePolicyPlugin"
```

Install the package into the same Python environment (or extend `Containerfile`), then configure options under `plugins:` in `sec-gate.yaml`:

```yaml
plugins:
  dockerfile-policy:
    enabled: true
    allow_root: false
```

`PluginConfig` accepts arbitrary extra keys (`extra="allow"`) and forwards them via `self.raw_options`.

---

## 7. Troubleshooting & Operational Tips

- **MR/PR comment failed with `403 Forbidden`:**
  - **GitLab:** Verify `GITLAB_TOKEN` is set, unmasked in logs, has `api` scope, and is not blocked on unprotected branches.
  - **GitHub:** Ensure the caller workflow grants `permissions: { contents: read, pull-requests: write }` and passes `secrets: github-token: ${{ secrets.GITHUB_TOKEN }}`.
- **Slow scans on repositories with large Git history:**
  - Keep `plugins.kingfisher.git_history: none` in `sec-gate.yaml` for fast PR/MR working-tree checks, and run periodic scheduled pipelines with `git_history: full`.
  - Use `plugins.kingfisher.since_commit` or `exclude_paths` to skip vendor/lock artifacts.
- **Testing policy evaluation without posting comments:**
  - Pass `--no-comment --markdown-out preview.md` locally or in CI dry runs to inspect the exact Markdown verdict table before enabling PR/MR comments.
