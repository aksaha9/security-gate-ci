# Security Gate CI (`sec-gate`)

A platform-agnostic, pluggable CI/CD security compliance gate built for engineering and DevSecOps teams operating across **GitLab CI** and **GitHub Actions**.

`sec-gate` standardizes secret scanning, static injection checks, policy evaluation, and merge/pull request feedback behind one CLI and one immutable container image—without locking your pipelines into platform-specific scripts.

> **Ready to deploy?** Follow the step-by-step setup guide in **[HOWTO.md](HOWTO.md)** for container builds, `sec-gate.yaml` policy tuning, GitLab CI, GitHub Actions, and custom plugins.

---

## Why `sec-gate`

- **Verified Secret Detection:** Wraps [MongoDB Kingfisher](https://github.com/mongodb/kingfisher) to detect exposed credentials and distinguish live-verified active secrets (`VERIFIED_ACTIVE`) from unverified or inactive matches.
- **Pluggable Scanner Architecture:** Register new scanners via `BaseScannerPlugin` or Python entry points (`sec_gate.plugins`) with zero modifications to the orchestrator or policy engine. Ships with an **Injection Vulnerability Checker** (`sqli`, `cmdi`, `xss`) covering Python AST and JS/TS/HTML/Jinja2/PHP/Ruby/Java/Go/Shell patterns.
- **Deterministic Policy & Exit Codes:** Evaluates normalized findings against `sec-gate.yaml` (plus `SEC_GATE_*` env overrides) and enforces consistent CI exit codes:
  - `0` — **PASS**: No blocking findings.
  - `1` — **BLOCK**: Policy threshold breached (e.g., active verified secret, `HIGH`/`CRITICAL` injection, or plugin failure in `enforce` mode).
  - `10` — **WARN**: Findings detected in `warn` mode; surfaces pipeline warnings without blocking delivery.
- **Idempotent MR / PR Reporting:** Auto-detects GitLab CI (`GITLAB_CI=true`) or GitHub Actions (`GITHUB_ACTIONS=true`) and upserts a single redacted Markdown verdict comment (`<!-- sec-gate-verdict -->`) rather than spamming repeated notes across pipeline reruns.
- **Strict Secret Redaction:** Sanitizes raw tokens, URI credentials, PEM blocks, and sensitive key/value pairs before writing console logs, JSON/Markdown artifacts, or MR/PR comments.

---

## Built-in Scanners

| Plugin | Category | Engine | Highlights |
| --- | --- | --- | --- |
| `kingfisher` | `SECRET` | MongoDB Kingfisher CLI | Live validation (`--no-validate` toggle), confidence thresholds, Git history scope (`none` / `full`), strict redaction |
| `injection` | `INJECTION` | Python `ast` + extension-scoped rules | SQLi (`CWE-89`), CMDi (`CWE-78`/`CWE-94`), XSS (`CWE-79`), inline `sec-gate: ignore` suppression |

---

## Repository Layout

```text
.
├── Containerfile                        # Multi-stage image: Python 3.12 + sec-gate + Kingfisher
├── HOWTO.md                             # End-to-end setup & CI integration guide
├── LICENSE                              # MIT License
├── THIRD_PARTY_NOTICES.md               # Upstream licenses & attributions
├── licenses/                            # Upstream Apache-2.0 license & Kingfisher NOTICE
├── pyproject.toml                       # Root uv workspace + Ruff/Pytest configuration
├── sec-gate.example.yaml                # Reference policy configuration
├── .github/workflows/
│   └── sec-gate.workflow.yml            # Reusable GitHub Actions workflow (`workflow_call`)
├── ci-templates/
│   ├── github/sec-gate.workflow.yml     # Mirror copy for organization template repositories
│   └── gitlab/sec-gate.gitlab-ci.yml    # Reusable GitLab CI template (`include:`)
└── packages/sec-gate/
    ├── pyproject.toml                   # CLI entrypoint & plugin entry points
    ├── src/sec_gate/                    # CLI, config, orchestrator, plugins, reporters
    └── tests/                           # Pytest suite
```

---

## Secret Validation Default & Responsibility Disclaimer

By default, `plugins.kingfisher.validate_secrets` is set to **`false`** (`--no-validate`). This intentional safe default prevents unsolicited outbound authentication probes against third-party APIs when scanning repositories, untrusted fork pull requests, or credentials you may not own or have authorization to test.

- **Offline / Static Blocking:** Because live validation is disabled by default, matched secrets report `validation_status=NOT_ATTEMPTED`. Set `policy.fail_on_unverified_secret: true` (or `SEC_GATE_FAIL_ON_UNVERIFIED_SECRET=true`) if static secret detections should block merges without live validation.
- **Opt-In Live Validation:** Enable `validate_secrets: true` (or `SEC_GATE_KINGFISHER_VALIDATE=true`) only on repositories and pipelines where outbound credential verification is explicitly authorized.
- **Disclaimer:** With `validate_secrets` set to `false` (and given the inherent limitations of static pattern/entropy detection), any unblocked, unverified, or undetected secret exposure or resulting secret leakage is solely the responsibility of the consuming repository owner and operator—not `security-gate-ci` or its contributors.

---

## Quick Start

```bash
# 1. Install dependencies locally with uv (Python 3.12+)
uv sync --python 3.12

# 2. Inspect registered plugins
uv run sec-gate list-plugins

# 3. Run a non-blocking local scan
uv run sec-gate run . --mode warn --no-comment
```

For full container build instructions, GitLab CI `include:` templates, GitHub `workflow_call` setup, and custom plugin authoring, see **[HOWTO.md](HOWTO.md)**.

---

## License & Credits

- Licensed under the **MIT License** — see [LICENSE](LICENSE).
- Secret scanning leverages **[MongoDB Kingfisher](https://github.com/mongodb/kingfisher)** (`Apache-2.0`), copyrighted by MongoDB, Inc. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for complete third-party attributions and Apache-2.0 compliance notices.
