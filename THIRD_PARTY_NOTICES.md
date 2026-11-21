# Third-Party Notices and Attributions

`security-gate-ci` (`sec-gate`) is licensed under the **MIT License** (see [LICENSE](LICENSE)).
This repository and the container image built from [Containerfile](Containerfile) integrate or depend on the third-party software listed below.

---

## 1. Bundled External Security Tools & Build Containers

### MongoDB Kingfisher
- **Project:** https://github.com/mongodb/kingfisher
- **Container Source:** `ghcr.io/mongodb/kingfisher`
- **Copyright:** MongoDB, Inc. and contributors
- **License:** Apache License, Version 2.0 (`Apache-2.0`)
- **Integration & Compliance Notes:**
  - The Python `sec-gate` package wraps the `kingfisher` CLI binary as an external subprocess.
  - [Containerfile](Containerfile) copies `/usr/local/bin/kingfisher` from the official `ghcr.io/mongodb/kingfisher` image into the runtime container image alongside [LICENSE](LICENSE), this notice file, [licenses/APACHE-2.0.txt](licenses/APACHE-2.0.txt), and [licenses/KINGFISHER-NOTICE.txt](licenses/KINGFISHER-NOTICE.txt) under `/usr/share/licenses/sec-gate/`.
  - Including [licenses/APACHE-2.0.txt](licenses/APACHE-2.0.txt) and [licenses/KINGFISHER-NOTICE.txt](licenses/KINGFISHER-NOTICE.txt) inside redistributed container images satisfies Sections 4(a) and 4(d) of the Apache License, Version 2.0 for `mongodb/kingfisher` and its upstream attributions (including Praetorian Nosey Parker, Google OSV-SCALIBR / Veles, Betterleaks, and Tokei).
  - **Trademark & Non-Affiliation Disclaimer:** "MongoDB" and "Kingfisher" are trademarks of MongoDB, Inc. This project is an independent integration and is not affiliated with, sponsored by, or endorsed by MongoDB, Inc.

### Astral `uv`
- **Project:** https://github.com/astral-sh/uv
- **Container Source:** `ghcr.io/astral-sh/uv`
- **Copyright:** Astral Software Inc.
- **License:** MIT OR Apache-2.0
- **Integration Notes:** Used in the `Containerfile` builder stage and local development workflows to resolve and install Python dependencies deterministically from `uv.lock`.

---

## 2. Python Runtime & Development Dependencies

### Direct Runtime Dependencies (`packages/sec-gate/pyproject.toml`)
| Package | Purpose | License |
| --- | --- | --- |
| `pydantic` (`pydantic-core`) | Schema validation and settings models | MIT |
| `typer` (`rich`, `shellingham`) | CLI commands and options | MIT |
| `httpx` (`httpcore`, `idna`) | GitLab/GitHub API client | BSD-3-Clause |
| `PyYAML` | `sec-gate.yaml` policy parsing | MIT |

### Transitive Runtime & Build/Dev Dependencies
| Package | Category | License |
| --- | --- | --- |
| `anyio`, `h11` | `httpx` HTTP/async transport stack | MIT |
| `certifi` | Mozilla CA root bundle (used unmodified) | MPL-2.0 |
| `annotated-doc`, `annotated-types`, `markdown-it-py`, `mdurl`, `typing-inspection` | CLI / Pydantic typing & formatting support | MIT |
| `pygments` | Terminal syntax highlighting (`rich` dependency) | BSD-2-Clause |
| `typing-extensions` | Backported typing constructs | PSF-2.0 |
| `hatchling` | Python PEP 517 build backend | MIT |
| `pytest`, `iniconfig`, `pluggy` | Unit test runner (dev only) | MIT |
| `ruff` | Linter & formatter (dev only) | MIT |
| `packaging` | Version/packaging utilities | Apache-2.0 OR BSD-2-Clause |

---

## 3. Base Image & CI Action Components

| Component | Usage | License |
| --- | --- | --- |
| `python:3.12-slim-bookworm` | Container runtime & builder base image | PSF-2.0 (Python) & Debian Free Software Guidelines packages |
| `git` (Debian package) | Invoked by `kingfisher` when scanning Git repositories | GPL-2.0-only (standalone CLI binary) |
| `ca-certificates` | TLS root certificates for API validation & MR/PR reporting | MPL-2.0 / Debian distributable |
| `actions/checkout@v4` | Repository checkout in GitHub reusable workflow | MIT (GitHub, Inc.) |
| `actions/upload-artifact@v4` | Verdict report upload in GitHub reusable workflow | MIT (GitHub, Inc.) |
