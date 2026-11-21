"""Unit tests for MongoDB Kingfisher parser and subprocess plugin wrapper."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from sec_gate.models import FindingCategory, PluginStatus, Severity, ValidationStatus
from sec_gate.plugins.kingfisher import KingfisherPlugin, parse_kingfisher_output


def test_parse_kingfisher_json_array_and_redact_secrets() -> None:
    raw_token = "ghp_FAKE1234567890ABCDEF1234567890abcdef"
    payload = [
        {
            "rule": {"id": "github-pat", "name": "GitHub Personal Access Token"},
            "finding": {
                "fingerprint": "14085685380484734428",
                "confidence": "high",
                "snippet": f"GITHUB_TOKEN={raw_token}",
                "secret": raw_token,
                "location": {"path": "deploy/env.yaml ", "line": 12, "column": 15},
                "validation": {"outcome": "verified_active", "status": "Active Credential"},
                "git_metadata": {"commit_sha": "abc123", "branch": "feature/sec"},
            },
        }
    ]

    findings = parse_kingfisher_output(json.dumps(payload))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.plugin == "kingfisher"
    assert finding.category == FindingCategory.SECRET
    assert finding.rule_id == "github-pat"
    assert finding.rule_name == "GitHub Personal Access Token"
    assert finding.file_path == "deploy/env.yaml"
    assert finding.line == 12
    assert finding.column == 15
    assert finding.fingerprint == "kf:14085685380484734428"
    assert finding.validation_status == ValidationStatus.VERIFIED_ACTIVE
    assert finding.severity == Severity.CRITICAL
    assert finding.is_verified_secret is True
    assert finding.redacted_snippet is not None
    assert "[REDACTED]" in finding.redacted_snippet
    assert raw_token not in finding.redacted_snippet
    assert raw_token not in finding.message
    assert raw_token not in json.dumps(finding.model_dump())


def test_parse_kingfisher_jsonl_and_non_json_log_lines() -> None:
    raw_mongo = "mongodb+srv://admin:SuperSecretPass99@prod.mongodb.net/orders"
    raw_lines = "\n".join(
        [
            "INFO starting kingfisher scan...",
            json.dumps(
                {
                    "finding": {
                        "rule_id": "mongodb-connection-string",
                        "rule_name": "MongoDB Connection URI",
                        "confidence": "medium",
                        "snippet": raw_mongo,
                        "location": {"file": "config/db.json", "line": 4, "start_byte": 40},
                        "validation": {"outcome": "verified_inactive"},
                    }
                }
            ),
            json.dumps(
                {
                    "rule": {"id": "aws-access-key", "name": "AWS Access Key"},
                    "finding": {
                        "confidence": "low",
                        "snippet": "AKIAIOSFODNN7EXAMPLE99",
                        "location": {"path": "scripts/sync.sh", "line": 8},
                        "validation": {"outcome": "not_attempted"},
                    },
                }
            ),
            "",
        ]
    )

    findings = parse_kingfisher_output(raw_lines)

    assert len(findings) == 2

    mongo, aws = findings
    assert mongo.validation_status == ValidationStatus.VERIFIED_INACTIVE
    assert mongo.severity == Severity.MEDIUM
    assert mongo.is_verified_secret is False
    assert "SuperSecretPass99" not in (mongo.redacted_snippet or "")
    assert "[REDACTED]" in (mongo.redacted_snippet or "")

    assert aws.validation_status == ValidationStatus.NOT_ATTEMPTED
    assert aws.severity == Severity.LOW
    assert "AKIAIOSFODNN7EXAMPLE99" not in (aws.redacted_snippet or "")
    assert aws.fingerprint.startswith("kf:")


def test_parse_kingfisher_envelope_and_deduplicates_fingerprints() -> None:
    envelope = {
        "findings": [
            {
                "rule_id": "stripe-secret-key",
                "fingerprint": "dup-1",
                "confidence": "high",
                "location": {"path": "app.py", "line": 3},
                "snippet": "sk_live_TEST1234567890ABCDEF",
                "validation": {"status": "Inconclusive Validation"},
            },
            {
                "rule_id": "stripe-secret-key",
                "fingerprint": "dup-1",
                "confidence": "high",
                "location": {"path": "app.py", "line": 3},
                "snippet": "sk_live_TEST1234567890ABCDEF",
                "validation": {"status": "Inconclusive Validation"},
            },
        ]
    }

    findings = parse_kingfisher_output(json.dumps(envelope))
    assert len(findings) == 1
    assert findings[0].validation_status == ValidationStatus.UNAVAILABLE
    assert findings[0].severity == Severity.HIGH
    assert "sk_live_TEST1234567890ABCDEF" not in (findings[0].redacted_snippet or "")


def test_kingfisher_plugin_build_command() -> None:
    plugin = KingfisherPlugin(
        options={
            "binary": "/usr/local/bin/kingfisher",
            "validate_secrets": False,
            "confidence": "high",
            "git_history": "full",
            "since_commit": "HEAD~1",
            "exclude_paths": ["*.lock", "dist/"],
            "extra_args": ["--threads", "2"],
        }
    )
    cmd = plugin.build_command(Path("/workspace/repo"))
    assert cmd == [
        "/usr/local/bin/kingfisher",
        "scan",
        "/workspace/repo",
        "--format",
        "json",
        "--confidence",
        "high",
        "--git-history",
        "full",
        "--no-validate",
        "--since-commit",
        "HEAD~1",
        "--exclude",
        "*.lock",
        "--exclude",
        "dist/",
        "--threads",
        "2",
    ]


def test_kingfisher_plugin_defaults_to_no_validate() -> None:
    default_plugin = KingfisherPlugin()
    assert default_plugin.options.validate_secrets is False
    default_cmd = default_plugin.build_command(Path("/workspace/repo"))
    assert "--no-validate" in default_cmd

    live_plugin = KingfisherPlugin(options={"validate_secrets": True})
    assert live_plugin.options.validate_secrets is True
    live_cmd = live_plugin.build_command(Path("/workspace/repo"))
    assert "--no-validate" not in live_cmd


def test_kingfisher_plugin_scan_exit_codes(tmp_path: Path) -> None:
    plugin = KingfisherPlugin(options={"binary": "kingfisher"})

    with patch("sec_gate.plugins.kingfisher.shutil.which", return_value="/usr/bin/kingfisher"):
        # Clean exit 0
        with patch(
            "sec_gate.plugins.kingfisher.subprocess.run",
            return_value=subprocess.CompletedProcess(["kingfisher"], 0, stdout="", stderr=""),
        ):
            clean_res = plugin.scan(tmp_path)
            assert clean_res.status == PluginStatus.PASSED
            assert clean_res.findings == []

        # Exit 205 (validated findings)
        validated_json = json.dumps(
            [
                {
                    "rule": {"id": "glpat", "name": "GitLab PAT"},
                    "finding": {
                        "fingerprint": "999",
                        "snippet": "glpat-abcdefghijklmnop",
                        "location": {"path": "ci.yml", "line": 2},
                        "validation": {"outcome": "verified_active"},
                    },
                }
            ]
        )
        with patch(
            "sec_gate.plugins.kingfisher.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["kingfisher"], 205, stdout=validated_json, stderr=""
            ),
        ):
            found_res = plugin.scan(tmp_path)
            assert found_res.status == PluginStatus.FINDINGS
            assert len(found_res.findings) == 1
            assert found_res.findings[0].is_verified_secret is True

        # Exit 3 (no inputs discovered)
        with patch(
            "sec_gate.plugins.kingfisher.subprocess.run",
            return_value=subprocess.CompletedProcess(["kingfisher"], 3, stdout="", stderr=""),
        ):
            empty_res = plugin.scan(tmp_path)
            assert empty_res.status == PluginStatus.PASSED

        # Exit 1 (fatal scan error)
        with patch(
            "sec_gate.plugins.kingfisher.subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["kingfisher"], 1, stdout="", stderr="fatal failure ghp_SecretToken123456"
            ),
        ):
            err_res = plugin.scan(tmp_path)
            assert err_res.status == PluginStatus.ERROR
            assert err_res.error is not None
            assert "ghp_SecretToken123456" not in err_res.error

        # Timeout
        with patch(
            "sec_gate.plugins.kingfisher.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd=["kingfisher"], timeout=5),
        ):
            timeout_res = plugin.scan(tmp_path)
            assert timeout_res.status == PluginStatus.ERROR
            assert "timed out" in (timeout_res.error or "")

        # Missing binary at exec time
        with patch(
            "sec_gate.plugins.kingfisher.subprocess.run",
            side_effect=FileNotFoundError(),
        ):
            missing_res = plugin.scan(tmp_path)
            assert missing_res.status == PluginStatus.ERROR
            assert "not found" in (missing_res.error or "")
