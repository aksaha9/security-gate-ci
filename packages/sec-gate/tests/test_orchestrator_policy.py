"""Unit tests for orchestrator, policy engine, config overrides, and CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from sec_gate.cli import app
from sec_gate.config import PluginConfig, PolicyConfig, SecGateConfig, load_config
from sec_gate.models import (
    EnforcementMode,
    ExecutionMode,
    ExitCode,
    Finding,
    FindingCategory,
    GateStatus,
    PluginResult,
    PluginStatus,
    Severity,
    ValidationStatus,
)
from sec_gate.orchestrator import PolicyEvaluator, ScanOrchestrator
from sec_gate.plugins import BaseScannerPlugin, PluginRegistry

REPO_ROOT = Path(__file__).resolve().parents[3]


def _make_finding(
    *,
    plugin: str = "injection",
    category: FindingCategory = FindingCategory.INJECTION,
    rule_id: str = "INJ-SQLI-001",
    severity: Severity = Severity.HIGH,
    validation: ValidationStatus = ValidationStatus.NOT_ATTEMPTED,
    fingerprint: str = "fp-1",
) -> Finding:
    return Finding(
        plugin=plugin,
        category=category,
        rule_id=rule_id,
        rule_name=rule_id,
        severity=severity,
        file_path="src/app.py",
        line=10,
        fingerprint=fingerprint,
        message="Test finding",
        validation_status=validation,
    )


def test_policy_evaluator_enforce_vs_warn_exit_codes() -> None:
    high_inj = _make_finding(severity=Severity.HIGH, fingerprint="fp-high")
    med_inj = _make_finding(severity=Severity.MEDIUM, rule_id="INJ-LOW", fingerprint="fp-med")
    results = [
        PluginResult(plugin="injection", status=PluginStatus.FINDINGS, findings=[high_inj, med_inj])
    ]

    enforce_verdict = PolicyEvaluator(
        PolicyConfig(mode=EnforcementMode.ENFORCE, fail_on_severity=Severity.HIGH)
    ).evaluate(".", results)
    assert enforce_verdict.status == GateStatus.BLOCK
    assert enforce_verdict.exit_code == ExitCode.BLOCK
    assert len(enforce_verdict.blocking_findings) == 1

    # Findings strictly below threshold pass in enforce mode
    pass_verdict = PolicyEvaluator(
        PolicyConfig(mode=EnforcementMode.ENFORCE, fail_on_severity=Severity.CRITICAL)
    ).evaluate(".", results)
    assert pass_verdict.status == GateStatus.PASS
    assert pass_verdict.exit_code == ExitCode.PASS
    assert pass_verdict.blocking_findings == []

    # Warn mode returns exit code 10 whenever findings exist
    warn_verdict = PolicyEvaluator(
        PolicyConfig(mode=EnforcementMode.WARN, fail_on_severity=Severity.CRITICAL)
    ).evaluate(".", results)
    assert warn_verdict.status == GateStatus.WARN
    assert warn_verdict.exit_code == ExitCode.WARN


def test_policy_evaluator_secret_validation_and_allowlists() -> None:
    verified_secret = _make_finding(
        plugin="kingfisher",
        category=FindingCategory.SECRET,
        rule_id="github-pat",
        severity=Severity.CRITICAL,
        validation=ValidationStatus.VERIFIED_ACTIVE,
        fingerprint="kf:verified",
    )
    unverified_secret = _make_finding(
        plugin="kingfisher",
        category=FindingCategory.SECRET,
        rule_id="generic-key",
        severity=Severity.HIGH,
        validation=ValidationStatus.NOT_ATTEMPTED,
        fingerprint="kf:unverified",
    )
    inactive_secret = _make_finding(
        plugin="kingfisher",
        category=FindingCategory.SECRET,
        rule_id="old-token",
        severity=Severity.MEDIUM,
        validation=ValidationStatus.VERIFIED_INACTIVE,
        fingerprint="kf:inactive",
    )

    res = [
        PluginResult(
            plugin="kingfisher",
            status=PluginStatus.FINDINGS,
            findings=[verified_secret, unverified_secret, inactive_secret],
        )
    ]

    # Default policy blocks only verified active secrets
    verdict = PolicyEvaluator(PolicyConfig()).evaluate(".", res)
    assert verdict.exit_code == ExitCode.BLOCK
    assert [f.fingerprint for f in verdict.blocking_findings] == ["kf:verified"]

    # Allowlisting the verified secret allows the gate to pass
    suppressed = PolicyEvaluator(PolicyConfig(ignore_fingerprints=["kf:verified"])).evaluate(
        ".", res
    )
    assert suppressed.exit_code == ExitCode.PASS
    assert suppressed.total_findings == 2

    # Failing on unverified secrets blocks when configured
    strict = PolicyEvaluator(
        PolicyConfig(fail_on_unverified_secret=True, ignore_rules=["github-pat"])
    ).evaluate(".", res)
    assert strict.exit_code == ExitCode.BLOCK
    assert [f.fingerprint for f in strict.blocking_findings] == ["kf:unverified"]


def test_policy_evaluator_plugin_error_handling() -> None:
    errored = [PluginResult(plugin="kingfisher", status=PluginStatus.ERROR, error="binary missing")]

    block_verdict = PolicyEvaluator(PolicyConfig(fail_on_plugin_error=True)).evaluate(".", errored)
    assert block_verdict.status == GateStatus.BLOCK
    assert block_verdict.exit_code == ExitCode.BLOCK

    pass_verdict = PolicyEvaluator(PolicyConfig(fail_on_plugin_error=False)).evaluate(".", errored)
    assert pass_verdict.status == GateStatus.PASS
    assert pass_verdict.exit_code == ExitCode.PASS


def test_orchestrator_supports_custom_registered_plugins_without_core_changes(
    tmp_path: Path,
) -> None:
    registry = PluginRegistry()

    @registry.register
    class CustomLicensePlugin(BaseScannerPlugin):
        name: ClassVar[str] = "custom-license"
        description: ClassVar[str] = "Checks custom license header"
        category: ClassVar[FindingCategory] = FindingCategory.COMPLIANCE

        def scan(self, target: Path) -> PluginResult:
            expected_header = self.raw_options.get("header", "SPDX")
            return PluginResult(
                plugin=self.name,
                status=PluginStatus.FINDINGS,
                findings=[
                    Finding(
                        plugin=self.name,
                        category=self.category,
                        rule_id="LIC-001",
                        rule_name="Missing Header",
                        severity=Severity.HIGH,
                        file_path=str(target),
                        fingerprint="lic-1",
                        message=f"Missing {expected_header} header",
                    )
                ],
            )

    cfg = SecGateConfig(
        execution_mode=ExecutionMode.PARALLEL,
        plugins={"custom-license": PluginConfig(enabled=True, header="Apache-2.0")},
    )
    verdict = ScanOrchestrator(config=cfg, registry=registry).run(tmp_path)

    assert verdict.exit_code == ExitCode.BLOCK
    assert len(verdict.all_findings) == 1
    assert "Apache-2.0" in verdict.all_findings[0].message


def test_load_example_config_and_env_overrides(tmp_path: Path) -> None:
    example_path = REPO_ROOT / "sec-gate.example.yaml"
    cfg = load_config(
        config_path=example_path,
        env={
            "SEC_GATE_MODE": "warn",
            "SEC_GATE_FAIL_ON_SEVERITY": "critical",
            "SEC_GATE_PLUGINS": "injection",
            "SEC_GATE_POST_COMMENT": "false",
        },
    )
    assert cfg.policy.mode == EnforcementMode.WARN
    assert cfg.policy.fail_on_severity == Severity.CRITICAL
    assert cfg.plugins["injection"].enabled is True
    assert cfg.plugins["kingfisher"].enabled is False
    assert cfg.reporters.post_comment is False

    with pytest.raises(FileNotFoundError):
        load_config(config_path=tmp_path / "missing.yaml")


def test_cli_run_and_list_plugins(tmp_path: Path) -> None:
    runner = CliRunner()

    list_res = runner.invoke(app, ["list-plugins", "--json"])
    assert list_res.exit_code == 0
    plugins_data = json.loads(list_res.stdout)
    names = {item["name"] for item in plugins_data}
    assert {"kingfisher", "injection"}.issubset(names)

    vuln_file = tmp_path / "handler.py"
    vuln_file.write_text(
        'def run(c, x):\n    c.execute(f"SELECT * FROM t WHERE id={x}")\n',
        encoding="utf-8",
    )

    json_report = tmp_path / "out.json"
    md_report = tmp_path / "out.md"

    warn_res = runner.invoke(
        app,
        [
            "run",
            str(tmp_path),
            "--plugin",
            "injection",
            "--mode",
            "warn",
            "--no-comment",
            "--json-out",
            str(json_report),
            "--markdown-out",
            str(md_report),
        ],
    )
    assert warn_res.exit_code == 10
    assert json_report.is_file()
    assert md_report.is_file()
    assert "INJ-SQLI-001" in md_report.read_text(encoding="utf-8")

    enforce_res = runner.invoke(
        app,
        ["run", str(tmp_path), "--plugin", "injection", "--mode", "enforce", "--no-comment"],
    )
    assert enforce_res.exit_code == 1
