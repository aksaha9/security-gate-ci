"""Plugin orchestrator and compliance policy evaluator."""

from __future__ import annotations

import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sec_gate.config import PluginConfig, PolicyConfig, SecGateConfig
from sec_gate.models import (
    EnforcementMode,
    ExecutionMode,
    ExitCode,
    Finding,
    FindingCategory,
    GateStatus,
    GateVerdict,
    PluginResult,
    PluginStatus,
    ValidationStatus,
)
from sec_gate.plugins import BaseScannerPlugin, PluginRegistry, default_registry


class PolicyEvaluator:
    """Evaluates normalized findings against ``PolicyConfig`` to produce a ``GateVerdict``."""

    def __init__(self, policy: PolicyConfig) -> None:
        self.policy = policy
        self._ignored_fingerprints = set(policy.ignore_fingerprints)
        self._ignored_rules = set(policy.ignore_rules)

    def filter_findings(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        """Filter allowlisted findings by fingerprint or rule ID."""
        kept: list[Finding] = []
        ignored = 0
        for finding in findings:
            if (
                finding.fingerprint in self._ignored_fingerprints
                or finding.rule_id in self._ignored_rules
            ):
                ignored += 1
                continue
            kept.append(finding)
        return kept, ignored

    def is_blocking_finding(self, finding: Finding) -> bool:
        """Return True if ``finding`` breaches configured enforcement policy."""
        if finding.category == FindingCategory.SECRET:
            if finding.validation_status == ValidationStatus.VERIFIED_ACTIVE:
                return self.policy.fail_on_verified_secret
            if finding.validation_status == ValidationStatus.VERIFIED_INACTIVE:
                return self.policy.fail_on_inactive_secret
            return self.policy.fail_on_unverified_secret

        return finding.severity.meets_threshold(self.policy.fail_on_severity)

    def evaluate(self, target: str, plugin_results: list[PluginResult]) -> GateVerdict:
        """Aggregate plugin results and calculate final gate status and exit code."""
        filtered_results: list[PluginResult] = []
        total_ignored = 0

        for result in plugin_results:
            if result.status in (PluginStatus.PASSED, PluginStatus.FINDINGS):
                kept, ignored = self.filter_findings(result.findings)
                total_ignored += ignored
                updated_status = PluginStatus.FINDINGS if kept else PluginStatus.PASSED
                filtered_results.append(
                    result.model_copy(
                        update={
                            "findings": kept,
                            "status": updated_status,
                            "metadata": {**result.metadata, "ignored_findings": ignored}
                            if ignored
                            else result.metadata,
                        }
                    )
                )
            else:
                filtered_results.append(result)

        all_findings = [f for res in filtered_results for f in res.findings]
        blocking_findings = [f for f in all_findings if self.is_blocking_finding(f)]
        failed_plugins = [res for res in filtered_results if res.status == PluginStatus.ERROR]

        reasons: list[str] = []
        has_plugin_failure = bool(failed_plugins) and self.policy.fail_on_plugin_error

        if self.policy.mode == EnforcementMode.ENFORCE:
            if blocking_findings or has_plugin_failure:
                status = GateStatus.BLOCK
                exit_code = ExitCode.BLOCK
            else:
                status = GateStatus.PASS
                exit_code = ExitCode.PASS
        else:
            if all_findings or has_plugin_failure:
                status = GateStatus.WARN
                exit_code = ExitCode.WARN
            else:
                status = GateStatus.PASS
                exit_code = ExitCode.PASS

        if blocking_findings:
            reasons.append(
                f"{len(blocking_findings)} finding(s) breached enforcement policy "
                f"(fail_on_severity={self.policy.fail_on_severity.value}, "
                f"fail_on_verified_secret={self.policy.fail_on_verified_secret})."
            )
        elif all_findings and self.policy.mode == EnforcementMode.WARN:
            reasons.append(
                f"{len(all_findings)} finding(s) detected in warn mode (non-blocking exit 10)."
            )
        elif all_findings:
            reasons.append(
                f"{len(all_findings)} finding(s) observed below blocking policy thresholds."
            )

        if failed_plugins:
            failed_names = ", ".join(p.plugin for p in failed_plugins)
            if self.policy.fail_on_plugin_error:
                reasons.append(f"Scanner plugin error(s) in: {failed_names}.")
            else:
                reasons.append(f"Non-fatal plugin error(s) ignored in: {failed_names}.")

        if total_ignored:
            reasons.append(f"{total_ignored} allowlisted finding(s) suppressed by policy.")

        if not reasons:
            reasons.append("All enabled security checks passed with zero findings.")

        return GateVerdict(
            status=status,
            exit_code=exit_code,
            mode=self.policy.mode,
            target=target,
            plugin_results=filtered_results,
            blocking_findings=blocking_findings,
            summary_reasons=reasons,
        )


class ScanOrchestrator:
    """Executes enabled scanner plugins and evaluates policy."""

    def __init__(
        self,
        config: SecGateConfig,
        registry: PluginRegistry | None = None,
    ) -> None:
        self.config = config
        self.registry = registry or default_registry

    def _resolve_plan(
        self,
        only_plugins: Sequence[str] | None,
    ) -> list[tuple[str, PluginConfig, bool]]:
        selected = set(only_plugins) if only_plugins else None
        plan: list[tuple[str, PluginConfig, bool]] = []

        for plugin_name, plugin_cfg in self.config.plugins.items():
            should_run = plugin_name in selected if selected is not None else plugin_cfg.enabled
            plan.append((plugin_name, plugin_cfg, should_run))

        if selected is not None:
            known_in_cfg = set(self.config.plugins)
            for plugin_name in sorted(selected - known_in_cfg):
                plan.append((plugin_name, PluginConfig(enabled=True), True))

        return plan

    def _run_single_plugin(
        self,
        plugin_name: str,
        plugin_cfg: PluginConfig,
        target: Path,
    ) -> PluginResult:
        start = time.perf_counter()
        try:
            plugin: BaseScannerPlugin = self.registry.create(
                plugin_name, options=plugin_cfg.extra_options()
            )
        except KeyError as exc:
            return PluginResult(
                plugin=plugin_name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=str(exc),
            )
        except Exception as exc:
            return PluginResult(
                plugin=plugin_name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Invalid configuration for plugin {plugin_name!r}: {exc}",
            )

        available, reason = plugin.is_available()
        if not available:
            return PluginResult(
                plugin=plugin_name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=reason or f"Plugin {plugin_name!r} is unavailable",
            )

        try:
            return plugin.scan(target)
        except Exception as exc:
            return PluginResult(
                plugin=plugin_name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Unhandled error in plugin {plugin_name!r}: {exc}",
            )

    def run(
        self,
        target: Path,
        *,
        only_plugins: Sequence[str] | None = None,
    ) -> GateVerdict:
        """Run planned plugins against ``target`` and return evaluated ``GateVerdict``."""
        plan = self._resolve_plan(only_plugins)
        results_by_index: dict[int, PluginResult] = {}
        active_jobs: list[tuple[int, str, PluginConfig]] = []

        for idx, (plugin_name, plugin_cfg, should_run) in enumerate(plan):
            if not should_run:
                results_by_index[idx] = PluginResult(
                    plugin=plugin_name,
                    status=PluginStatus.SKIPPED,
                    metadata={"reason": "disabled"},
                )
            else:
                active_jobs.append((idx, plugin_name, plugin_cfg))

        if active_jobs:
            if self.config.execution_mode == ExecutionMode.PARALLEL and len(active_jobs) > 1:
                workers = min(self.config.max_workers, len(active_jobs))
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    futures = [
                        (idx, pool.submit(self._run_single_plugin, name, cfg, target))
                        for idx, name, cfg in active_jobs
                    ]
                    for idx, future in futures:
                        results_by_index[idx] = future.result()
            else:
                for idx, name, cfg in active_jobs:
                    results_by_index[idx] = self._run_single_plugin(name, cfg, target)

        ordered_results = [results_by_index[i] for i in range(len(plan))]
        evaluator = PolicyEvaluator(self.config.policy)
        return evaluator.evaluate(target=str(target), plugin_results=ordered_results)
