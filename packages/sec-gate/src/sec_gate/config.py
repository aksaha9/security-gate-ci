"""Pydantic v2 policy configuration loader with YAML and environment overrides."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sec_gate.models import EnforcementMode, ExecutionMode, Severity

DEFAULT_CONFIG_FILENAMES = ("sec-gate.yaml", "sec-gate.yml", ".sec-gate.yaml")


class PluginConfig(BaseModel):
    """Configuration block for an individual plugin.

    Allows arbitrary plugin-specific options so new plugins require zero core
    schema edits.
    """

    model_config = ConfigDict(extra="allow")

    enabled: bool = True

    def extra_options(self) -> dict[str, Any]:
        """Return plugin-specific configuration keys beyond ``enabled``."""
        return dict(self.model_extra or {})


class PolicyConfig(BaseModel):
    """Policy evaluation rules governing exit codes and blocking criteria."""

    mode: EnforcementMode = EnforcementMode.ENFORCE
    fail_on_severity: Severity = Severity.HIGH
    fail_on_verified_secret: bool = True
    fail_on_unverified_secret: bool = False
    fail_on_inactive_secret: bool = False
    fail_on_plugin_error: bool = True
    max_findings_in_comment: int = Field(default=50, ge=1)
    ignore_fingerprints: list[str] = Field(default_factory=list)
    ignore_rules: list[str] = Field(default_factory=list)


class ReporterConfig(BaseModel):
    """Reporter output and MR/PR commenting settings."""

    console: bool = True
    post_comment: bool = True
    comment_marker: str = "<!-- sec-gate-verdict -->"
    json_output: str | None = None
    markdown_output: str | None = None


def _default_plugins() -> dict[str, PluginConfig]:
    return {
        "kingfisher": PluginConfig(enabled=True),
        "injection": PluginConfig(enabled=True),
    }


class SecGateConfig(BaseModel):
    """Root ``sec-gate.yaml`` configuration model."""

    version: str = "1"
    execution_mode: ExecutionMode = ExecutionMode.PARALLEL
    max_workers: int = Field(default=4, ge=1)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    reporters: ReporterConfig = Field(default_factory=ReporterConfig)
    plugins: dict[str, PluginConfig] = Field(default_factory=_default_plugins)


def _parse_bool(raw: str, var_name: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value {raw!r} for environment variable {var_name}")


def _resolve_config_file(
    config_path: Path | None,
    search_dir: Path | None,
) -> Path | None:
    if config_path is not None:
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        return config_path

    base_dir = search_dir or Path.cwd()
    for filename in DEFAULT_CONFIG_FILENAMES:
        candidate = base_dir / filename
        if candidate.is_file():
            return candidate
    return None


def _apply_env_overrides(raw_data: dict[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    data = dict(raw_data)
    policy = dict(data.get("policy") or {})
    reporters = dict(data.get("reporters") or {})
    plugins = {
        name: dict(cfg) if isinstance(cfg, Mapping) else {"enabled": bool(cfg)}
        for name, cfg in (
            data.get("plugins") or {"kingfisher": {"enabled": True}, "injection": {"enabled": True}}
        ).items()
    }

    if mode := env.get("SEC_GATE_MODE"):
        policy["mode"] = mode.strip().lower()
    if exec_mode := env.get("SEC_GATE_EXECUTION_MODE"):
        data["execution_mode"] = exec_mode.strip().lower()
    if severity := env.get("SEC_GATE_FAIL_ON_SEVERITY"):
        policy["fail_on_severity"] = severity.strip().upper()
    if raw_val := env.get("SEC_GATE_FAIL_ON_VERIFIED_SECRET"):
        policy["fail_on_verified_secret"] = _parse_bool(raw_val, "SEC_GATE_FAIL_ON_VERIFIED_SECRET")
    if raw_val := env.get("SEC_GATE_FAIL_ON_UNVERIFIED_SECRET"):
        policy["fail_on_unverified_secret"] = _parse_bool(
            raw_val, "SEC_GATE_FAIL_ON_UNVERIFIED_SECRET"
        )
    if raw_val := env.get("SEC_GATE_FAIL_ON_PLUGIN_ERROR"):
        policy["fail_on_plugin_error"] = _parse_bool(raw_val, "SEC_GATE_FAIL_ON_PLUGIN_ERROR")
    if raw_val := env.get("SEC_GATE_POST_COMMENT"):
        reporters["post_comment"] = _parse_bool(raw_val, "SEC_GATE_POST_COMMENT")
    if json_output := env.get("SEC_GATE_JSON_OUTPUT"):
        reporters["json_output"] = json_output
    if md_output := env.get("SEC_GATE_MARKDOWN_OUTPUT"):
        reporters["markdown_output"] = md_output

    if selected_plugins := env.get("SEC_GATE_PLUGINS"):
        selected = {name.strip() for name in selected_plugins.split(",") if name.strip()}
        for plugin_name in list(plugins):
            plugins[plugin_name]["enabled"] = plugin_name in selected
        for plugin_name in selected:
            plugins.setdefault(plugin_name, {"enabled": True})

    if raw_val := env.get("SEC_GATE_KINGFISHER_VALIDATE"):
        plugins.setdefault("kingfisher", {"enabled": True})["validate_secrets"] = _parse_bool(
            raw_val, "SEC_GATE_KINGFISHER_VALIDATE"
        )
    if confidence := env.get("SEC_GATE_KINGFISHER_CONFIDENCE"):
        plugins.setdefault("kingfisher", {"enabled": True})["confidence"] = (
            confidence.strip().lower()
        )
    if binary := env.get("SEC_GATE_KINGFISHER_BINARY"):
        plugins.setdefault("kingfisher", {"enabled": True})["binary"] = binary.strip()

    data["policy"] = policy
    data["reporters"] = reporters
    data["plugins"] = plugins
    return data


def load_config(
    config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    search_dir: Path | None = None,
) -> SecGateConfig:
    """Load ``SecGateConfig`` from YAML (if present) and apply ``SEC_GATE_*`` env overrides."""
    resolved_env = os.environ if env is None else env
    resolved_path = _resolve_config_file(config_path, search_dir)

    raw_data: dict[str, Any] = {}
    if resolved_path is not None:
        loaded = yaml.safe_load(resolved_path.read_text(encoding="utf-8"))
        if loaded is not None:
            if not isinstance(loaded, dict):
                raise ValueError(
                    f"Expected mapping at root of {resolved_path}, got {type(loaded).__name__}"
                )
            raw_data = loaded

    merged = _apply_env_overrides(raw_data, resolved_env)
    return SecGateConfig.model_validate(merged)
