"""MongoDB Kingfisher subprocess wrapper and JSON/JSONL finding parser."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field

from sec_gate.models import (
    Finding,
    FindingCategory,
    PluginResult,
    PluginStatus,
    Severity,
    ValidationStatus,
    redact_secret_text,
)
from sec_gate.plugins.base import BaseScannerPlugin, register_plugin

_KINGFISHER_CLEAN_EXIT = 0
_KINGFISHER_NO_INPUTS_EXIT = 3
_KINGFISHER_FINDINGS_EXIT = 200
_KINGFISHER_VALIDATED_EXIT = 205

_VALIDATION_MAP: dict[str, ValidationStatus] = {
    "verified_active": ValidationStatus.VERIFIED_ACTIVE,
    "active": ValidationStatus.VERIFIED_ACTIVE,
    "active credential": ValidationStatus.VERIFIED_ACTIVE,
    "valid": ValidationStatus.VERIFIED_ACTIVE,
    "verified_inactive": ValidationStatus.VERIFIED_INACTIVE,
    "inactive": ValidationStatus.VERIFIED_INACTIVE,
    "inactive credential": ValidationStatus.VERIFIED_INACTIVE,
    "revoked": ValidationStatus.VERIFIED_INACTIVE,
    "invalid": ValidationStatus.VERIFIED_INACTIVE,
    "assumed": ValidationStatus.ASSUMED,
    "assumed valid": ValidationStatus.ASSUMED,
    "unavailable": ValidationStatus.UNAVAILABLE,
    "inconclusive": ValidationStatus.UNAVAILABLE,
    "inconclusive validation": ValidationStatus.UNAVAILABLE,
    "not_attempted": ValidationStatus.NOT_ATTEMPTED,
    "not attempted": ValidationStatus.NOT_ATTEMPTED,
    "skipped": ValidationStatus.NOT_ATTEMPTED,
}

_CONFIDENCE_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class KingfisherOptions(BaseModel):
    """Typed options accepted by ``KingfisherPlugin``."""

    binary: str = "kingfisher"
    validate_secrets: bool = False
    confidence: Literal["low", "medium", "high"] = "medium"
    git_history: Literal["none", "full"] = "none"
    since_commit: str | None = None
    exclude_paths: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=300, ge=1)
    extra_args: list[str] = Field(default_factory=list)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _map_validation_status(validation_obj: dict[str, Any]) -> ValidationStatus:
    for key in ("outcome", "status", "state"):
        raw = validation_obj.get(key)
        if isinstance(raw, str):
            normalized = raw.strip().lower()
            if normalized in _VALIDATION_MAP:
                return _VALIDATION_MAP[normalized]
    return ValidationStatus.NOT_ATTEMPTED


def _map_severity(confidence: str | None, validation_status: ValidationStatus) -> Severity:
    if validation_status == ValidationStatus.VERIFIED_ACTIVE:
        return Severity.CRITICAL
    if confidence:
        mapped = _CONFIDENCE_SEVERITY_MAP.get(confidence.strip().lower())
        if mapped is not None:
            return mapped
    return Severity.HIGH


def _extract_raw_records(raw_output: str) -> list[dict[str, Any]]:
    text = raw_output.strip()
    if not text:
        return []

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                if isinstance(item.get("findings"), list):
                    records.extend(el for el in item["findings"] if isinstance(el, dict))
                else:
                    records.append(item)
        return records

    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]
    if isinstance(parsed, dict):
        if isinstance(parsed.get("findings"), list):
            return [item for item in parsed["findings"] if isinstance(item, dict)]
        return [parsed]
    return []


def _normalize_record(record: dict[str, Any]) -> Finding | None:
    finding_obj = _as_dict(record.get("finding")) or record
    rule_obj = _as_dict(record.get("rule")) or _as_dict(finding_obj.get("rule"))
    location_obj = _as_dict(finding_obj.get("location"))
    validation_obj = _as_dict(finding_obj.get("validation")) or _as_dict(record.get("validation"))
    git_meta_obj = _as_dict(finding_obj.get("git_metadata")) or _as_dict(record.get("git_metadata"))

    rule_id = str(
        rule_obj.get("id")
        or finding_obj.get("rule_id")
        or record.get("rule_id")
        or rule_obj.get("rule_id")
        or "kingfisher.unknown"
    )
    rule_name = str(
        rule_obj.get("name") or finding_obj.get("rule_name") or record.get("rule_name") or rule_id
    )

    file_path = str(
        location_obj.get("path")
        or location_obj.get("file")
        or finding_obj.get("path")
        or finding_obj.get("file")
        or finding_obj.get("file_path")
        or "<unknown>"
    ).rstrip()

    line = _as_int(
        location_obj.get("line")
        or location_obj.get("start_line")
        or finding_obj.get("line")
        or finding_obj.get("line_number")
    )
    column = _as_int(
        location_obj.get("column") or location_obj.get("start_column") or finding_obj.get("column")
    )

    raw_confidence = (
        finding_obj.get("confidence") or rule_obj.get("confidence") or record.get("confidence")
    )
    confidence = str(raw_confidence).lower() if isinstance(raw_confidence, str) else None

    validation_status = _map_validation_status(validation_obj)
    severity = _map_severity(confidence, validation_status)

    raw_secret_candidate = (
        finding_obj.get("secret")
        or finding_obj.get("match")
        or finding_obj.get("value")
        or record.get("secret")
    )
    raw_secret = raw_secret_candidate if isinstance(raw_secret_candidate, str) else None

    raw_snippet = (
        finding_obj.get("snippet")
        or finding_obj.get("line_content")
        or record.get("snippet")
        or raw_secret
    )
    snippet_str = raw_snippet if isinstance(raw_snippet, str) else None
    redacted_snippet = redact_secret_text(snippet_str, raw_secret=raw_secret, aggressive=True)

    raw_fingerprint = finding_obj.get("fingerprint") or record.get("fingerprint")
    if raw_fingerprint is not None and str(raw_fingerprint).strip():
        fingerprint = f"kf:{raw_fingerprint}"
    else:
        offset_start = location_obj.get("offset_start") or location_obj.get("start_byte") or ""
        digest_src = f"kingfisher|{rule_id}|{file_path}|{line}|{column}|{offset_start}"
        fingerprint = f"kf:{hashlib.sha256(digest_src.encode('utf-8')).hexdigest()[:20]}"

    validation_note = (
        "verified active credential"
        if validation_status == ValidationStatus.VERIFIED_ACTIVE
        else f"validation: {validation_status.value.lower()}"
    )
    message = f"{rule_name} secret exposure detected in {file_path} ({validation_note})"

    safe_metadata: dict[str, Any] = {
        "origin": finding_obj.get("origin") or record.get("origin"),
        "entropy": finding_obj.get("entropy"),
        "commit_sha": git_meta_obj.get("commit_sha"),
        "branch": git_meta_obj.get("branch"),
    }
    safe_metadata = {k: v for k, v in safe_metadata.items() if v is not None}

    if rule_id == "kingfisher.unknown" and file_path == "<unknown>" and redacted_snippet is None:
        return None

    return Finding(
        plugin="kingfisher",
        category=FindingCategory.SECRET,
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        file_path=file_path,
        line=line,
        column=column,
        fingerprint=fingerprint,
        message=message,
        redacted_snippet=redacted_snippet,
        confidence=confidence,
        validation_status=validation_status,
        cwe="CWE-798",
        remediation="Revoke and rotate the exposed credential, then move it to a secret manager.",
        metadata=safe_metadata,
    )


def parse_kingfisher_output(raw_output: str) -> list[Finding]:
    """Parse Kingfisher JSON or JSONL output into deduplicated, redacted ``Finding`` objects."""
    findings: list[Finding] = []
    seen_fingerprints: set[str] = set()

    for record in _extract_raw_records(raw_output):
        finding = _normalize_record(record)
        if finding is None or finding.fingerprint in seen_fingerprints:
            continue
        seen_fingerprints.add(finding.fingerprint)
        findings.append(finding)

    return findings


@register_plugin
class KingfisherPlugin(BaseScannerPlugin):
    """Secret-scanning plugin wrapping MongoDB Kingfisher CLI."""

    name: ClassVar[str] = "kingfisher"
    description: ClassVar[str] = "MongoDB Kingfisher secret scanner with live validation support"
    category: ClassVar[FindingCategory] = FindingCategory.SECRET
    version: ClassVar[str] = "0.1.0"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options = KingfisherOptions.model_validate(self.raw_options)

    def _resolve_binary(self) -> str | None:
        binary = self.options.binary
        candidate = Path(binary)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return shutil.which(binary)

    def is_available(self) -> tuple[bool, str | None]:
        """Check whether the configured Kingfisher binary is executable."""
        resolved = self._resolve_binary()
        if resolved is None:
            return False, f"Kingfisher binary {self.options.binary!r} not found in PATH"
        return True, None

    def build_command(self, target: Path) -> list[str]:
        """Construct the deterministic ``kingfisher scan`` command line."""
        binary = self._resolve_binary() or self.options.binary
        cmd = [
            binary,
            "scan",
            str(target),
            "--format",
            "json",
            "--confidence",
            self.options.confidence,
            "--git-history",
            self.options.git_history,
        ]
        if not self.options.validate_secrets:
            cmd.append("--no-validate")
        if self.options.since_commit:
            cmd.extend(["--since-commit", self.options.since_commit])
        for pattern in self.options.exclude_paths:
            cmd.extend(["--exclude", pattern])
        cmd.extend(self.options.extra_args)
        return cmd

    def scan(self, target: Path) -> PluginResult:
        """Execute Kingfisher against ``target`` and normalize findings."""
        start = time.perf_counter()
        if not target.exists():
            return PluginResult(
                plugin=self.name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Scan target does not exist: {target}",
            )

        cmd = self.build_command(target)
        try:
            proc = subprocess.run(  # noqa: S603
                cmd,
                capture_output=True,
                text=True,
                timeout=self.options.timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            return PluginResult(
                plugin=self.name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Kingfisher binary {self.options.binary!r} not found",
            )
        except subprocess.TimeoutExpired:
            return PluginResult(
                plugin=self.name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Kingfisher scan timed out after {self.options.timeout_seconds}s",
            )

        duration_ms = (time.perf_counter() - start) * 1000
        if proc.returncode == _KINGFISHER_CLEAN_EXIT:
            findings = parse_kingfisher_output(proc.stdout)
            status = PluginStatus.FINDINGS if findings else PluginStatus.PASSED
            return PluginResult(
                plugin=self.name,
                status=status,
                findings=findings,
                duration_ms=duration_ms,
                metadata={"exit_code": proc.returncode},
            )

        if proc.returncode in (_KINGFISHER_FINDINGS_EXIT, _KINGFISHER_VALIDATED_EXIT):
            findings = parse_kingfisher_output(proc.stdout)
            status = PluginStatus.FINDINGS if findings else PluginStatus.PASSED
            return PluginResult(
                plugin=self.name,
                status=status,
                findings=findings,
                duration_ms=duration_ms,
                metadata={"exit_code": proc.returncode},
            )

        if proc.returncode == _KINGFISHER_NO_INPUTS_EXIT:
            return PluginResult(
                plugin=self.name,
                status=PluginStatus.PASSED,
                findings=[],
                duration_ms=duration_ms,
                metadata={"exit_code": proc.returncode, "note": "No inputs discovered to scan"},
            )

        stderr_preview = redact_secret_text((proc.stderr or proc.stdout).strip()) or "unknown error"
        return PluginResult(
            plugin=self.name,
            status=PluginStatus.ERROR,
            duration_ms=duration_ms,
            error=f"Kingfisher exited with code {proc.returncode}: {stderr_preview[:400]}",
            metadata={"exit_code": proc.returncode},
        )
