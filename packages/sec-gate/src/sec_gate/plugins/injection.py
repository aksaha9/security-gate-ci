"""Pluggable Injection Vulnerability Checker plugin (SQLi, CMDi, XSS)."""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field

from sec_gate.models import (
    Finding,
    FindingCategory,
    PluginResult,
    PluginStatus,
    Severity,
    redact_secret_text,
)
from sec_gate.plugins.base import BaseScannerPlugin, register_plugin

InjectionCheck = Literal["sqli", "cmdi", "xss"]

_DEFAULT_EXTENSIONS = [
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".sh",
    ".html",
    ".jinja2",
    ".j2",
]

_DEFAULT_EXCLUDES = [
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
]

_SUPPRESSION_MARKER = "sec-gate: ignore"
_SQL_KEYWORDS_RE = re.compile(
    r"\b(select|insert|update|delete|drop|alter|create|union|truncate|merge)\b",
    re.IGNORECASE,
)
_SUBPROCESS_FUNCS = frozenset({"run", "Popen", "call", "check_call", "check_output"})
_SQL_METHODS = frozenset({"execute", "executemany", "raw"})


class InjectionOptions(BaseModel):
    """Configuration options for ``InjectionPlugin``."""

    checks: list[InjectionCheck] = Field(default_factory=lambda: ["sqli", "cmdi", "xss"])
    include_extensions: list[str] = Field(default_factory=lambda: list(_DEFAULT_EXTENSIONS))
    exclude_paths: list[str] = Field(default_factory=lambda: list(_DEFAULT_EXCLUDES))
    max_file_size_kb: int = Field(default=1024, ge=1)


@dataclass(frozen=True)
class _RegexRule:
    rule_id: str
    rule_name: str
    check: InjectionCheck
    severity: Severity
    cwe: str
    extensions: frozenset[str]
    pattern: re.Pattern[str]
    message: str
    remediation: str


_REGEX_RULES: tuple[_RegexRule, ...] = (
    _RegexRule(
        rule_id="INJ-SQLI-002",
        rule_name="Dynamic SQL Template or Concatenation (JS/TS)",
        check="sqli",
        severity=Severity.HIGH,
        cwe="CWE-89",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
        pattern=re.compile(
            r"\.(?:query|execute|raw)\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['\"][^'\"]*['\"]\s*\+)"
        ),
        message="Potential SQL injection via dynamic template literal or string concatenation.",
        remediation="Use parameterized query placeholders instead of interpolating variables.",
    ),
    _RegexRule(
        rule_id="INJ-SQLI-003",
        rule_name="Dynamic SQL Concatenation (Server-Side)",
        check="sqli",
        severity=Severity.HIGH,
        cwe="CWE-89",
        extensions=frozenset({".php", ".rb", ".java", ".go"}),
        pattern=re.compile(
            r"(?:query|executeQuery|execute|prepareStatement|Exec|Query)\s*\(\s*"
            r"(?:['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^'\"]*['\"]\s*[.+]|"
            r"\"[^\"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\$[A-Za-z_]\w*[^\"]*\")",
            re.IGNORECASE,
        ),
        message="Potential SQL injection via dynamic SQL string construction.",
        remediation="Use prepared statements with bound parameters.",
    ),
    _RegexRule(
        rule_id="INJ-CMDI-004",
        rule_name="Dynamic Shell Command Execution (JS/TS)",
        check="cmdi",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
        pattern=re.compile(
            r"\b(?:exec|execSync)\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|['\"][^'\"]*['\"]\s*\+)"
        ),
        message="Dynamic command execution with exec/execSync may allow OS command injection.",
        remediation="Use execFile/spawn with an explicit argument array and shell=false.",
    ),
    _RegexRule(
        rule_id="INJ-CMDI-005",
        rule_name="Dynamic Shell Execution (PHP/Shell)",
        check="cmdi",
        severity=Severity.CRITICAL,
        cwe="CWE-78",
        extensions=frozenset({".php", ".sh"}),
        pattern=re.compile(
            r"(?:\b(?:shell_exec|passthru|system)\s*\([^)]*\$[A-Za-z_]\w*|"
            r"\beval\s+[\"']?\$[A-Za-z_{])"
        ),
        message="Dynamic shell command evaluation with interpolated variables.",
        remediation="Avoid shell evaluation of untrusted inputs; use argument arrays or escaping.",
    ),
    _RegexRule(
        rule_id="INJ-XSS-003",
        rule_name="React dangerouslySetInnerHTML Sink",
        check="xss",
        severity=Severity.HIGH,
        cwe="CWE-79",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
        pattern=re.compile(r"\bdangerouslySetInnerHTML\b"),
        message="Use of dangerouslySetInnerHTML can expose the application to DOM XSS.",
        remediation="Render escaped JSX children or sanitize HTML with DOMPurify first.",
    ),
    _RegexRule(
        rule_id="INJ-XSS-004",
        rule_name="Unsafe DOM innerHTML/outerHTML Assignment",
        check="xss",
        severity=Severity.HIGH,
        cwe="CWE-79",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx"}),
        pattern=re.compile(r"\.(?:innerHTML|outerHTML)\s*="),
        message="Direct assignment to innerHTML/outerHTML may lead to DOM-based XSS.",
        remediation="Use textContent/innerText or sanitize markup with a strict allowlist.",
    ),
    _RegexRule(
        rule_id="INJ-XSS-005",
        rule_name="Unsafe document.write Sink",
        check="xss",
        severity=Severity.HIGH,
        cwe="CWE-79",
        extensions=frozenset({".js", ".ts", ".jsx", ".tsx", ".html"}),
        pattern=re.compile(r"\bdocument\.write(?:ln)?\s*\("),
        message="document.write() with unescaped data can introduce DOM XSS vulnerabilities.",
        remediation="Manipulate DOM nodes safely via textContent or createElement().",
    ),
    _RegexRule(
        rule_id="INJ-XSS-006",
        rule_name="Template Escaping Bypass (| safe)",
        check="xss",
        severity=Severity.HIGH,
        cwe="CWE-79",
        extensions=frozenset({".html", ".jinja2", ".j2"}),
        pattern=re.compile(r"\{\{[^}]*\|\s*safe\b[^}]*\}\}"),
        message="Jinja2/Django `| safe` filter disables automatic HTML escaping.",
        remediation="Remove `| safe` or sanitize HTML server-side with bleach/nh3.",
    ),
    _RegexRule(
        rule_id="INJ-XSS-007",
        rule_name="Disabled Template Autoescape",
        check="xss",
        severity=Severity.HIGH,
        cwe="CWE-79",
        extensions=frozenset({".html", ".jinja2", ".j2"}),
        pattern=re.compile(r"\{%\s*autoescape\s+false\s*%\}", re.IGNORECASE),
        message="Disabling template autoescape exposes rendered variables to XSS.",
        remediation="Keep autoescape enabled for HTML templates.",
    ),
)


def _fingerprint(rule_id: str, rel_path: str, line: int) -> str:
    raw = f"injection|{rule_id}|{rel_path}|{line}"
    return f"inj:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20]}"


def _line_snippet(lines: list[str], line_no: int) -> str | None:
    if 1 <= line_no <= len(lines):
        return redact_secret_text(lines[line_no - 1].strip())
    return None


def _is_suppressed(lines: list[str], line_no: int) -> bool:
    if 1 <= line_no <= len(lines):
        return _SUPPRESSION_MARKER in lines[line_no - 1].lower()
    return False


def _collect_static_fragments(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
        return parts
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return _collect_static_fragments(node.left) + _collect_static_fragments(node.right)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        return _collect_static_fragments(node.func.value)
    return []


def _is_dynamic_string_expr(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(val, ast.FormattedValue) for val in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    )


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _is_constant_literal(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant)


class _PythonInjectionVisitor(ast.NodeVisitor):
    """AST visitor detecting Python SQLi, CMDi, and XSS patterns with low false positives."""

    def __init__(
        self,
        *,
        rel_path: str,
        lines: list[str],
        enabled_checks: set[InjectionCheck],
    ) -> None:
        self.rel_path = rel_path
        self.lines = lines
        self.enabled_checks = enabled_checks
        self.findings: list[Finding] = []
        self._dynamic_sql_vars: set[str] = set()

    def _add_finding(
        self,
        *,
        rule_id: str,
        rule_name: str,
        severity: Severity,
        cwe: str,
        node: ast.AST,
        message: str,
        remediation: str,
    ) -> None:
        line_no = getattr(node, "lineno", 1)
        if _is_suppressed(self.lines, line_no):
            return
        col_no = getattr(node, "col_offset", 0) + 1
        self.findings.append(
            Finding(
                plugin="injection",
                category=FindingCategory.INJECTION,
                rule_id=rule_id,
                rule_name=rule_name,
                severity=severity,
                file_path=self.rel_path,
                line=line_no,
                column=col_no,
                fingerprint=_fingerprint(rule_id, self.rel_path, line_no),
                message=message,
                redacted_snippet=_line_snippet(self.lines, line_no),
                confidence="high",
                cwe=cwe,
                remediation=remediation,
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        if _is_dynamic_string_expr(node.value):
            joined = " ".join(_collect_static_fragments(node.value))
            if _SQL_KEYWORDS_RE.search(joined):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._dynamic_sql_vars.add(target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_sqli(node)
        self._check_cmdi(node)
        self._check_xss(node)
        self.generic_visit(node)

    def _check_sqli(self, node: ast.Call) -> None:
        if "sqli" not in self.enabled_checks:
            return
        if not (isinstance(node.func, ast.Attribute) and node.func.attr in _SQL_METHODS):
            return

        query_arg: ast.AST | None = node.args[0] if node.args else None
        if query_arg is None:
            for kw in node.keywords:
                if kw.arg in {"sql", "query", "statement", "raw_query"}:
                    query_arg = kw.value
                    break
        if query_arg is None:
            return

        is_dynamic_sql = False
        if _is_dynamic_string_expr(query_arg):
            joined = " ".join(_collect_static_fragments(query_arg))
            is_dynamic_sql = bool(_SQL_KEYWORDS_RE.search(joined)) or not joined.strip()
        elif isinstance(query_arg, ast.Name) and query_arg.id in self._dynamic_sql_vars:
            is_dynamic_sql = True

        if is_dynamic_sql:
            self._add_finding(
                rule_id="INJ-SQLI-001",
                rule_name="Dynamic SQL Query Execution",
                severity=Severity.CRITICAL,
                cwe="CWE-89",
                node=node,
                message=(
                    f"Dynamic string interpolation/concatenation passed to .{node.func.attr}()."
                ),
                remediation="Use bound query parameters (e.g. cursor.execute(sql, (param,))).",
            )

    def _check_cmdi(self, node: ast.Call) -> None:
        if "cmdi" not in self.enabled_checks:
            return

        if isinstance(node.func, ast.Attribute) and node.func.attr in _SUBPROCESS_FUNCS:
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if shell_true:
                cmd_arg = node.args[0] if node.args else None
                is_static = cmd_arg is not None and _is_constant_literal(cmd_arg)
                self._add_finding(
                    rule_id="INJ-CMDI-001",
                    rule_name="Subprocess Invocation with shell=True",
                    severity=Severity.MEDIUM if is_static else Severity.CRITICAL,
                    cwe="CWE-78",
                    node=node,
                    message=f"subprocess.{node.func.attr}() called with shell=True.",
                    remediation="Pass an argument list and omit shell=True (shell=False).",
                )
                return

        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr in {"system", "popen"}
        ):
            cmd_arg = node.args[0] if node.args else None
            is_static = cmd_arg is not None and _is_constant_literal(cmd_arg)
            self._add_finding(
                rule_id="INJ-CMDI-002",
                rule_name=f"OS Command Execution via os.{node.func.attr}()",
                severity=Severity.MEDIUM if is_static else Severity.CRITICAL,
                cwe="CWE-78",
                node=node,
                message=f"Use of os.{node.func.attr}() invokes a system shell.",
                remediation="Use subprocess.run([...], shell=False) with validated arguments.",
            )
            return

        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            arg = node.args[0] if node.args else None
            if arg is not None and not _is_constant_literal(arg):
                self._add_finding(
                    rule_id="INJ-CMDI-003",
                    rule_name=f"Dynamic Code Evaluation via {node.func.id}()",
                    severity=Severity.HIGH,
                    cwe="CWE-94",
                    node=node,
                    message=f"Dynamic argument passed to {node.func.id}() allows code injection.",
                    remediation="Replace eval/exec with ast.literal_eval() or explicit dispatch.",
                )

    def _check_xss(self, node: ast.Call) -> None:
        if "xss" not in self.enabled_checks:
            return
        func_name = _call_name(node)
        if func_name in {"mark_safe", "Markup"}:
            arg = node.args[0] if node.args else None
            if arg is not None and not _is_constant_literal(arg):
                self._add_finding(
                    rule_id="INJ-XSS-001",
                    rule_name=f"Unsafe HTML Marking via {func_name}()",
                    severity=Severity.HIGH,
                    cwe="CWE-79",
                    node=node,
                    message=f"Dynamic content marked safe with {func_name}() bypasses escaping.",
                    remediation="Sanitize HTML or rely on template auto-escaping.",
                )
        elif func_name in {"HttpResponse", "HTMLResponse"}:
            arg = node.args[0] if node.args else None
            if arg is not None and _is_dynamic_string_expr(arg):
                fragments = " ".join(_collect_static_fragments(arg))
                if "<" in fragments:
                    self._add_finding(
                        rule_id="INJ-XSS-002",
                        rule_name=f"Unescaped Dynamic HTML in {func_name}()",
                        severity=Severity.HIGH,
                        cwe="CWE-79",
                        node=node,
                        message=f"Dynamically formatted HTML returned via {func_name}().",
                        remediation="Render HTML via an auto-escaping template engine.",
                    )


@register_plugin
class InjectionPlugin(BaseScannerPlugin):
    """Static injection vulnerability scanner supporting Python AST and multi-language rules."""

    name: ClassVar[str] = "injection"
    description: ClassVar[str] = "Static SQLi, Command Injection, and XSS vulnerability analyzer"
    category: ClassVar[FindingCategory] = FindingCategory.INJECTION
    version: ClassVar[str] = "0.1.0"

    def __init__(self, options: dict[str, Any] | None = None) -> None:
        super().__init__(options)
        self.options = InjectionOptions.model_validate(self.raw_options)

    def _is_excluded(self, rel_path: Path) -> bool:
        parts = set(rel_path.parts)
        rel_str = rel_path.as_posix()
        for pattern in self.options.exclude_paths:
            if (
                pattern in parts
                or fnmatch.fnmatch(rel_str, pattern)
                or fnmatch.fnmatch(rel_path.name, pattern)
            ):
                return True
        return False

    def _iter_target_files(self, target: Path) -> list[tuple[Path, str]]:
        allowed_exts = {ext.lower() for ext in self.options.include_extensions}
        if target.is_file():
            if target.suffix.lower() in allowed_exts:
                return [(target, target.name)]
            return []

        collected: list[tuple[Path, str]] = []
        for path in sorted(target.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(target)
            if self._is_excluded(rel):
                continue
            if path.suffix.lower() not in allowed_exts:
                continue
            collected.append((path, rel.as_posix()))
        return collected

    def _scan_python_file(
        self,
        rel_path: str,
        content: str,
        enabled_checks: set[InjectionCheck],
    ) -> list[Finding]:
        try:
            tree = ast.parse(content, filename=rel_path)
        except SyntaxError:
            return []
        visitor = _PythonInjectionVisitor(
            rel_path=rel_path,
            lines=content.splitlines(),
            enabled_checks=enabled_checks,
        )
        visitor.visit(tree)
        return visitor.findings

    def _scan_regex_file(
        self,
        ext: str,
        rel_path: str,
        content: str,
        enabled_checks: set[InjectionCheck],
    ) -> list[Finding]:
        findings: list[Finding] = []
        lines = content.splitlines()
        applicable_rules = [
            rule for rule in _REGEX_RULES if rule.check in enabled_checks and ext in rule.extensions
        ]
        if not applicable_rules:
            return findings

        for line_no, raw_line in enumerate(lines, start=1):
            if _SUPPRESSION_MARKER in raw_line.lower():
                continue
            for rule in applicable_rules:
                match = rule.pattern.search(raw_line)
                if match is None:
                    continue
                findings.append(
                    Finding(
                        plugin=self.name,
                        category=FindingCategory.INJECTION,
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        severity=rule.severity,
                        file_path=rel_path,
                        line=line_no,
                        column=match.start() + 1,
                        fingerprint=_fingerprint(rule.rule_id, rel_path, line_no),
                        message=rule.message,
                        redacted_snippet=redact_secret_text(raw_line.strip()),
                        confidence="medium",
                        cwe=rule.cwe,
                        remediation=rule.remediation,
                    )
                )
        return findings

    def scan(self, target: Path) -> PluginResult:
        """Scan ``target`` for SQLi, Command Injection, and XSS vulnerabilities."""
        start = time.perf_counter()
        if not target.exists():
            return PluginResult(
                plugin=self.name,
                status=PluginStatus.ERROR,
                duration_ms=(time.perf_counter() - start) * 1000,
                error=f"Scan target does not exist: {target}",
            )

        enabled_checks: set[InjectionCheck] = set(self.options.checks)
        max_bytes = self.options.max_file_size_kb * 1024
        files = self._iter_target_files(target)

        findings: list[Finding] = []
        scanned_files = 0
        for file_path, rel_path in files:
            try:
                if file_path.stat().st_size > max_bytes:
                    continue
                content = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            scanned_files += 1
            ext = file_path.suffix.lower()
            if ext == ".py":
                findings.extend(self._scan_python_file(rel_path, content, enabled_checks))
            else:
                findings.extend(self._scan_regex_file(ext, rel_path, content, enabled_checks))

        deduped: list[Finding] = []
        seen: set[str] = set()
        for finding in findings:
            if finding.fingerprint not in seen:
                seen.add(finding.fingerprint)
                deduped.append(finding)

        duration_ms = (time.perf_counter() - start) * 1000
        status = PluginStatus.FINDINGS if deduped else PluginStatus.PASSED
        return PluginResult(
            plugin=self.name,
            status=status,
            findings=deduped,
            duration_ms=duration_ms,
            metadata={"scanned_files": scanned_files, "checks": sorted(enabled_checks)},
        )
