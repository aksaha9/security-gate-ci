"""Unit tests for the pluggable Injection Vulnerability Checker plugin."""

from __future__ import annotations

from pathlib import Path

from sec_gate.models import FindingCategory, PluginStatus, Severity
from sec_gate.plugins.injection import InjectionPlugin


def test_python_ast_detects_sqli_cmdi_and_xss(tmp_path: Path) -> None:
    vuln_py = tmp_path / "app.py"
    vuln_py.write_text(
        "\n".join(
            [
                "import os",
                "import subprocess",
                "from markupsafe import Markup",
                "",
                "def get_user(cursor, user_id):",
                '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                '    q = "DELETE FROM sessions WHERE id = " + str(user_id)',
                "    cursor.execute(q)",
                "",
                "def run_cmd(host):",
                '    subprocess.run(f"ping -c 1 {host}", shell=True)',
                '    os.system("ls " + host)',
                "    return eval(host)",
                "",
                "def render_banner(msg):",
                "    return Markup(msg)",
            ]
        ),
        encoding="utf-8",
    )

    plugin = InjectionPlugin()
    result = plugin.scan(tmp_path)

    assert result.status == PluginStatus.FINDINGS
    rule_ids = {f.rule_id for f in result.findings}
    assert "INJ-SQLI-001" in rule_ids
    assert "INJ-CMDI-001" in rule_ids
    assert "INJ-CMDI-002" in rule_ids
    assert "INJ-CMDI-003" in rule_ids
    assert "INJ-XSS-001" in rule_ids
    assert all(f.category == FindingCategory.INJECTION for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_python_ast_allows_safe_parameterized_and_list_subprocess(tmp_path: Path) -> None:
    safe_py = tmp_path / "safe.py"
    safe_py.write_text(
        "\n".join(
            [
                "import ast",
                "import subprocess",
                "",
                "def get_user(cursor, user_id):",
                '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
                "",
                "def run_tool(target):",
                '    subprocess.run(["echo", target], check=False)',
                "",
                "def parse_lit(raw):",
                "    return ast.literal_eval(raw)",
            ]
        ),
        encoding="utf-8",
    )

    plugin = InjectionPlugin()
    result = plugin.scan(tmp_path)

    assert result.status == PluginStatus.PASSED
    assert result.findings == []


def test_multilang_regex_detection_js_html_and_suppression(tmp_path: Path) -> None:
    js_file = tmp_path / "web.tsx"
    js_file.write_text(
        "\n".join(
            [
                "const row = await db.query(`SELECT * FROM items WHERE name = '${input}'`);",
                "exec(`tar -czf out.tgz ${folder}`);",
                "el.innerHTML = userHtml;",
                "const suppressed = document.write(banner); // sec-gate: ignore",
            ]
        ),
        encoding="utf-8",
    )

    html_file = tmp_path / "view.jinja2"
    html_file.write_text("<div>{{ user_bio | safe }}</div>\n", encoding="utf-8")

    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    (ignored_dir / "vendor.js").write_text("el.innerHTML = x;\n", encoding="utf-8")

    plugin = InjectionPlugin()
    result = plugin.scan(tmp_path)

    assert result.status == PluginStatus.FINDINGS
    rule_ids = {f.rule_id for f in result.findings}
    assert "INJ-SQLI-002" in rule_ids
    assert "INJ-CMDI-004" in rule_ids
    assert "INJ-XSS-004" in rule_ids
    assert "INJ-XSS-006" in rule_ids
    assert "INJ-XSS-005" not in rule_ids  # inline suppressed
    assert all("node_modules" not in f.file_path for f in result.findings)


def test_injection_plugin_respects_enabled_checks_filter(tmp_path: Path) -> None:
    sample = tmp_path / "mixed.py"
    sample.write_text(
        "\n".join(
            [
                "import os",
                "def demo(c, x):",
                '    c.execute(f"SELECT * FROM t WHERE x = {x}")',
                '    os.system(f"echo {x}")',
            ]
        ),
        encoding="utf-8",
    )

    sqli_only = InjectionPlugin(options={"checks": ["sqli"]})
    result = sqli_only.scan(tmp_path)

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "INJ-SQLI-001"
