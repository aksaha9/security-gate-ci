"""Typer CLI entrypoint for `sec-gate`."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer

from sec_gate.config import load_config
from sec_gate.models import EnforcementMode, ExecutionMode, Severity
from sec_gate.orchestrator import ScanOrchestrator
from sec_gate.plugins import default_registry
from sec_gate.reporters import ConsoleReporter, MarkdownFileReporter, detect_ci_reporter

app = typer.Typer(
    name="sec-gate",
    help="Pluggable CI/CD security compliance gate.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def run(
    target: Annotated[
        Path,
        typer.Argument(help="Target directory or file to scan."),
    ] = Path("."),
    config_file: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to sec-gate YAML policy file."),
    ] = None,
    mode: Annotated[
        EnforcementMode | None,
        typer.Option("--mode", "-m", help="Override enforcement mode (enforce or warn)."),
    ] = None,
    fail_on_severity: Annotated[
        Severity | None,
        typer.Option("--fail-on-severity", help="Override minimum blocking severity."),
    ] = None,
    execution_mode: Annotated[
        ExecutionMode | None,
        typer.Option(
            "--execution-mode",
            help="Plugin execution strategy (parallel or sequential).",
        ),
    ] = None,
    plugins: Annotated[
        list[str] | None,
        typer.Option("--plugin", "-p", help="Specific plugin(s) to execute (repeatable)."),
    ] = None,
    no_comment: Annotated[
        bool,
        typer.Option("--no-comment", help="Disable posting MR/PR comments."),
    ] = False,
    json_out: Annotated[
        Path | None,
        typer.Option("--json-out", help="Write full GateVerdict JSON report to file."),
    ] = None,
    markdown_out: Annotated[
        Path | None,
        typer.Option("--markdown-out", help="Write redacted Markdown verdict report to file."),
    ] = None,
    quiet: Annotated[
        bool,
        typer.Option("--quiet", "-q", help="Suppress console summary output."),
    ] = False,
) -> None:
    """Run enabled security plugins, evaluate policy, and enforce exit code."""
    try:
        config = load_config(config_path=config_file)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"[sec-gate] Configuration error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    if mode is not None:
        config.policy.mode = mode
    if fail_on_severity is not None:
        config.policy.fail_on_severity = fail_on_severity
    if execution_mode is not None:
        config.execution_mode = execution_mode
    if no_comment:
        config.reporters.post_comment = False

    orchestrator = ScanOrchestrator(config=config)
    verdict = orchestrator.run(target, only_plugins=plugins)

    if config.reporters.console and not quiet:
        ConsoleReporter(stream=sys.stdout).report(verdict)

    resolved_json_out = json_out or (
        Path(config.reporters.json_output) if config.reporters.json_output else None
    )
    if resolved_json_out is not None:
        resolved_json_out.parent.mkdir(parents=True, exist_ok=True)
        resolved_json_out.write_text(verdict.model_dump_json(indent=2) + "\n", encoding="utf-8")

    resolved_md_out = markdown_out or (
        Path(config.reporters.markdown_output) if config.reporters.markdown_output else None
    )
    if resolved_md_out is not None:
        MarkdownFileReporter(
            resolved_md_out,
            marker=config.reporters.comment_marker,
            max_findings=config.policy.max_findings_in_comment,
        ).report(verdict)

    if config.reporters.post_comment:
        ci_reporter = detect_ci_reporter(
            os.environ,
            marker=config.reporters.comment_marker,
            max_findings=config.policy.max_findings_in_comment,
        )
        if ci_reporter is not None:
            try:
                outcome = ci_reporter.report(verdict)
                if not quiet:
                    typer.echo(
                        f"[sec-gate] Published {ci_reporter.name} comment: {outcome}",
                        err=False,
                    )
            except Exception as exc:
                typer.echo(
                    f"[sec-gate] Warning: failed to publish {ci_reporter.name} comment: {exc}",
                    err=True,
                )

    raise typer.Exit(code=int(verdict.exit_code))


@app.command("list-plugins")
def list_plugins(
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit registered plugin metadata as JSON."),
    ] = False,
) -> None:
    """List registered scanner plugins and their environment availability."""
    rows: list[dict[str, object]] = []
    for plugin_cls in default_registry.list_plugins():
        instance = plugin_cls()
        available, reason = instance.is_available()
        rows.append(
            {
                "name": plugin_cls.name,
                "category": plugin_cls.category.value,
                "version": plugin_cls.version,
                "available": available,
                "reason": reason,
                "description": plugin_cls.description,
            }
        )

    if as_json:
        typer.echo(json.dumps(rows, indent=2))
        return

    for row in rows:
        status = "available" if row["available"] else f"unavailable ({row['reason']})"
        typer.echo(
            f"{row['name']} [{row['category']}] v{row['version']} — {status}\n"
            f"  {row['description']}"
        )


@app.command()
def version() -> None:
    """Print the installed sec-gate version."""
    from sec_gate import __version__

    typer.echo(f"sec-gate {__version__}")
