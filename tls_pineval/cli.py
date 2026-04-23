"""Click CLI for TLS-PinEval (V2 §8).

Commands:
    analyze   Full pipeline: static + dynamic + scoring + report
    static    Static analysis only (no device needed)
    dynamic   Dynamic analysis (requires --static-report)
    score     Score and report from existing JSON reports

Usage:
    tls-pineval analyze app.apk -o ./results
    tls-pineval static app.apk -o ./results
    tls-pineval dynamic app.apk --static-report ./results/static_report.json
    tls-pineval score --static ./results/static_report.json
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Optional

import click

from tls_pineval.config import load_config

# Ensure UTF-8 output on Windows terminals that default to a narrow code page
for _stream in ("stdout", "stderr"):
    _s = getattr(sys, _stream, None)
    if _s is not None and hasattr(_s, "reconfigure"):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
from tls_pineval.models.common import SecurityLevel
from tls_pineval.models.evaluation import EvaluationResult
from tls_pineval.models.static_report import StaticReport


# ---------------------------------------------------------------------------
# Terminal output helpers
# ---------------------------------------------------------------------------

_LEVEL_COLOURS = {
    SecurityLevel.HIGH.value:     "green",
    SecurityLevel.MEDIUM.value:   "yellow",
    SecurityLevel.LOW.value:      "red",
    SecurityLevel.CRITICAL.value: "bright_red",
}

_WIDTH = 56


def _sep() -> None:
    click.echo("-" * _WIDTH)


def _bar(score: float, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "#" * filled + "." * (width - filled)


def _print_summary(evaluation: EvaluationResult, report_path: Path) -> None:
    """Print a human-readable result summary to stdout."""
    ai = evaluation.app_info
    level = evaluation.security_level.value
    colour = _LEVEL_COLOURS.get(level, "white")

    _sep()
    click.secho(" TLS-PinEval | Security Assessment", bold=True)
    _sep()
    name = ai.app_name or ai.package_name
    click.echo(f" App:     {name}")
    parts = [ai.package_name]
    if ai.version:
        parts.append(f"v{ai.version}")
    if ai.target_sdk:
        parts.append(f"SDK {ai.target_sdk}")
    click.echo(f" Package: {' | '.join(parts)}")
    _sep()

    score_str = f"{evaluation.final_score:.1f} / 100"
    bar = _bar(evaluation.final_score)
    level_tag = click.style(f" {level} ", fg=colour, bold=True, reverse=True)
    click.echo(f" Score:   {score_str}  [{bar}]  {level_tag}")
    _sep()

    dynamic_included = evaluation.dynamic_report_path is not None
    for c in evaluation.criteria:
        excluded = c.criterion_id == 3 and not dynamic_included
        score_disp = f"--/100 [excluded]" if excluded else f"{c.score:>3}/100"
        pct = f"{int(c.weight * 100)}%"
        click.echo(f"  C{c.criterion_id}  {c.name:<36} {score_disp}  {pct}")

    if evaluation.warnings:
        _sep()
        click.secho(f" Warnings ({len(evaluation.warnings)}):", fg="yellow")
        for w in evaluation.warnings[:3]:
            click.echo(f"   [!]{w[:_WIDTH - 6]}")
        if len(evaluation.warnings) > 3:
            click.echo(f"   … and {len(evaluation.warnings) - 3} more (see report)")

    if evaluation.recommendations:
        _sep()
        click.secho(f" Recommendations ({len(evaluation.recommendations)}):", fg="cyan")
        for i, rec in enumerate(evaluation.recommendations[:3], 1):
            click.echo(f"   {i}. {rec[:_WIDTH - 6]}")
        if len(evaluation.recommendations) > 3:
            click.echo(f"   … and {len(evaluation.recommendations) - 3} more (see report)")

    _sep()
    click.secho(f" Report:  {report_path}", fg="bright_white")
    _sep()


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.option(
    "-o", "--output-dir",
    default="./results",
    show_default=True,
    type=click.Path(),
    help="Directory for all output files.",
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
@click.option(
    "-c", "--config",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to YAML config override file.",
)
@click.version_option(package_name="tls-pineval")
@click.pass_context
def cli(ctx: click.Context, output_dir: str, verbose: bool, config: Optional[str]) -> None:
    """TLS-PinEval — quantitative TLS pinning security assessment for Android APKs."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)-8s %(name)s  %(message)s",
        stream=sys.stderr,
    )
    ctx.ensure_object(dict)
    ctx.obj["output_dir"] = Path(output_dir)
    ctx.obj["cfg"] = load_config(Path(config) if config else None)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--skip-dynamic",
    is_flag=True,
    default=False,
    help="Run static analysis and scoring only (no device required).",
)
@click.option(
    "--skip-jadx",
    is_flag=True,
    default=False,
    help="Skip Jadx Java decompilation (faster, Smali-only).",
)
@click.pass_context
def analyze(ctx: click.Context, apk: str, skip_dynamic: bool, skip_jadx: bool) -> None:
    """Full pipeline: static + dynamic + scoring + HTML report."""
    from tls_pineval.orchestrator import pipeline_full

    output_dir: Path = ctx.obj["output_dir"]
    cfg: dict[str, Any] = ctx.obj["cfg"]

    # CLI flags override config file
    if skip_dynamic:
        cfg.setdefault("analysis", {})["skip_dynamic"] = True
    if skip_jadx:
        cfg.setdefault("analysis", {})["skip_jadx"] = True

    try:
        evaluation, report_path = pipeline_full(
            Path(apk), output_dir=output_dir, cfg=cfg
        )
        _print_summary(evaluation, report_path)
    except FileNotFoundError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
    except Exception as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)


@cli.command(name="static")
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--skip-jadx",
    is_flag=True,
    default=False,
    help="Skip Jadx decompilation.",
)
@click.pass_context
def static_cmd(ctx: click.Context, apk: str, skip_jadx: bool) -> None:
    """Static analysis only — no Android device required."""
    from tls_pineval.orchestrator import pipeline_static

    output_dir: Path = ctx.obj["output_dir"]
    cfg: dict[str, Any] = ctx.obj["cfg"]
    if skip_jadx:
        cfg.setdefault("analysis", {})["skip_jadx"] = True

    try:
        report: StaticReport = pipeline_static(Path(apk), output_dir=output_dir, cfg=cfg)
        ai = report.app_info
        _sep()
        click.secho(" TLS-PinEval  ·  Static Analysis", bold=True)
        _sep()
        click.echo(f" App:     {ai.app_name or ai.package_name}")
        click.echo(f" Package: {ai.package_name}")
        click.echo(f" Findings:         {len(report.findings)}")
        click.echo(f" Pinning impls:    {len(report.pinning_implementations)}")
        click.echo(f" Hookable targets: {len(report.hookable_targets)}")
        click.echo(f" Obfuscation:      {report.protection.obfuscation_level.value}")
        _sep()
        click.secho(f" Report:  {output_dir / 'static_report.json'}", fg="bright_white")
        _sep()
    except FileNotFoundError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
    except Exception as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)


@cli.command(name="dynamic")
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--static-report",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to static_report.json from a previous 'static' run.",
)
@click.pass_context
def dynamic_cmd(ctx: click.Context, apk: str, static_report: str) -> None:
    """Dynamic bypass analysis — requires a connected ADB device with frida-server."""
    from tls_pineval.dynamic.analyzer import DynamicAnalysisError
    from tls_pineval.orchestrator import pipeline_dynamic

    output_dir: Path = ctx.obj["output_dir"]
    cfg: dict[str, Any] = ctx.obj["cfg"]

    try:
        sr = StaticReport.model_validate_json(
            Path(static_report).read_text(encoding="utf-8")
        )
        dr = pipeline_dynamic(Path(apk), sr, output_dir=output_dir, cfg=cfg)
        ai = dr.app_info
        _sep()
        click.secho(" TLS-PinEval  ·  Dynamic Analysis", bold=True)
        _sep()
        click.echo(f" App:             {ai.app_name or ai.package_name}")
        click.echo(f" Device:          {dr.environment.device_id}")
        click.echo(f" Android:         {dr.environment.android_version}")
        click.echo(f" Frida:           {dr.environment.frida_version}")
        click.echo(f" Bypass attempts: {len(dr.bypass_attempts)}")
        overall = click.style("YES", fg="red", bold=True) if dr.overall_bypass else click.style("NO", fg="green", bold=True)
        click.echo(f" Bypass success:  {overall}")
        click.echo(f" Frida detected:  {'YES' if dr.detection_results.frida_detected else 'NO'}")
        _sep()
        click.secho(f" Report:  {output_dir / 'dynamic_report.json'}", fg="bright_white")
        _sep()
    except DynamicAnalysisError as exc:
        click.secho(f"Environment not ready: {exc}", fg="red", err=True)
        sys.exit(1)
    except FileNotFoundError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
    except Exception as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)


@cli.command(name="score")
@click.option(
    "--static",
    "static_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to static_report.json.",
)
@click.option(
    "--dynamic",
    "dynamic_path",
    default=None,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to dynamic_report.json (optional).",
)
@click.pass_context
def score_cmd(
    ctx: click.Context,
    static_path: str,
    dynamic_path: Optional[str],
) -> None:
    """Score from existing report files and generate HTML report."""
    from tls_pineval.orchestrator import pipeline_score_from_paths

    output_dir: Path = ctx.obj["output_dir"]
    cfg: dict[str, Any] = ctx.obj["cfg"]

    try:
        evaluation, report_path = pipeline_score_from_paths(
            Path(static_path),
            Path(dynamic_path) if dynamic_path else None,
            output_dir=output_dir,
            cfg=cfg,
        )
        _print_summary(evaluation, report_path)
    except FileNotFoundError as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
    except Exception as exc:
        click.secho(f"Error: {exc}", fg="red", err=True)
        sys.exit(1)
