"""HTML report generator for TLS-PinEval (V2 §4.4).

Renders an EvaluationResult as a fully self-contained HTML report
(CSS embedded) using a Jinja2 template.

Public API:
    generate_report(evaluation, *, output_path) -> Path
"""

from __future__ import annotations

from pathlib import Path

from tls_pineval.models.common import SecurityLevel
from tls_pineval.models.evaluation import EvaluationResult

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"

_LEVEL_COLORS: dict[str, str] = {
    SecurityLevel.HIGH.value:     "#27ae60",
    SecurityLevel.MEDIUM.value:   "#f39c12",
    SecurityLevel.LOW.value:      "#e67e22",
    SecurityLevel.CRITICAL.value: "#c0392b",
}

_CONF_COLORS: dict[str, str] = {
    "HIGH":   "#27ae60",
    "MEDIUM": "#f39c12",
    "LOW":    "#e74c3c",
}


def generate_report(
    evaluation: EvaluationResult,
    *,
    output_path: Path,
) -> Path:
    """Render an HTML report from an EvaluationResult.

    Args:
        evaluation: Completed evaluation produced by the scorer.
        output_path: Where to write the .html file.

    Returns:
        output_path (the generated file).

    Raises:
        ImportError: If Jinja2 is not installed.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Jinja2 is required for report generation. "
            "Install with: pip install jinja2"
        ) from exc

    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Register custom filters
    env.filters["pct"] = lambda v: f"{v:.0f}%"
    env.filters["score_fmt"] = lambda v: f"{v:.1f}"
    env.filters["conf_color"] = lambda c: _CONF_COLORS.get(str(c), "#7f8c8d")

    template = env.get_template("report.html")

    score = evaluation.final_score
    level = evaluation.security_level.value

    html = template.render(
        ev=evaluation,
        score_color=_score_color(score),
        level_color=_LEVEL_COLORS.get(level, "#7f8c8d"),
        generated_at=evaluation.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        dynamic_included=evaluation.dynamic_report_path is not None,
        conf_colors=_CONF_COLORS,
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _score_color(score: float) -> str:
    if score >= 85:
        return _LEVEL_COLORS[SecurityLevel.HIGH.value]
    if score >= 60:
        return _LEVEL_COLORS[SecurityLevel.MEDIUM.value]
    if score >= 30:
        return _LEVEL_COLORS[SecurityLevel.LOW.value]
    return _LEVEL_COLORS[SecurityLevel.CRITICAL.value]
