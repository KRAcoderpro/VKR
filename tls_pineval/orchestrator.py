"""Pipeline orchestrator for TLS-PinEval (V2 §3).

Ties together the four analysis phases in the fixed execution order:
    Static Analyzer → Dynamic Analyzer → Scorer → Reporter

Each public function corresponds to one CLI command and returns a
completed EvaluationResult plus the path to the HTML report.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Optional

from tls_pineval.config import get as cfg_get
from tls_pineval.dynamic.analyzer import DynamicAnalysisError, analyze as run_dynamic
from tls_pineval.models.dynamic_report import DynamicReport
from tls_pineval.models.evaluation import EvaluationResult
from tls_pineval.models.static_report import StaticReport
from tls_pineval.scoring import evaluate, generate_report
from tls_pineval.static.analyzer import run_static_analysis

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public pipeline functions (one per CLI command)
# ---------------------------------------------------------------------------


def pipeline_static(
    apk_path: Path,
    *,
    output_dir: Path,
    cfg: dict[str, Any] | None = None,
) -> StaticReport:
    """Run static analysis only and return the StaticReport.

    Saves ``static_report.json`` to *output_dir*.
    """
    cfg = cfg or {}
    skip_jadx: bool    = cfg_get(cfg, "analysis", "skip_jadx",    default=False)
    jadx_timeout: int  = cfg_get(cfg, "analysis", "jadx_timeout", default=300)

    logger.info("Phase 1 — Static analysis: %s", apk_path.name)
    t0 = time.perf_counter()
    result = run_static_analysis(
        apk_path, output_dir, skip_jadx=skip_jadx, jadx_timeout=jadx_timeout
    )
    logger.info("Phase 1 done in %.1fs", time.perf_counter() - t0)
    return result


def pipeline_dynamic(
    apk_path: Path,
    static_report: StaticReport,
    *,
    output_dir: Path,
    cfg: dict[str, Any] | None = None,
) -> DynamicReport:
    """Run dynamic analysis on top of an existing StaticReport.

    Saves ``dynamic_report.json`` to *output_dir*.

    Raises:
        DynamicAnalysisError: If the environment is not ready.
    """
    cfg = cfg or {}
    bypass_timeout: int    = cfg_get(cfg, "analysis", "bypass_timeout",    default=15)
    detection_timeout: int = cfg_get(cfg, "analysis", "detection_timeout", default=10)

    logger.info("Phase 2 — Dynamic analysis: %s", static_report.app_info.package_name)
    t0 = time.perf_counter()
    result = run_dynamic(
        apk_path,
        static_report,
        output_dir=output_dir,
        bypass_timeout=bypass_timeout,
        detection_timeout=detection_timeout,
    )
    logger.info("Phase 2 done in %.1fs", time.perf_counter() - t0)
    return result


def pipeline_score(
    static_report: StaticReport,
    dynamic_report: Optional[DynamicReport],
    *,
    output_dir: Path,
    static_report_path: Path,
    dynamic_report_path: Optional[Path] = None,
    cfg: dict[str, Any] | None = None,
) -> tuple[EvaluationResult, Path]:
    """Score existing reports and generate an HTML report.

    Returns:
        Tuple of (EvaluationResult, path-to-HTML).
    """
    logger.info("Phase 3 — Scoring")
    t0 = time.perf_counter()
    evaluation = evaluate(
        static_report,
        dynamic_report,
        static_report_path=static_report_path,
        dynamic_report_path=dynamic_report_path,
    )
    logger.info("Phase 3 done in %.1fs — final score: %.1f (%s)",
                time.perf_counter() - t0,
                evaluation.final_score,
                evaluation.security_level.value)

    logger.info("Phase 4 — Report generation")
    t0 = time.perf_counter()
    report_path = output_dir / "report.html"
    generate_report(evaluation, output_path=report_path)
    logger.info("Phase 4 done in %.1fs", time.perf_counter() - t0)

    return evaluation, report_path


def pipeline_full(
    apk_path: Path,
    *,
    output_dir: Path,
    cfg: dict[str, Any] | None = None,
) -> tuple[EvaluationResult, Path]:
    """Full pipeline: static → dynamic → score → report.

    Dynamic analysis failure is caught and the pipeline continues with
    static-only scoring (a warning is added to the report automatically
    by the scorer when C3 is excluded).

    Returns:
        Tuple of (EvaluationResult, path-to-HTML).
    """
    cfg = cfg or {}
    skip_dynamic: bool = cfg_get(cfg, "analysis", "skip_dynamic", default=False)

    output_dir.mkdir(parents=True, exist_ok=True)
    pipeline_start = time.perf_counter()

    # Phase 1 — Static
    static_report = pipeline_static(apk_path, output_dir=output_dir, cfg=cfg)
    static_report_path = output_dir / "static_report.json"

    # Phase 2 — Dynamic (optional)
    dynamic_report: Optional[DynamicReport] = None
    dynamic_report_path: Optional[Path] = None

    if not skip_dynamic:
        try:
            dynamic_report = pipeline_dynamic(
                apk_path, static_report, output_dir=output_dir, cfg=cfg
            )
            dynamic_report_path = output_dir / "dynamic_report.json"
        except DynamicAnalysisError as exc:
            logger.warning(
                "Dynamic analysis skipped — %s\n"
                "Continuing with static-only scoring (C3 excluded).",
                exc,
            )
        except Exception as exc:
            logger.warning(
                "Dynamic analysis failed unexpectedly: %s\n"
                "Continuing with static-only scoring.",
                exc,
            )

    # Phases 3 & 4 — Score + Report
    result = pipeline_score(
        static_report,
        dynamic_report,
        output_dir=output_dir,
        static_report_path=static_report_path,
        dynamic_report_path=dynamic_report_path,
        cfg=cfg,
    )
    logger.info("Pipeline complete in %.1fs total", time.perf_counter() - pipeline_start)
    return result


def pipeline_score_from_paths(
    static_report_path: Path,
    dynamic_report_path: Optional[Path],
    *,
    output_dir: Path,
    cfg: dict[str, Any] | None = None,
) -> tuple[EvaluationResult, Path]:
    """Load reports from disk, score, and generate HTML report.

    Convenience wrapper for the ``tls-pineval score`` CLI command.
    """
    static_report = StaticReport.model_validate_json(
        static_report_path.read_text(encoding="utf-8")
    )

    dynamic_report: Optional[DynamicReport] = None
    if dynamic_report_path is not None:
        dynamic_report = DynamicReport.model_validate_json(
            dynamic_report_path.read_text(encoding="utf-8")
        )

    return pipeline_score(
        static_report,
        dynamic_report,
        output_dir=output_dir,
        static_report_path=static_report_path,
        dynamic_report_path=dynamic_report_path,
        cfg=cfg,
    )
