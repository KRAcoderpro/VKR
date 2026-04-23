"""Scoring engine and reporter for TLS-PinEval (V2 §4.4).

Public API:
    evaluate(static_report, dynamic_report, *, static_report_path, dynamic_report_path)
        → EvaluationResult
    generate_report(evaluation, *, output_path) → Path
"""

from tls_pineval.scoring.reporter import generate_report
from tls_pineval.scoring.scorer import evaluate

__all__ = ["evaluate", "generate_report"]
