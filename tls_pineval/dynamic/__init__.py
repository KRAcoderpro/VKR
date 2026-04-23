"""Dynamic analysis module for TLS-PinEval (V2 §4.3).

Public API:
    analyze(apk_path, static_report, *, output_dir) -> DynamicReport
"""

from tls_pineval.dynamic.analyzer import DynamicAnalysisError, analyze

__all__ = ["analyze", "DynamicAnalysisError"]
