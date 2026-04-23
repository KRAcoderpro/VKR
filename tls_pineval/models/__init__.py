"""Domain models for TLS-PinEval.

All models use Pydantic v2 and support full JSON serialization/deserialization.

Module structure:
    common         — Enums, AppInfo, Finding (shared across all modules)
    static_report  — StaticReport and sub-models (NSCResult, PinningImpl, etc.)
    dynamic_report — DynamicReport and sub-models (BypassAttempt, DetectionResults, etc.)
    evaluation     — CriterionScore, EvaluationResult, ScoreComponent
"""

from tls_pineval.models.common import (
    AppInfo,
    AppReaction,
    Confidence,
    Finding,
    HookCategory,
    HookTarget,
    MITMStatus,
    ObfuscationLevel,
    SecurityLevel,
    Severity,
    VerificationResult,
)
from tls_pineval.models.dynamic_report import (
    BypassAttempt,
    DetectionResults,
    DynamicReport,
    Environment,
    MITMCheck,
)
from tls_pineval.models.evaluation import (
    CriterionScore,
    EvaluationResult,
    ScoreComponent,
)
from tls_pineval.models.static_report import (
    NSCResult,
    PinningImpl,
    PinSet,
    ProtectionProfile,
    StaticReport,
)

__all__ = [
    # Enums
    "Confidence",
    "Severity",
    "SecurityLevel",
    "HookCategory",
    "AppReaction",
    "VerificationResult",
    "MITMStatus",
    "ObfuscationLevel",
    # Core
    "AppInfo",
    "Finding",
    "HookTarget",
    # Static
    "PinSet",
    "NSCResult",
    "PinningImpl",
    "ProtectionProfile",
    "StaticReport",
    # Dynamic
    "Environment",
    "BypassAttempt",
    "DetectionResults",
    "MITMCheck",
    "DynamicReport",
    # Evaluation
    "ScoreComponent",
    "CriterionScore",
    "EvaluationResult",
]
