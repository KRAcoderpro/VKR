"""Evaluation and scoring models (V2 §5.5).

Defines:
    ScoreComponent   — A single scored check within a criterion
    CriterionScore   — Score for one of the 4 evaluation criteria
    EvaluationResult — Final evaluation output with all criteria and metadata
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from tls_pineval.models.common import AppInfo, Confidence, SecurityLevel


class ScoreComponent(BaseModel):
    """A single scored check within a criterion (V2 §5.5).

    Each component has a unique ID, descriptive name, awarded points
    (out of a maximum), detection confidence, and a human-readable
    rationale explaining WHY these points were awarded or withheld.
    """

    check_id: str = Field(
        ...,
        description="Unique check identifier, e.g. 'c1_nsc_sha256' or 'c3_generic_bypass'",
    )
    check_name: str = Field(
        ...,
        description="Human-readable check name, e.g. 'NSC pin-set with SHA-256'",
    )
    points: int = Field(
        default=0,
        description="Points awarded for this check (after confidence scaling)",
    )
    max_points: int = Field(
        ...,
        description="Maximum possible points for this check",
    )
    confidence: Confidence = Field(
        default=Confidence.HIGH,
        description="Detection confidence for this check",
    )
    rationale: str = Field(
        default="",
        description=(
            "Human-readable explanation of WHY these points were awarded or withheld. "
            "E.g. 'SHA-256 key hashing detected in NSC — recommended pinning method.'"
        ),
    )


class CriterionScore(BaseModel):
    """Score for one of the 4 evaluation criteria (V2 §5.5).

    Criterion IDs:
        1 — Implementation Correctness (weight 0.30)
        2 — Static Bypass Resistance  (weight 0.25)
        3 — Dynamic Bypass Resistance (weight 0.30)
        4 — Comprehensive Protection  (weight 0.15)

    ``confidence`` is the minimum confidence of any component that awarded
    > 0 points (conservative propagation rule from architecture review).

    ``warning`` is set when > 50% of awarded points come from LOW-confidence
    components, indicating the score may not be reliable.
    """

    criterion_id: int = Field(
        ...,
        ge=1,
        le=4,
        description="Criterion ID: 1 (C1), 2 (C2), 3 (C3), or 4 (C4)",
    )
    name: str = Field(
        ...,
        description="Criterion name, e.g. 'Implementation Correctness'",
    )
    score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Total score for this criterion (0–100)",
    )
    weight: float = Field(
        ...,
        description="Weight of this criterion in the final score (e.g. 0.30)",
    )
    confidence: Confidence = Field(
        default=Confidence.HIGH,
        description=(
            "Overall confidence for this criterion — "
            "min(confidence) of all components that awarded > 0 points"
        ),
    )
    components: list[ScoreComponent] = Field(
        default_factory=list,
        description="Breakdown of individual checks contributing to this score",
    )
    summary: str = Field(
        default="",
        description="One-line human-readable summary of the criterion result",
    )
    warning: Optional[str] = Field(
        default=None,
        description=(
            "Warning message, set if > 50% of awarded points come from "
            "LOW-confidence components"
        ),
    )


class EvaluationResult(BaseModel):
    """Final evaluation output combining all 4 criteria (V2 §5.5).

    Contains the weighted final score, security level classification,
    per-criterion breakdowns, recommendations, and warnings about
    inconclusive or low-confidence results.

    When dynamic analysis is not performed, C3 is excluded from the
    weighted average and weights are normalized (C3 normalization fix).
    """

    app_info: AppInfo
    criteria: list[CriterionScore] = Field(
        ...,
        min_length=4,
        max_length=4,
        description="Exactly 4 criterion scores (C1–C4)",
    )
    final_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Weighted average of all evaluated criteria (0–100)",
    )
    security_level: SecurityLevel = Field(
        default=SecurityLevel.CRITICAL,
        description="Final security level: HIGH, MEDIUM, LOW, or CRITICAL",
    )
    recommendations: list[str] = Field(
        default_factory=list,
        description="Ordered list of improvement recommendations for the developer",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description=(
            "Warnings about inconclusive results, low-confidence scores, "
            "or skipped analysis phases"
        ),
    )
    static_report_path: Path = Field(
        ...,
        description="Path to the saved StaticReport JSON file",
    )
    dynamic_report_path: Optional[Path] = Field(
        default=None,
        description="Path to the saved DynamicReport JSON file, None if dynamic was skipped",
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the evaluation was performed",
    )

    model_config = {"json_encoders": {Path: str}}
