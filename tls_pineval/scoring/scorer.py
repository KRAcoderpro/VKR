"""Scoring engine — evaluates C1–C4 criteria from static/dynamic reports (V2 §6).

Scoring pipeline:
    1. _score_c1  — Implementation Correctness  (weight 0.30)
    2. _score_c2  — Static Bypass Resistance     (weight 0.25)
    3. _score_c3  — Dynamic Bypass Resistance    (weight 0.30)
    4. _score_c4  — Comprehensive Protection     (weight 0.15)
    5. _aggregate — Weighted final score, C3 normalisation when skipped
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from tls_pineval.models.common import (
    Confidence,
    HookCategory,
    ObfuscationLevel,
    SecurityLevel,
    VerificationResult,
)
from tls_pineval.models.dynamic_report import DynamicReport
from tls_pineval.models.evaluation import CriterionScore, EvaluationResult, ScoreComponent
from tls_pineval.models.static_report import StaticReport
from tls_pineval.scoring.explainer import generate_recommendations, generate_warnings

# ---------------------------------------------------------------------------
# Constants (configurable in future via config.yaml)
# ---------------------------------------------------------------------------

_CONFIDENCE_FACTORS: dict[Confidence, float] = {
    Confidence.HIGH: 1.0,
    Confidence.MEDIUM: 0.7,
    Confidence.LOW: 0.4,
}

_WEIGHTS: dict[int, float] = {1: 0.30, 2: 0.25, 3: 0.30, 4: 0.15}

# Confidence ordering for min() (higher = more confident)
_CONF_ORDER: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _scale(base: int, confidence: Confidence) -> int:
    """Apply confidence penalty and round to nearest integer."""
    return round(base * _CONFIDENCE_FACTORS[confidence])


def _criterion_confidence(components: list[ScoreComponent]) -> Confidence:
    """Minimum confidence of all components that awarded > 0 points."""
    awarded = [c.confidence for c in components if c.points > 0]
    if not awarded:
        return Confidence.HIGH
    return min(awarded, key=lambda c: _CONF_ORDER[c])


def _low_confidence_warning(name: str, components: list[ScoreComponent]) -> Optional[str]:
    """Return warning string if >50% of awarded points come from LOW components."""
    total = sum(c.points for c in components)
    if total == 0:
        return None
    low_pts = sum(c.points for c in components if c.confidence == Confidence.LOW)
    if low_pts / total > 0.5:
        return (
            f"C{name}: over 50% of awarded points come from LOW-confidence "
            f"components — score may not be reliable"
        )
    return None


def _security_level(score: float) -> SecurityLevel:
    if score >= 85:
        return SecurityLevel.HIGH
    if score >= 60:
        return SecurityLevel.MEDIUM
    if score >= 30:
        return SecurityLevel.LOW
    return SecurityLevel.CRITICAL


# ---------------------------------------------------------------------------
# C1 — Implementation Correctness (weight 0.30)
# ---------------------------------------------------------------------------

def _score_c1(static: StaticReport) -> CriterionScore:
    nsc = static.nsc
    impls = static.pinning_implementations

    # Pre-check: no pinning detected at all
    has_nsc_pins = bool(nsc.pin_sets)
    has_code_pinning = bool(impls)
    if not has_nsc_pins and not has_code_pinning:
        no_pin = ScoreComponent(
            check_id="c1_no_pinning",
            check_name="TLS pinning detected",
            points=0,
            max_points=100,
            confidence=Confidence.HIGH,
            rationale="No NSC pin-sets and no pinning implementations detected — app uses no TLS pinning",
        )
        return CriterionScore(
            criterion_id=1,
            name="Implementation Correctness",
            score=0,
            weight=_WEIGHTS[1],
            confidence=Confidence.HIGH,
            components=[no_pin],
            summary="No TLS pinning detected",
        )

    components: list[ScoreComponent] = []

    # c1_nsc_sha256 — NSC pin-set with SHA-256 (20 pts)
    sha256_pins = [
        p for ps in nsc.pin_sets for p in ps.pins
        if p.lower().startswith("sha256/") or p.lower().startswith("sha-256/")
    ]
    if sha256_pins:
        components.append(ScoreComponent(
            check_id="c1_nsc_sha256",
            check_name="NSC pin-set with SHA-256",
            points=20,
            max_points=20,
            confidence=Confidence.HIGH,
            rationale=f"SHA-256 key hashing used in {len(nsc.pin_sets)} pin-set(s) — recommended pinning method",
        ))
    else:
        components.append(ScoreComponent(
            check_id="c1_nsc_sha256",
            check_name="NSC pin-set with SHA-256",
            points=0,
            max_points=20,
            confidence=Confidence.HIGH,
            rationale="No NSC pin-set with SHA-256 hashing found",
        ))

    # c1_backup_pin — Backup pin configured (15 pts)
    has_backup = any(ps.has_backup for ps in nsc.pin_sets)
    components.append(ScoreComponent(
        check_id="c1_backup_pin",
        check_name="Backup pin configured",
        points=15 if has_backup else 0,
        max_points=15,
        confidence=Confidence.HIGH,
        rationale=(
            "Backup pin present — certificate rotation will not break the app"
            if has_backup else
            "No backup pin found — certificate rotation may cause app failures"
        ),
    ))

    # c1_pin_expiry — Pin expiry set (10 pts)
    has_expiry = any(ps.expiry is not None for ps in nsc.pin_sets)
    components.append(ScoreComponent(
        check_id="c1_pin_expiry",
        check_name="Pin expiry set",
        points=10 if has_expiry else 0,
        max_points=10,
        confidence=Confidence.HIGH,
        rationale=(
            "Pin expiry date configured — enables key rotation"
            if has_expiry else
            "No pin expiry date set — stale pins risk"
        ),
    ))

    # c1_no_cleartext — No cleartext traffic (10 pts)
    components.append(ScoreComponent(
        check_id="c1_no_cleartext",
        check_name="No cleartext traffic",
        points=0 if nsc.cleartext_allowed else 10,
        max_points=10,
        confidence=Confidence.HIGH,
        rationale=(
            "cleartextTrafficPermitted=true — HTTP traffic bypasses TLS entirely"
            if nsc.cleartext_allowed else
            "Cleartext traffic not permitted"
        ),
    ))

    # c1_no_trust_all — No trust-all TrustManager (20 pts)
    has_trust_all = any(
        i.type == HookCategory.TRUST_MANAGER and i.is_vulnerable
        for i in impls
    )
    components.append(ScoreComponent(
        check_id="c1_no_trust_all",
        check_name="No trust-all TrustManager",
        points=0 if has_trust_all else 20,
        max_points=20,
        confidence=Confidence.HIGH,
        rationale=(
            "Trust-all TrustManager detected — checkServerTrusted returns without validation"
            if has_trust_all else
            "No trust-all TrustManager detected"
        ),
    ))

    # c1_no_allow_all_hv — No allow-all HostnameVerifier (10 pts)
    has_allow_all_hv = any(
        i.type == HookCategory.HOSTNAME_VERIFIER and i.is_vulnerable
        for i in impls
    )
    components.append(ScoreComponent(
        check_id="c1_no_allow_all_hv",
        check_name="No allow-all HostnameVerifier",
        points=0 if has_allow_all_hv else 10,
        max_points=10,
        confidence=Confidence.HIGH,
        rationale=(
            "Allow-all HostnameVerifier detected — verify() returns true without checking hostname"
            if has_allow_all_hv else
            "No allow-all HostnameVerifier detected"
        ),
    ))

    # c1_webview_ssl — WebView SSL errors handled safely (15 pts)
    webview_safe = any(
        i.type == HookCategory.WEBVIEW_SSL and not i.is_vulnerable
        for i in impls
    )
    webview_insecure = any(
        i.type == HookCategory.WEBVIEW_SSL and i.is_vulnerable
        for i in impls
    )
    if webview_safe:
        wv_rationale = "WebView SSL error handler present and does NOT call proceed() — handled safely"
    elif webview_insecure:
        wv_rationale = "WebView SSL error handler calls handler.proceed() — ignores SSL errors"
    else:
        wv_rationale = "No WebView SSL error handler detected — not applicable or missing"
    components.append(ScoreComponent(
        check_id="c1_webview_ssl",
        check_name="WebView SSL errors handled",
        points=15 if webview_safe else 0,
        max_points=15,
        confidence=Confidence.HIGH,
        rationale=wv_rationale,
    ))

    raw_score = sum(c.points for c in components)

    # Disqualification rule (CRITICAL-2): any is_vulnerable → cap at 20
    any_vulnerable = any(i.is_vulnerable for i in impls)
    disqualified = any_vulnerable and raw_score > 20
    if disqualified:
        raw_score = 20
        summary = (
            "DISQUALIFIED: insecure TLS implementation detected — "
            "score capped at 20 regardless of other checks"
        )
    else:
        total_possible = sum(c.max_points for c in components)
        pct = round(raw_score / total_possible * 100) if total_possible else 0
        summary = f"Implementation Correctness: {raw_score}/100 ({pct}% of checks passed)"

    confidence = _criterion_confidence(components)
    warning = _low_confidence_warning("C1", components)

    return CriterionScore(
        criterion_id=1,
        name="Implementation Correctness",
        score=min(raw_score, 100),
        weight=_WEIGHTS[1],
        confidence=confidence,
        components=components,
        summary=summary,
        warning=warning,
    )


# ---------------------------------------------------------------------------
# C2 — Static Bypass Resistance (weight 0.25)
# ---------------------------------------------------------------------------

def _score_c2(static: StaticReport) -> CriterionScore:
    prot = static.protection
    findings = static.findings
    components: list[ScoreComponent] = []

    # c2_obfuscation — Code obfuscation (30 pts, MEDIUM)
    obf = prot.obfuscation_level
    if obf == ObfuscationLevel.STRONG:
        obf_pts = _scale(30, Confidence.MEDIUM)
        obf_rationale = f"Strong obfuscation (likely DexGuard/R8 advanced) — 30 × 0.7 = {obf_pts}"
    elif obf == ObfuscationLevel.BASIC:
        obf_pts = _scale(15, Confidence.MEDIUM)
        obf_rationale = f"Basic obfuscation (ProGuard/R8) — 15 × 0.7 = {obf_pts}"
    else:
        obf_pts = 0
        obf_rationale = "No code obfuscation detected"
    obf_conf = Confidence.MEDIUM if obf != ObfuscationLevel.NONE else Confidence.HIGH
    components.append(ScoreComponent(
        check_id="c2_obfuscation",
        check_name="Code obfuscation",
        points=obf_pts,
        max_points=30,
        confidence=obf_conf,
        rationale=obf_rationale,
    ))

    # c2_native_code — Pinning in native .so (25 pts, LOW)
    ssl_native = [
        lib for lib in prot.native_libs
        if "ssl" in lib.lower() or "tls" in lib.lower()
    ]
    if ssl_native:
        native_pts = _scale(25, Confidence.LOW)
        native_rationale = (
            f"SSL-related native lib(s) found: {', '.join(ssl_native[:3])} — "
            f"25 × 0.4 = {native_pts} (LOW: presence doesn't confirm pinning logic)"
        )
        native_conf = Confidence.LOW
    else:
        native_pts = 0
        native_conf = Confidence.HIGH
        native_rationale = "No SSL-related native libraries found"
    components.append(ScoreComponent(
        check_id="c2_native_code",
        check_name="Pinning logic in native code",
        points=native_pts,
        max_points=25,
        confidence=native_conf,
        rationale=native_rationale,
    ))

    # c2_integrity — APK integrity check (20 pts, MEDIUM)
    if prot.integrity_checks:
        integ_pts = _scale(20, Confidence.MEDIUM)
        integ_rationale = (
            f"{', '.join(prot.integrity_checks)} detected — "
            f"20 × 0.7 = {integ_pts} (MEDIUM: heuristic detection)"
        )
        integ_conf = Confidence.MEDIUM
    else:
        integ_pts = 0
        integ_conf = Confidence.HIGH
        integ_rationale = "No APK integrity checks (SafetyNet / Play Integrity) detected"
    components.append(ScoreComponent(
        check_id="c2_integrity",
        check_name="APK integrity verification",
        points=integ_pts,
        max_points=20,
        confidence=integ_conf,
        rationale=integ_rationale,
    ))

    # c2_no_hardcoded — No hardcoded pins in plaintext (15 pts, HIGH)
    has_hardcoded = any(f.category == "secrets" for f in findings)
    components.append(ScoreComponent(
        check_id="c2_no_hardcoded",
        check_name="No hardcoded pins in plaintext",
        points=0 if has_hardcoded else 15,
        max_points=15,
        confidence=Confidence.HIGH,
        rationale=(
            "Hardcoded pin hashes found in plaintext — trivially extractable by attacker"
            if has_hardcoded else
            "No hardcoded pin hashes in plaintext"
        ),
    ))

    # c2_root_detection — Root/env detection (10 pts, MEDIUM)
    if prot.root_detection:
        root_pts = _scale(10, Confidence.MEDIUM)
        root_rationale = f"Root detection code found — 10 × 0.7 = {root_pts} (MEDIUM: heuristic)"
        root_conf = Confidence.MEDIUM
    else:
        root_pts = 0
        root_conf = Confidence.HIGH
        root_rationale = "No root detection code detected"
    components.append(ScoreComponent(
        check_id="c2_root_detection",
        check_name="Root/environment detection",
        points=root_pts,
        max_points=10,
        confidence=root_conf,
        rationale=root_rationale,
    ))

    score = sum(c.points for c in components)
    confidence = _criterion_confidence(components)
    warning = _low_confidence_warning("C2", components)

    return CriterionScore(
        criterion_id=2,
        name="Static Bypass Resistance",
        score=min(score, 100),
        weight=_WEIGHTS[2],
        confidence=confidence,
        components=components,
        summary=f"Static Bypass Resistance: {score}/100",
        warning=warning,
    )


# ---------------------------------------------------------------------------
# C3 — Dynamic Bypass Resistance (weight 0.30)
# ---------------------------------------------------------------------------

def _score_c3(dynamic: DynamicReport) -> CriterionScore:
    attempts = dynamic.bypass_attempts
    detection = dynamic.detection_results
    components: list[ScoreComponent] = []

    # c3_generic_bypass — Generic bypass (android-unpinner) failed (35 pts)
    generic = next((a for a in attempts if a.target is None), None)
    if generic is None:
        gen_pts = 0
        gen_conf = Confidence.MEDIUM
        gen_rationale = "Generic bypass attempt not recorded"
    elif generic.verification == VerificationResult.FAILED:
        gen_pts = 35
        gen_conf = Confidence.HIGH
        gen_rationale = "android-unpinner generic bypass FAILED — pinning held against universal script"
    elif generic.verification == VerificationResult.INCONCLUSIVE:
        gen_pts = _scale(35, Confidence.MEDIUM)
        gen_conf = Confidence.MEDIUM
        gen_rationale = f"Generic bypass result INCONCLUSIVE — 35 × 0.7 = {gen_pts}"
    else:  # SUCCESS
        gen_pts = 0
        gen_conf = Confidence.HIGH
        gen_rationale = "Generic bypass SUCCEEDED — pinning bypassed by universal script (trivially vulnerable)"
    components.append(ScoreComponent(
        check_id="c3_generic_bypass",
        check_name="Generic bypass (android-unpinner) failed",
        points=gen_pts,
        max_points=35,
        confidence=gen_conf,
        rationale=gen_rationale,
    ))

    # c3_targeted_bypass — Targeted bypass also failed (25 pts)
    targeted = [a for a in attempts if a.target is not None]
    if not targeted:
        tgt_pts = 0
        tgt_conf = Confidence.HIGH
        tgt_rationale = "No targeted bypass attempts (either generic succeeded or no hookable targets)"
    elif any(a.verification == VerificationResult.SUCCESS for a in targeted):
        tgt_pts = 0
        tgt_conf = Confidence.HIGH
        tgt_rationale = "Targeted bypass SUCCEEDED — pinning bypassed with static-analysis-guided hook"
    elif all(a.verification == VerificationResult.FAILED for a in targeted):
        tgt_pts = 25
        tgt_conf = Confidence.HIGH
        tgt_rationale = f"All {len(targeted)} targeted bypass attempt(s) FAILED — strong resistance"
    else:
        tgt_pts = _scale(25, Confidence.MEDIUM)
        tgt_conf = Confidence.MEDIUM
        tgt_rationale = f"Targeted bypass results INCONCLUSIVE — 25 × 0.7 = {tgt_pts}"
    components.append(ScoreComponent(
        check_id="c3_targeted_bypass",
        check_name="Targeted bypass also failed",
        points=tgt_pts,
        max_points=25,
        confidence=tgt_conf,
        rationale=tgt_rationale,
    ))

    # c3_frida_detection — App detects Frida (20 pts)
    components.append(ScoreComponent(
        check_id="c3_frida_detection",
        check_name="App detects Frida",
        points=20 if detection.frida_detected else 0,
        max_points=20,
        confidence=Confidence.HIGH,
        rationale=(
            f"App detected Frida instrumentation (reaction: {detection.app_reaction.value})"
            if detection.frida_detected else
            "App did not detect Frida instrumentation"
        ),
    ))

    # c3_root_detection — App detects root (10 pts)
    components.append(ScoreComponent(
        check_id="c3_root_detection",
        check_name="App detects root",
        points=10 if detection.root_detected else 0,
        max_points=10,
        confidence=Confidence.HIGH,
        rationale=(
            "App detected rooted environment"
            if detection.root_detected else
            "App did not detect rooted environment"
        ),
    ))

    # c3_debugger_detection — App detects debugger (10 pts)
    components.append(ScoreComponent(
        check_id="c3_debugger_detection",
        check_name="App detects debugger",
        points=10 if detection.debugger_detected else 0,
        max_points=10,
        confidence=Confidence.HIGH,
        rationale=(
            "App detected debugger attachment"
            if detection.debugger_detected else
            "No debugger detection observed"
        ),
    ))

    score = sum(c.points for c in components)
    confidence = _criterion_confidence(components)
    warning = _low_confidence_warning("C3", components)

    return CriterionScore(
        criterion_id=3,
        name="Dynamic Bypass Resistance",
        score=min(score, 100),
        weight=_WEIGHTS[3],
        confidence=confidence,
        components=components,
        summary=f"Dynamic Bypass Resistance: {score}/100",
        warning=warning,
    )


def _score_c3_skipped() -> CriterionScore:
    """Placeholder C3 when dynamic analysis was not performed."""
    return CriterionScore(
        criterion_id=3,
        name="Dynamic Bypass Resistance",
        score=0,
        weight=_WEIGHTS[3],
        confidence=Confidence.LOW,
        components=[ScoreComponent(
            check_id="c3_skipped",
            check_name="Dynamic analysis not performed",
            points=0,
            max_points=100,
            confidence=Confidence.LOW,
            rationale="Dynamic analysis was skipped — C3 excluded from weighted average",
        )],
        summary="Dynamic analysis not performed — excluded from scoring",
    )


# ---------------------------------------------------------------------------
# C4 — Comprehensive Protection (weight 0.15)
# ---------------------------------------------------------------------------

def _score_c4(static: StaticReport) -> CriterionScore:
    nsc = static.nsc
    impls = static.pinning_implementations
    prot = static.protection
    components: list[ScoreComponent] = []

    # c4_multiple_methods — NSC + programmatic pinning (30 pts)
    has_nsc_pins = bool(nsc.pin_sets)
    has_programmatic = bool(impls)
    if has_nsc_pins and has_programmatic:
        multi_pts = 30
        multi_rationale = "Both NSC pin-sets and programmatic pinning detected — defense-in-depth"
    else:
        multi_pts = 0
        multi_rationale = (
            "Only one pinning method detected — NSC-only or programmatic-only"
            if (has_nsc_pins or has_programmatic) else
            "No pinning methods detected"
        )
    components.append(ScoreComponent(
        check_id="c4_multiple_methods",
        check_name="Multiple pinning methods (NSC + programmatic)",
        points=multi_pts,
        max_points=30,
        confidence=Confidence.HIGH,
        rationale=multi_rationale,
    ))

    # c4_custom_logic — Custom (non-standard) pinning logic (25 pts)
    has_custom = any(i.type == HookCategory.CUSTOM for i in impls)
    components.append(ScoreComponent(
        check_id="c4_custom_logic",
        check_name="Custom (non-standard) pinning logic",
        points=25 if has_custom else 0,
        max_points=25,
        confidence=Confidence.HIGH,
        rationale=(
            "Custom CUSTOM-category pinning implementation detected — harder to bypass with known scripts"
            if has_custom else
            "No custom pinning logic detected — uses standard APIs only"
        ),
    ))

    # c4_native_java — Native + Java pinning combined (25 pts, LOW)
    ssl_native = [
        lib for lib in prot.native_libs
        if "ssl" in lib.lower() or "tls" in lib.lower()
    ]
    if ssl_native and has_programmatic:
        native_java_pts = _scale(25, Confidence.LOW)
        native_conf = Confidence.LOW
        native_rationale = (
            f"SSL native lib(s) alongside Java pinning — "
            f"25 × 0.4 = {native_java_pts} (LOW: native lib presence ≠ pinning confirmed)"
        )
    else:
        native_java_pts = 0
        native_conf = Confidence.HIGH
        native_rationale = "No native + Java pinning combination detected"
    components.append(ScoreComponent(
        check_id="c4_native_java",
        check_name="Native + Java pinning combined",
        points=native_java_pts,
        max_points=25,
        confidence=native_conf,
        rationale=native_rationale,
    ))

    # c4_anti_tampering — Anti-tampering checks (20 pts, MEDIUM)
    if prot.integrity_checks:
        tamper_pts = _scale(20, Confidence.MEDIUM)
        tamper_conf = Confidence.MEDIUM
        tamper_rationale = (
            f"{', '.join(prot.integrity_checks)} anti-tampering detected — "
            f"20 × 0.7 = {tamper_pts}"
        )
    else:
        tamper_pts = 0
        tamper_conf = Confidence.HIGH
        tamper_rationale = "No anti-tampering checks detected"
    components.append(ScoreComponent(
        check_id="c4_anti_tampering",
        check_name="Anti-tampering checks",
        points=tamper_pts,
        max_points=20,
        confidence=tamper_conf,
        rationale=tamper_rationale,
    ))

    score = sum(c.points for c in components)
    confidence = _criterion_confidence(components)
    warning = _low_confidence_warning("C4", components)

    return CriterionScore(
        criterion_id=4,
        name="Comprehensive Protection",
        score=min(score, 100),
        weight=_WEIGHTS[4],
        confidence=confidence,
        components=components,
        summary=f"Comprehensive Protection: {score}/100",
        warning=warning,
    )


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _aggregate(criteria: list[CriterionScore], dynamic_skipped: bool) -> float:
    """Compute weighted final score with C3 normalisation when skipped."""
    if dynamic_skipped:
        active = [c for c in criteria if c.criterion_id != 3]
        total_weight = sum(c.weight for c in active)
        return round(sum(c.score * c.weight for c in active) / total_weight, 2)
    return round(sum(c.score * c.weight for c in criteria), 2)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def evaluate(
    static_report: StaticReport,
    dynamic_report: Optional[DynamicReport],
    *,
    static_report_path: Path,
    dynamic_report_path: Optional[Path] = None,
) -> EvaluationResult:
    """Evaluate an APK and produce a scored EvaluationResult.

    Args:
        static_report: Completed StaticReport from the static analyzer.
        dynamic_report: DynamicReport from the dynamic analyzer, or None
            if dynamic analysis was skipped.
        static_report_path: Path where the StaticReport JSON was saved.
        dynamic_report_path: Path where the DynamicReport JSON was saved,
            or None if dynamic was skipped.

    Returns:
        EvaluationResult with 4 criterion scores, final score, security level,
        recommendations, and warnings.
    """
    dynamic_skipped = dynamic_report is None

    c1 = _score_c1(static_report)
    c2 = _score_c2(static_report)
    c3 = _score_c3(dynamic_report) if not dynamic_skipped else _score_c3_skipped()
    c4 = _score_c4(static_report)

    criteria = [c1, c2, c3, c4]
    final_score = _aggregate(criteria, dynamic_skipped)
    level = _security_level(final_score)

    recommendations = generate_recommendations(criteria, static_report, dynamic_report)
    warnings = generate_warnings(criteria, dynamic_skipped)

    return EvaluationResult(
        app_info=static_report.app_info,
        criteria=criteria,
        final_score=final_score,
        security_level=level,
        recommendations=recommendations,
        warnings=warnings,
        static_report_path=static_report_path,
        dynamic_report_path=dynamic_report_path,
        timestamp=datetime.now(),
    )
