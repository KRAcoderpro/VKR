"""Unit tests for Phase 3 scorer and explainer (V2 §6).

All tests build synthetic StaticReport / DynamicReport objects — no APK needed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tls_pineval.models.common import (
    AppInfo,
    AppReaction,
    Confidence,
    HookCategory,
    HookTarget,
    ObfuscationLevel,
    SecurityLevel,
    VerificationResult,
)
from tls_pineval.models.dynamic_report import (
    BypassAttempt,
    DetectionResults,
    DynamicReport,
    Environment,
    MITMCheck,
)
from tls_pineval.models.evaluation import CriterionScore, ScoreComponent
from tls_pineval.models.static_report import (
    NSCResult,
    PinningImpl,
    PinSet,
    ProtectionProfile,
    StaticReport,
)
from tls_pineval.scoring.explainer import generate_recommendations, generate_warnings
from tls_pineval.scoring.scorer import (
    _aggregate,
    _criterion_confidence,
    _low_confidence_warning,
    _scale,
    _score_c1,
    _score_c2,
    _score_c3,
    _score_c3_skipped,
    _score_c4,
    evaluate,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_APK_PATH = Path("samples/test.apk")
_STATIC_PATH = Path("results/static_report.json")


def _app_info() -> AppInfo:
    return AppInfo(
        apk_path=_APK_PATH,
        package_name="com.example.app",
        app_name="Test App",
        version="1.0",
        min_sdk=24,
        target_sdk=34,
    )


def _env() -> Environment:
    return Environment(
        device_id="emulator-5554",
        android_version="14",
        frida_version="16.2.1",
        is_rooted=True,
    )


def _static(
    nsc: NSCResult | None = None,
    impls: list[PinningImpl] | None = None,
    protection: ProtectionProfile | None = None,
    findings=None,
) -> StaticReport:
    return StaticReport(
        app_info=_app_info(),
        nsc=nsc or NSCResult(),
        pinning_implementations=impls or [],
        protection=protection or ProtectionProfile(),
        findings=findings or [],
    )


def _nsc_with_sha256(
    backup: bool = True,
    expiry: str | None = "2027-01-01",
    cleartext: bool = False,
) -> NSCResult:
    return NSCResult(
        found=True,
        pin_sets=[PinSet(
            domain="api.example.com",
            pins=[
                "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" if backup else
                "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            ],
            expiry=expiry,
            has_backup=backup,
        )],
        cleartext_allowed=cleartext,
    )


def _bypass(
    target: HookTarget | None = None,
    verification: VerificationResult = VerificationResult.FAILED,
    script_name: str = "generic_unpinner",
) -> BypassAttempt:
    return BypassAttempt(
        script_name=script_name,
        target=target,
        hook_triggered=True,
        verification=verification,
        verification_method="logcat",
        confidence=Confidence.HIGH,
        duration_ms=1000,
    )


def _dynamic(
    attempts: list[BypassAttempt] | None = None,
    frida_detected: bool = False,
    root_detected: bool = False,
    debugger_detected: bool = False,
    overall_bypass: bool = False,
) -> DynamicReport:
    detection = DetectionResults(
        frida_detected=frida_detected,
        root_detected=root_detected,
        debugger_detected=debugger_detected,
        app_reaction=AppReaction.CRASH if frida_detected else AppReaction.NONE,
    )
    return DynamicReport(
        app_info=_app_info(),
        environment=_env(),
        bypass_attempts=attempts or [],
        detection_results=detection,
        mitm_check=MITMCheck(),
        overall_bypass=overall_bypass,
    )


def _hook_target() -> HookTarget:
    return HookTarget(
        class_name="com.example.ssl.PinningTM",
        method_name="checkServerTrusted",
        category=HookCategory.TRUST_MANAGER,
        overloads=["[Ljava.security.cert.X509Certificate;, java.lang.String"],
        source_file="com/example/ssl/PinningTM.smali",
        confidence=Confidence.HIGH,
    )


# ---------------------------------------------------------------------------
# _scale
# ---------------------------------------------------------------------------

class TestScale:
    def test_high_factor_full(self):
        assert _scale(20, Confidence.HIGH) == 20

    def test_medium_factor_70_pct(self):
        assert _scale(30, Confidence.MEDIUM) == 21  # 30 × 0.7

    def test_low_factor_40_pct(self):
        assert _scale(25, Confidence.LOW) == 10  # 25 × 0.4

    def test_zero_stays_zero(self):
        assert _scale(0, Confidence.HIGH) == 0


# ---------------------------------------------------------------------------
# _criterion_confidence
# ---------------------------------------------------------------------------

class TestCriterionConfidence:
    def _comp(self, pts: int, conf: Confidence) -> ScoreComponent:
        return ScoreComponent(
            check_id="x", check_name="x", points=pts, max_points=100, confidence=conf
        )

    def test_all_high(self):
        comps = [self._comp(10, Confidence.HIGH), self._comp(20, Confidence.HIGH)]
        assert _criterion_confidence(comps) == Confidence.HIGH

    def test_min_of_awarded(self):
        comps = [
            self._comp(20, Confidence.HIGH),
            self._comp(5, Confidence.LOW),
        ]
        assert _criterion_confidence(comps) == Confidence.LOW

    def test_zero_pts_not_counted(self):
        comps = [
            self._comp(20, Confidence.HIGH),
            self._comp(0, Confidence.LOW),  # not awarded — should not lower confidence
        ]
        assert _criterion_confidence(comps) == Confidence.HIGH

    def test_no_awarded_returns_high(self):
        comps = [self._comp(0, Confidence.LOW)]
        assert _criterion_confidence(comps) == Confidence.HIGH

    def test_medium_lower_than_high(self):
        comps = [self._comp(10, Confidence.HIGH), self._comp(5, Confidence.MEDIUM)]
        assert _criterion_confidence(comps) == Confidence.MEDIUM


# ---------------------------------------------------------------------------
# _low_confidence_warning
# ---------------------------------------------------------------------------

class TestLowConfidenceWarning:
    def _comp(self, pts: int, conf: Confidence) -> ScoreComponent:
        return ScoreComponent(
            check_id="x", check_name="x", points=pts, max_points=100, confidence=conf
        )

    def test_no_low_confidence_no_warning(self):
        comps = [self._comp(30, Confidence.HIGH), self._comp(20, Confidence.MEDIUM)]
        assert _low_confidence_warning("C1", comps) is None

    def test_low_majority_triggers_warning(self):
        comps = [
            self._comp(5, Confidence.HIGH),
            self._comp(10, Confidence.LOW),   # 10/15 > 50%
        ]
        result = _low_confidence_warning("C1", comps)
        assert result is not None
        assert "LOW" in result

    def test_low_exactly_half_no_warning(self):
        comps = [self._comp(10, Confidence.HIGH), self._comp(10, Confidence.LOW)]
        assert _low_confidence_warning("C1", comps) is None

    def test_all_zero_no_warning(self):
        comps = [self._comp(0, Confidence.LOW)]
        assert _low_confidence_warning("C1", comps) is None


# ---------------------------------------------------------------------------
# C1 — Implementation Correctness
# ---------------------------------------------------------------------------

class TestScoreC1:
    def test_no_pinning_returns_zero(self):
        c1 = _score_c1(_static())
        assert c1.score == 0
        assert c1.confidence == Confidence.HIGH
        assert c1.criterion_id == 1

    def test_full_nsc_pinning_no_vulnerable(self):
        nsc = _nsc_with_sha256(backup=True, expiry="2027-01-01", cleartext=False)
        s = _static(nsc=nsc, impls=[
            PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                        is_vulnerable=False, confidence=Confidence.HIGH),
        ])
        c1 = _score_c1(s)
        # sha256=20 + backup=15 + expiry=10 + no_cleartext=10 + no_trust_all=20 + no_allow_all=10 = 85
        assert c1.score == 85

    def test_trust_all_triggers_disqualification(self):
        nsc = _nsc_with_sha256()
        s = _static(nsc=nsc, impls=[
            PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                        is_vulnerable=True, confidence=Confidence.HIGH),
        ])
        c1 = _score_c1(s)
        assert c1.score <= 20
        assert "DISQUALIFIED" in c1.summary

    def test_allow_all_hv_triggers_disqualification(self):
        nsc = _nsc_with_sha256()
        s = _static(nsc=nsc, impls=[
            PinningImpl(type=HookCategory.HOSTNAME_VERIFIER, class_name="com.example.HV",
                        is_vulnerable=True, confidence=Confidence.HIGH),
        ])
        c1 = _score_c1(s)
        assert c1.score <= 20

    def test_webview_proceed_triggers_disqualification(self):
        nsc = _nsc_with_sha256()
        s = _static(nsc=nsc, impls=[
            PinningImpl(type=HookCategory.WEBVIEW_SSL, class_name="com.example.WV",
                        is_vulnerable=True, confidence=Confidence.HIGH),
        ])
        c1 = _score_c1(s)
        assert c1.score <= 20

    def test_webview_safe_awards_15_pts(self):
        nsc = _nsc_with_sha256()
        s = _static(nsc=nsc, impls=[
            PinningImpl(type=HookCategory.WEBVIEW_SSL, class_name="com.example.WV",
                        is_vulnerable=False, confidence=Confidence.HIGH),
        ])
        c1 = _score_c1(s)
        comp = next(c for c in c1.components if c.check_id == "c1_webview_ssl")
        assert comp.points == 15

    def test_cleartext_allowed_loses_points(self):
        nsc = _nsc_with_sha256(cleartext=True)
        s = _static(nsc=nsc)
        c1 = _score_c1(s)
        comp = next(c for c in c1.components if c.check_id == "c1_no_cleartext")
        assert comp.points == 0

    def test_no_backup_pin_loses_15_pts(self):
        nsc = _nsc_with_sha256(backup=False)
        s = _static(nsc=nsc)
        c1 = _score_c1(s)
        comp = next(c for c in c1.components if c.check_id == "c1_backup_pin")
        assert comp.points == 0

    def test_no_expiry_loses_10_pts(self):
        nsc = _nsc_with_sha256(expiry=None)
        s = _static(nsc=nsc)
        c1 = _score_c1(s)
        comp = next(c for c in c1.components if c.check_id == "c1_pin_expiry")
        assert comp.points == 0

    def test_weight_is_0_30(self):
        c1 = _score_c1(_static())
        assert c1.weight == pytest.approx(0.30)


# ---------------------------------------------------------------------------
# C2 — Static Bypass Resistance
# ---------------------------------------------------------------------------

class TestScoreC2:
    def test_no_protections_zero_score(self):
        c2 = _score_c2(_static())
        comp_ids = {c.check_id: c.points for c in c2.components}
        assert comp_ids["c2_obfuscation"] == 0
        assert comp_ids["c2_native_code"] == 0
        assert comp_ids["c2_integrity"] == 0
        assert comp_ids["c2_no_hardcoded"] == 15  # no secrets = positive check
        assert comp_ids["c2_root_detection"] == 0

    def test_strong_obfuscation(self):
        prot = ProtectionProfile(obfuscation_level=ObfuscationLevel.STRONG)
        c2 = _score_c2(_static(protection=prot))
        comp = next(c for c in c2.components if c.check_id == "c2_obfuscation")
        assert comp.points == 21  # 30 × 0.7
        assert comp.confidence == Confidence.MEDIUM

    def test_basic_obfuscation(self):
        prot = ProtectionProfile(obfuscation_level=ObfuscationLevel.BASIC)
        c2 = _score_c2(_static(protection=prot))
        comp = next(c for c in c2.components if c.check_id == "c2_obfuscation")
        assert comp.points == 10  # round(15 × 0.7) = round(10.5) = 10 (Python banker's rounding)

    def test_ssl_native_lib_awards_low_pts(self):
        prot = ProtectionProfile(native_libs=["lib/arm64-v8a/libssl_pinning.so"])
        c2 = _score_c2(_static(protection=prot))
        comp = next(c for c in c2.components if c.check_id == "c2_native_code")
        assert comp.points == 10  # 25 × 0.4
        assert comp.confidence == Confidence.LOW

    def test_non_ssl_native_lib_no_pts(self):
        prot = ProtectionProfile(native_libs=["lib/arm64-v8a/libutils.so"])
        c2 = _score_c2(_static(protection=prot))
        comp = next(c for c in c2.components if c.check_id == "c2_native_code")
        assert comp.points == 0

    def test_safetynet_integrity(self):
        prot = ProtectionProfile(integrity_checks=["SafetyNet"])
        c2 = _score_c2(_static(protection=prot))
        comp = next(c for c in c2.components if c.check_id == "c2_integrity")
        assert comp.points == 14  # 20 × 0.7
        assert comp.confidence == Confidence.MEDIUM

    def test_hardcoded_secrets_finding_loses_pts(self):
        from tls_pineval.models.common import Finding, Severity
        findings = [Finding(
            id="S-001", category="secrets",
            description="Hardcoded pin found",
            location="com.example.Net",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            raw_evidence="sha256/XXXX",
        )]
        c2 = _score_c2(_static(findings=findings))
        comp = next(c for c in c2.components if c.check_id == "c2_no_hardcoded")
        assert comp.points == 0

    def test_root_detection_medium_confidence(self):
        prot = ProtectionProfile(root_detection=True)
        c2 = _score_c2(_static(protection=prot))
        comp = next(c for c in c2.components if c.check_id == "c2_root_detection")
        assert comp.points == 7  # 10 × 0.7
        assert comp.confidence == Confidence.MEDIUM

    def test_weight_is_0_25(self):
        assert _score_c2(_static()).weight == pytest.approx(0.25)


# ---------------------------------------------------------------------------
# C3 — Dynamic Bypass Resistance
# ---------------------------------------------------------------------------

class TestScoreC3:
    def test_generic_bypass_failed_35_pts(self):
        dyn = _dynamic(attempts=[_bypass(target=None, verification=VerificationResult.FAILED)])
        c3 = _score_c3(dyn)
        comp = next(c for c in c3.components if c.check_id == "c3_generic_bypass")
        assert comp.points == 35
        assert comp.confidence == Confidence.HIGH

    def test_generic_bypass_inconclusive_medium(self):
        dyn = _dynamic(attempts=[_bypass(target=None, verification=VerificationResult.INCONCLUSIVE)])
        c3 = _score_c3(dyn)
        comp = next(c for c in c3.components if c.check_id == "c3_generic_bypass")
        assert comp.points == _scale(35, Confidence.MEDIUM)
        assert comp.confidence == Confidence.MEDIUM

    def test_generic_bypass_success_zero_pts(self):
        dyn = _dynamic(attempts=[_bypass(target=None, verification=VerificationResult.SUCCESS)])
        c3 = _score_c3(dyn)
        comp = next(c for c in c3.components if c.check_id == "c3_generic_bypass")
        assert comp.points == 0

    def test_targeted_all_failed_25_pts(self):
        ht = _hook_target()
        dyn = _dynamic(attempts=[
            _bypass(target=None, verification=VerificationResult.FAILED),
            _bypass(target=ht, verification=VerificationResult.FAILED, script_name="tm_hook"),
        ])
        c3 = _score_c3(dyn)
        comp = next(c for c in c3.components if c.check_id == "c3_targeted_bypass")
        assert comp.points == 25

    def test_targeted_any_success_zero_pts(self):
        ht = _hook_target()
        dyn = _dynamic(attempts=[
            _bypass(target=None, verification=VerificationResult.FAILED),
            _bypass(target=ht, verification=VerificationResult.SUCCESS, script_name="tm_hook"),
        ])
        c3 = _score_c3(dyn)
        comp = next(c for c in c3.components if c.check_id == "c3_targeted_bypass")
        assert comp.points == 0

    def test_no_targeted_attempts_zero(self):
        dyn = _dynamic(attempts=[_bypass(target=None, verification=VerificationResult.FAILED)])
        c3 = _score_c3(dyn)
        comp = next(c for c in c3.components if c.check_id == "c3_targeted_bypass")
        assert comp.points == 0

    def test_frida_detected_20_pts(self):
        c3 = _score_c3(_dynamic(frida_detected=True))
        comp = next(c for c in c3.components if c.check_id == "c3_frida_detection")
        assert comp.points == 20

    def test_root_detected_10_pts(self):
        c3 = _score_c3(_dynamic(root_detected=True))
        comp = next(c for c in c3.components if c.check_id == "c3_root_detection")
        assert comp.points == 10

    def test_debugger_detected_10_pts(self):
        c3 = _score_c3(_dynamic(debugger_detected=True))
        comp = next(c for c in c3.components if c.check_id == "c3_debugger_detection")
        assert comp.points == 10

    def test_skipped_placeholder(self):
        c3 = _score_c3_skipped()
        assert c3.score == 0
        assert c3.criterion_id == 3
        assert "not performed" in c3.summary.lower() or "excluded" in c3.summary.lower()

    def test_weight_is_0_30(self):
        assert _score_c3(_dynamic()).weight == pytest.approx(0.30)

    def test_max_possible_score(self):
        ht = _hook_target()
        dyn = _dynamic(
            attempts=[
                _bypass(target=None, verification=VerificationResult.FAILED),
                _bypass(target=ht, verification=VerificationResult.FAILED, script_name="tm_hook"),
            ],
            frida_detected=True,
            root_detected=True,
            debugger_detected=True,
        )
        c3 = _score_c3(dyn)
        assert c3.score == 100  # 35 + 25 + 20 + 10 + 10


# ---------------------------------------------------------------------------
# C4 — Comprehensive Protection
# ---------------------------------------------------------------------------

class TestScoreC4:
    def test_no_protection_minimal_score(self):
        c4 = _score_c4(_static())
        assert c4.score == 0

    def test_nsc_plus_programmatic_30_pts(self):
        nsc = _nsc_with_sha256()
        s = _static(nsc=nsc, impls=[
            PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                        is_vulnerable=False, confidence=Confidence.HIGH),
        ])
        c4 = _score_c4(s)
        comp = next(c for c in c4.components if c.check_id == "c4_multiple_methods")
        assert comp.points == 30

    def test_programmatic_only_zero_multi_pts(self):
        s = _static(impls=[
            PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                        is_vulnerable=False, confidence=Confidence.HIGH),
        ])
        c4 = _score_c4(s)
        comp = next(c for c in c4.components if c.check_id == "c4_multiple_methods")
        assert comp.points == 0

    def test_custom_logic_25_pts(self):
        s = _static(impls=[
            PinningImpl(type=HookCategory.CUSTOM, class_name="com.example.CustomPin",
                        is_vulnerable=False, confidence=Confidence.HIGH),
        ])
        c4 = _score_c4(s)
        comp = next(c for c in c4.components if c.check_id == "c4_custom_logic")
        assert comp.points == 25

    def test_native_java_combo_low_confidence(self):
        prot = ProtectionProfile(native_libs=["lib/arm64-v8a/libssl.so"])
        s = _static(protection=prot, impls=[
            PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                        is_vulnerable=False, confidence=Confidence.HIGH),
        ])
        c4 = _score_c4(s)
        comp = next(c for c in c4.components if c.check_id == "c4_native_java")
        assert comp.points == 10  # 25 × 0.4
        assert comp.confidence == Confidence.LOW

    def test_anti_tampering_medium_confidence(self):
        prot = ProtectionProfile(integrity_checks=["Play Integrity"])
        c4 = _score_c4(_static(protection=prot))
        comp = next(c for c in c4.components if c.check_id == "c4_anti_tampering")
        assert comp.points == 14  # 20 × 0.7
        assert comp.confidence == Confidence.MEDIUM

    def test_weight_is_0_15(self):
        assert _score_c4(_static()).weight == pytest.approx(0.15)


# ---------------------------------------------------------------------------
# Aggregation + normalisation
# ---------------------------------------------------------------------------

class TestAggregate:
    def _criteria(self, scores: dict[int, int]) -> list[CriterionScore]:
        weights = {1: 0.30, 2: 0.25, 3: 0.30, 4: 0.15}
        return [
            CriterionScore(criterion_id=i, name=f"C{i}", score=scores[i], weight=weights[i])
            for i in range(1, 5)
        ]

    def test_normal_aggregation(self):
        # 80×0.30 + 60×0.25 + 70×0.30 + 50×0.15 = 24 + 15 + 21 + 7.5 = 67.5
        criteria = self._criteria({1: 80, 2: 60, 3: 70, 4: 50})
        result = _aggregate(criteria, dynamic_skipped=False)
        assert result == pytest.approx(67.5, abs=0.01)

    def test_c3_skipped_normalisation(self):
        # (80×0.30 + 60×0.25 + 50×0.15) / 0.70 = (24 + 15 + 7.5) / 0.70 = 46.5 / 0.70 ≈ 66.43
        criteria = self._criteria({1: 80, 2: 60, 3: 0, 4: 50})
        result = _aggregate(criteria, dynamic_skipped=True)
        assert result == pytest.approx(66.43, abs=0.01)

    def test_all_100_full_score(self):
        criteria = self._criteria({1: 100, 2: 100, 3: 100, 4: 100})
        assert _aggregate(criteria, dynamic_skipped=False) == pytest.approx(100.0)

    def test_all_zero(self):
        criteria = self._criteria({1: 0, 2: 0, 3: 0, 4: 0})
        assert _aggregate(criteria, dynamic_skipped=False) == 0.0


# ---------------------------------------------------------------------------
# evaluate() — end-to-end
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_static_only_returns_evaluation_result(self):
        s = _static(nsc=_nsc_with_sha256())
        result = evaluate(s, None, static_report_path=_STATIC_PATH)
        assert len(result.criteria) == 4
        assert 0 <= result.final_score <= 100
        assert result.dynamic_report_path is None
        assert result.security_level in list(SecurityLevel)

    def test_dynamic_skipped_warning_present(self):
        result = evaluate(_static(), None, static_report_path=_STATIC_PATH)
        assert any("C3" in w or "dynamic" in w.lower() for w in result.warnings)

    def test_full_pipeline_with_dynamic(self):
        nsc = _nsc_with_sha256()
        s = _static(
            nsc=nsc,
            impls=[PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                               is_vulnerable=False, confidence=Confidence.HIGH)],
            protection=ProtectionProfile(
                obfuscation_level=ObfuscationLevel.BASIC,
                integrity_checks=["SafetyNet"],
                root_detection=True,
            ),
        )
        dyn = _dynamic(
            attempts=[
                _bypass(target=None, verification=VerificationResult.FAILED),
                _bypass(target=_hook_target(), verification=VerificationResult.FAILED,
                        script_name="tm_hook"),
            ],
            frida_detected=True,
            root_detected=True,
        )
        result = evaluate(s, dyn, static_report_path=_STATIC_PATH,
                          dynamic_report_path=Path("results/dynamic_report.json"))
        assert result.final_score > 0
        assert result.dynamic_report_path is not None
        # C3 included
        c3 = next(c for c in result.criteria if c.criterion_id == 3)
        assert c3.score > 0

    def test_security_level_boundaries(self):
        # We can't directly test compute, but we can verify the mapping via scorer internals
        from tls_pineval.scoring.scorer import _security_level
        assert _security_level(85) == SecurityLevel.HIGH
        assert _security_level(84) == SecurityLevel.MEDIUM
        assert _security_level(60) == SecurityLevel.MEDIUM
        assert _security_level(59) == SecurityLevel.LOW
        assert _security_level(30) == SecurityLevel.LOW
        assert _security_level(29) == SecurityLevel.CRITICAL
        assert _security_level(0) == SecurityLevel.CRITICAL

    def test_disqualification_caps_final_score(self):
        nsc = _nsc_with_sha256()
        s = _static(nsc=nsc, impls=[
            PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                        is_vulnerable=True, confidence=Confidence.HIGH),
        ])
        result = evaluate(s, None, static_report_path=_STATIC_PATH)
        c1 = next(c for c in result.criteria if c.criterion_id == 1)
        assert c1.score <= 20


# ---------------------------------------------------------------------------
# Recommendations + warnings
# ---------------------------------------------------------------------------

class TestRecommendations:
    def test_trust_all_generates_recommendation(self):
        s = _static(
            nsc=_nsc_with_sha256(),
            impls=[PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                               is_vulnerable=True, confidence=Confidence.HIGH)],
        )
        c1 = _score_c1(s)
        c2 = _score_c2(s)
        c3 = _score_c3_skipped()
        c4 = _score_c4(s)
        recs = generate_recommendations([c1, c2, c3, c4], s, None)
        assert any("trust-all" in r.lower() or "TrustManager" in r for r in recs)

    def test_no_nsc_generates_nsc_recommendation(self):
        s = _static()  # no pinning
        result = evaluate(s, None, static_report_path=_STATIC_PATH)
        assert any("network_security_config" in r.lower() or "NSC" in r
                   for r in result.recommendations)

    def test_dynamic_skipped_warning(self):
        result = evaluate(_static(), None, static_report_path=_STATIC_PATH)
        assert any("dynamic" in w.lower() for w in result.warnings)

    def test_per_criterion_low_warning_propagated(self):
        prot = ProtectionProfile(
            native_libs=["lib/arm64-v8a/libssl.so"],  # LOW confidence → might trigger warning
        )
        s = _static(nsc=_nsc_with_sha256(), protection=prot, impls=[
            PinningImpl(type=HookCategory.TRUST_MANAGER, class_name="com.example.TM",
                        is_vulnerable=False, confidence=Confidence.HIGH),
        ])
        c2 = _score_c2(s)
        # C2 has native code (LOW, 10 pts) vs others — check if warning fires when majority
        # Build artificial majority-LOW scenario
        from tls_pineval.models.evaluation import ScoreComponent
        comps = [
            ScoreComponent(check_id="a", check_name="a", points=1,
                           max_points=10, confidence=Confidence.HIGH),
            ScoreComponent(check_id="b", check_name="b", points=10,
                           max_points=25, confidence=Confidence.LOW),
        ]
        warn = _low_confidence_warning("C2", comps)
        assert warn is not None  # majority is LOW (10/11)
        warnings = generate_warnings(
            [CriterionScore(criterion_id=2, name="C2", score=11, weight=0.25,
                            components=comps, warning=warn)],
            dynamic_skipped=False,
        )
        assert any("LOW" in w for w in warnings)
