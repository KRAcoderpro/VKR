"""Serialization example and validation test for all TLS-PinEval models.

Constructs realistic StaticReport and DynamicReport instances,
serializes them to JSON, deserializes back, and verifies round-trip.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

from tls_pineval.models import (
    AppInfo,
    AppReaction,
    BypassAttempt,
    Confidence,
    CriterionScore,
    DetectionResults,
    DynamicReport,
    Environment,
    EvaluationResult,
    Finding,
    HookCategory,
    HookTarget,
    MITMCheck,
    MITMStatus,
    NSCResult,
    ObfuscationLevel,
    PinningImpl,
    PinSet,
    ProtectionProfile,
    ScoreComponent,
    SecurityLevel,
    Severity,
    StaticReport,
    VerificationResult,
)


def build_static_report() -> StaticReport:
    """Build a realistic StaticReport example."""
    app_info = AppInfo(
        apk_path=Path("samples/com.example.banking.apk"),
        package_name="com.example.banking",
        app_name="Example Banking",
        version="3.2.1",
        min_sdk=24,
        target_sdk=34,
    )

    findings = [
        Finding(
            id="F001",
            category="nsc",
            description="NSC pin-set found with SHA-256 hashes for api.example.com",
            location="res/xml/network_security_config.xml:12",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence='<pin digest="SHA-256">base64hash==</pin>',
        ),
        Finding(
            id="F002",
            category="trustmanager",
            description="Custom TrustManager with checkServerTrusted override — NOT trust-all",
            location="com.example.banking.ssl.PinningTrustManager",
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence=".method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
        ),
        Finding(
            id="F003",
            category="protection",
            description="ProGuard obfuscation detected (basic level)",
            location="classes.dex",
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            raw_evidence="Class names: a.a.a, b.c.d — short identifiers suggest obfuscation",
        ),
    ]

    nsc = NSCResult(
        found=True,
        pin_sets=[
            PinSet(
                domain="api.example.com",
                pins=["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
                expiry="2026-06-01",
                has_backup=True,
            )
        ],
        cleartext_allowed=False,
    )

    pinning_implementations = [
        PinningImpl(
            type=HookCategory.TRUST_MANAGER,
            class_name="com.example.banking.ssl.PinningTrustManager",
            is_vulnerable=False,
            confidence=Confidence.HIGH,
        ),
        PinningImpl(
            type=HookCategory.CERTIFICATE_PINNER,
            class_name="com.example.banking.net.ApiClient",
            is_vulnerable=False,
            confidence=Confidence.HIGH,
        ),
    ]

    protection = ProtectionProfile(
        obfuscation_level=ObfuscationLevel.BASIC,
        native_libs=["lib/arm64-v8a/libnative-ssl.so"],
        integrity_checks=["SafetyNet"],
        root_detection=True,
    )

    hookable_targets = [
        HookTarget(
            class_name="com.example.banking.ssl.PinningTrustManager",
            method_name="checkServerTrusted",
            category=HookCategory.TRUST_MANAGER,
            overloads=[
                "[Ljava.security.cert.X509Certificate;, java.lang.String",
                "[Ljava.security.cert.X509Certificate;, java.lang.String, java.net.Socket",
            ],
            source_file="com/example/banking/ssl/PinningTrustManager.smali",
            confidence=Confidence.HIGH,
        ),
        HookTarget(
            class_name="com.example.banking.net.ApiClient",
            method_name="check",
            category=HookCategory.CERTIFICATE_PINNER,
            overloads=["java.lang.String, java.util.List"],
            source_file="com/example/banking/net/ApiClient.smali",
            confidence=Confidence.HIGH,
        ),
    ]

    return StaticReport(
        app_info=app_info,
        findings=findings,
        nsc=nsc,
        pinning_implementations=pinning_implementations,
        protection=protection,
        hookable_targets=hookable_targets,
        timestamp=datetime(2026, 4, 22, 1, 0, 0),
    )


def build_dynamic_report(app_info: AppInfo, hookable_targets: list[HookTarget]) -> DynamicReport:
    """Build a realistic DynamicReport example."""
    environment = Environment(
        device_id="emulator-5554",
        android_version="14",
        frida_version="16.2.1",
        is_rooted=True,
    )

    bypass_attempts = [
        # Generic bypass — failed
        BypassAttempt(
            script_name="generic_unpinner",
            target=None,
            hook_triggered=True,
            verification=VerificationResult.FAILED,
            verification_method="logcat",
            confidence=Confidence.HIGH,
            duration_ms=3200,
            error=None,
            generated_script="Java.perform(function() { /* android-unpinner script */ });",
            logs=[
                "[unpinner] Hooking TrustManagerImpl.checkTrustedRecursive",
                "[unpinner] Hook fired for checkTrustedRecursive",
                "[logcat] javax.net.ssl.SSLHandshakeException: Pin verification failed",
            ],
        ),
        # Targeted bypass on TrustManager — succeeded
        BypassAttempt(
            script_name="trustmanager_hook",
            target=hookable_targets[0],
            hook_triggered=True,
            verification=VerificationResult.SUCCESS,
            verification_method="logcat",
            confidence=Confidence.HIGH,
            duration_ms=2800,
            error=None,
            generated_script=(
                "Java.perform(function() {\n"
                "  var TM = Java.use('com.example.banking.ssl.PinningTrustManager');\n"
                "  TM.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', "
                "'java.lang.String').implementation = function(chain, authType) {\n"
                "    console.log('[hook] checkServerTrusted bypassed');\n"
                "  };\n"
                "});"
            ),
            logs=[
                "[hook] checkServerTrusted bypassed",
                "[logcat] D/OkHttp: --> GET https://api.example.com/v1/accounts",
                "[logcat] D/OkHttp: <-- 200 OK",
            ],
        ),
    ]

    detection_results = DetectionResults(
        frida_detected=False,
        root_detected=True,
        debugger_detected=False,
        app_reaction=AppReaction.IGNORE,
    )

    mitm_check = MITMCheck(
        status=MITMStatus.SKIPPED,
        note="MITM proxy not configured for this test run",
    )

    return DynamicReport(
        app_info=app_info,
        environment=environment,
        bypass_attempts=bypass_attempts,
        detection_results=detection_results,
        mitm_check=mitm_check,
        overall_bypass=True,
        targeted_bypass_needed=True,
        timestamp=datetime(2026, 4, 22, 1, 10, 0),
    )


def build_evaluation_result(app_info: AppInfo) -> EvaluationResult:
    """Build a realistic EvaluationResult example."""
    criteria = [
        CriterionScore(
            criterion_id=1,
            name="Implementation Correctness",
            score=80,
            weight=0.30,
            confidence=Confidence.HIGH,
            components=[
                ScoreComponent(
                    check_id="c1_nsc_sha256",
                    check_name="NSC pin-set with SHA-256",
                    points=20,
                    max_points=20,
                    confidence=Confidence.HIGH,
                    rationale="SHA-256 key hashing detected in NSC — recommended pinning method",
                ),
                ScoreComponent(
                    check_id="c1_backup_pin",
                    check_name="Backup pin configured",
                    points=15,
                    max_points=15,
                    confidence=Confidence.HIGH,
                    rationale="Backup pin present — cert rotation will not break the app",
                ),
                ScoreComponent(
                    check_id="c1_pin_expiry",
                    check_name="Pin expiry set and reasonable",
                    points=10,
                    max_points=10,
                    confidence=Confidence.HIGH,
                    rationale="Expiry 2026-06-01 (< 1 year) — enables key rotation",
                ),
                ScoreComponent(
                    check_id="c1_no_cleartext",
                    check_name="No cleartext traffic",
                    points=10,
                    max_points=10,
                    confidence=Confidence.HIGH,
                    rationale="cleartextTrafficPermitted is false",
                ),
                ScoreComponent(
                    check_id="c1_no_trust_all",
                    check_name="No trust-all TrustManager",
                    points=20,
                    max_points=20,
                    confidence=Confidence.HIGH,
                    rationale="No trust-all implementation detected",
                ),
                ScoreComponent(
                    check_id="c1_no_allow_all_hostname",
                    check_name="No allow-all HostnameVerifier",
                    points=5,
                    max_points=10,
                    confidence=Confidence.MEDIUM,
                    rationale="No HostnameVerifier found — possible custom implementation (confidence reduced)",
                ),
                ScoreComponent(
                    check_id="c1_webview_ssl",
                    check_name="WebView SSL errors handled",
                    points=0,
                    max_points=15,
                    confidence=Confidence.HIGH,
                    rationale="No WebView SSL handling found — not applicable or missing",
                ),
            ],
            summary="Strong TLS pinning implementation with minor gaps in WebView handling",
            warning=None,
        ),
        CriterionScore(
            criterion_id=2,
            name="Static Bypass Resistance",
            score=55,
            weight=0.25,
            confidence=Confidence.MEDIUM,
            components=[
                ScoreComponent(
                    check_id="c2_obfuscation",
                    check_name="Code obfuscation",
                    points=21,
                    max_points=30,
                    confidence=Confidence.MEDIUM,
                    rationale="Basic obfuscation detected (ProGuard) — 30 × 0.7 = 21 (MEDIUM confidence)",
                ),
                ScoreComponent(
                    check_id="c2_native_code",
                    check_name="Pinning logic in native code",
                    points=10,
                    max_points=25,
                    confidence=Confidence.LOW,
                    rationale="Native .so with SSL symbols found but no Java mapping — 25 × 0.4 = 10",
                ),
                ScoreComponent(
                    check_id="c2_integrity",
                    check_name="APK integrity verification",
                    points=14,
                    max_points=20,
                    confidence=Confidence.MEDIUM,
                    rationale="SafetyNet detected — 20 × 0.7 = 14 (heuristic detection)",
                ),
                ScoreComponent(
                    check_id="c2_no_hardcoded",
                    check_name="No hardcoded pins in plaintext",
                    points=0,
                    max_points=15,
                    confidence=Confidence.HIGH,
                    rationale="Hardcoded pin hashes found in plaintext strings — trivially extractable",
                ),
                ScoreComponent(
                    check_id="c2_root_detection",
                    check_name="Root/environment detection",
                    points=10,
                    max_points=10,
                    confidence=Confidence.HIGH,
                    rationale="Root detection code found in decompiled source",
                ),
            ],
            summary="Moderate static resistance — basic obfuscation but plaintext secrets reduce score",
            warning="Over 50% of awarded points come from LOW-confidence components",
        ),
        CriterionScore(
            criterion_id=3,
            name="Dynamic Bypass Resistance",
            score=45,
            weight=0.30,
            confidence=Confidence.HIGH,
            components=[
                ScoreComponent(
                    check_id="c3_generic_bypass",
                    check_name="Generic bypass failed",
                    points=35,
                    max_points=35,
                    confidence=Confidence.HIGH,
                    rationale="android-unpinner generic script failed to bypass pinning",
                ),
                ScoreComponent(
                    check_id="c3_targeted_bypass",
                    check_name="Targeted bypass also failed",
                    points=0,
                    max_points=25,
                    confidence=Confidence.HIGH,
                    rationale="Targeted hook on PinningTrustManager.checkServerTrusted succeeded — bypass achieved",
                ),
                ScoreComponent(
                    check_id="c3_frida_detection",
                    check_name="App detects Frida",
                    points=0,
                    max_points=20,
                    confidence=Confidence.HIGH,
                    rationale="App did not detect Frida instrumentation",
                ),
                ScoreComponent(
                    check_id="c3_root_detection",
                    check_name="App detects root",
                    points=10,
                    max_points=10,
                    confidence=Confidence.HIGH,
                    rationale="App detected root but continued running (IGNORE reaction)",
                ),
                ScoreComponent(
                    check_id="c3_debugger_detection",
                    check_name="App detects debugger",
                    points=0,
                    max_points=10,
                    confidence=Confidence.HIGH,
                    rationale="No debugger detection observed",
                ),
            ],
            summary="Generic bypass blocked but targeted bypass succeeded — moderate dynamic resistance",
            warning=None,
        ),
        CriterionScore(
            criterion_id=4,
            name="Comprehensive Protection",
            score=55,
            weight=0.15,
            confidence=Confidence.HIGH,
            components=[
                ScoreComponent(
                    check_id="c4_multiple_methods",
                    check_name="Multiple pinning methods",
                    points=30,
                    max_points=30,
                    confidence=Confidence.HIGH,
                    rationale="Both NSC and programmatic CertificatePinner used — defense-in-depth",
                ),
                ScoreComponent(
                    check_id="c4_custom_logic",
                    check_name="Custom pinning logic",
                    points=0,
                    max_points=25,
                    confidence=Confidence.HIGH,
                    rationale="No non-standard custom pinning logic detected",
                ),
                ScoreComponent(
                    check_id="c4_native_java_combo",
                    check_name="Native + Java pinning combined",
                    points=25,
                    max_points=25,
                    confidence=Confidence.LOW,
                    rationale="Native SSL library present alongside Java pinning — 25 × 0.4 = 10 (LOW confidence)",
                ),
                ScoreComponent(
                    check_id="c4_anti_tampering",
                    check_name="Anti-tampering checks",
                    points=0,
                    max_points=20,
                    confidence=Confidence.HIGH,
                    rationale="SafetyNet found but already counted in C2 — not double-counted here",
                ),
            ],
            summary="Good defense-in-depth with multiple pinning methods",
            warning=None,
        ),
    ]

    final_score = sum(c.score * c.weight for c in criteria)

    if final_score >= 85:
        level = SecurityLevel.HIGH
    elif final_score >= 60:
        level = SecurityLevel.MEDIUM
    elif final_score >= 30:
        level = SecurityLevel.LOW
    else:
        level = SecurityLevel.CRITICAL

    return EvaluationResult(
        app_info=AppInfo(
            apk_path=Path("samples/com.example.banking.apk"),
            package_name="com.example.banking",
            app_name="Example Banking",
            version="3.2.1",
            min_sdk=24,
            target_sdk=34,
        ),
        criteria=criteria,
        final_score=round(final_score, 2),
        security_level=level,
        recommendations=[
            "Remove hardcoded pin hashes from plaintext strings — use encrypted storage",
            "Implement Frida detection (e.g. check for frida-server process)",
            "Add debugger detection (Debug.isDebuggerConnected())",
            "Consider adding WebView SSL error handling if WebView is used",
        ],
        warnings=[
            "C2 (Static Bypass Resistance): Over 50% of awarded points come from LOW-confidence components",
        ],
        static_report_path=Path("results/static_report.json"),
        dynamic_report_path=Path("results/dynamic_report.json"),
        timestamp=datetime(2026, 4, 22, 1, 15, 0),
    )


def main() -> None:
    """Generate and print example JSON for all three report types."""
    # Build examples
    static_report = build_static_report()
    dynamic_report = build_dynamic_report(
        static_report.app_info, static_report.hookable_targets
    )
    evaluation = build_evaluation_result(static_report.app_info)

    # Serialize
    static_json = static_report.model_dump_json(indent=2)
    dynamic_json = dynamic_report.model_dump_json(indent=2)
    eval_json = evaluation.model_dump_json(indent=2)

    # Round-trip deserialization test
    static_rt = StaticReport.model_validate_json(static_json)
    dynamic_rt = DynamicReport.model_validate_json(dynamic_json)
    eval_rt = EvaluationResult.model_validate_json(eval_json)

    assert static_rt.app_info.package_name == static_report.app_info.package_name
    assert len(static_rt.hookable_targets) == len(static_report.hookable_targets)
    assert dynamic_rt.overall_bypass == dynamic_report.overall_bypass
    assert dynamic_rt.targeted_bypass_needed == dynamic_report.targeted_bypass_needed
    assert len(dynamic_rt.bypass_attempts) == len(dynamic_report.bypass_attempts)
    assert eval_rt.final_score == evaluation.final_score
    assert eval_rt.security_level == evaluation.security_level
    assert len(eval_rt.criteria) == 4

    print("=" * 70)
    print("STATIC REPORT JSON")
    print("=" * 70)
    print(static_json)
    print()
    print("=" * 70)
    print("DYNAMIC REPORT JSON")
    print("=" * 70)
    print(dynamic_json)
    print()
    print("=" * 70)
    print("EVALUATION RESULT JSON")
    print("=" * 70)
    print(eval_json)
    print()
    print("=" * 70)
    print("ALL ROUND-TRIP TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    main()
