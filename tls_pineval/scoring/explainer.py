"""Human-readable explanations, recommendations, and warnings (V2 §4.4).

Generates the ``recommendations`` and ``warnings`` lists for EvaluationResult
by inspecting criterion scores, static report findings, and dynamic results.
"""

from __future__ import annotations

from typing import Optional

from tls_pineval.models.common import HookCategory
from tls_pineval.models.dynamic_report import DynamicReport
from tls_pineval.models.evaluation import CriterionScore
from tls_pineval.models.static_report import StaticReport


def _pts(criteria: list[CriterionScore], check_id: str) -> int:
    """Return awarded points for a specific check_id across all criteria."""
    for criterion in criteria:
        for comp in criterion.components:
            if comp.check_id == check_id:
                return comp.points
    return 0


def generate_recommendations(
    criteria: list[CriterionScore],
    static_report: StaticReport,
    dynamic_report: Optional[DynamicReport],
) -> list[str]:
    """Generate ordered improvement recommendations.

    Recommendations are ordered by impact: critical vulnerabilities first,
    then missing protections, then detection improvements.
    """
    recs: list[str] = []
    impls = static_report.pinning_implementations

    # --- Critical: insecure implementations ---
    vulnerable_types = {i.type for i in impls if i.is_vulnerable}
    if HookCategory.TRUST_MANAGER in vulnerable_types:
        recs.append(
            "Remove trust-all TrustManager — implement proper certificate chain validation "
            "in checkServerTrusted() instead of ignoring it"
        )
    if HookCategory.HOSTNAME_VERIFIER in vulnerable_types:
        recs.append(
            "Remove allow-all HostnameVerifier — verify() must check the hostname "
            "against the expected value, not return true unconditionally"
        )
    if HookCategory.WEBVIEW_SSL in vulnerable_types:
        recs.append(
            "Fix WebViewClient.onReceivedSslError() — call handler.cancel() instead of "
            "handler.proceed() to prevent loading pages with SSL errors"
        )

    # --- C1: implementation gaps ---
    if _pts(criteria, "c1_nsc_sha256") == 0:
        recs.append(
            "Add SHA-256 pin hashes to network_security_config.xml — use public key pinning "
            "with at least two pins (primary + backup)"
        )
    if _pts(criteria, "c1_backup_pin") == 0 and _pts(criteria, "c1_nsc_sha256") > 0:
        recs.append(
            "Add a backup pin to network_security_config.xml pin-set — "
            "prevents app outage during certificate rotation"
        )
    if _pts(criteria, "c1_pin_expiry") == 0 and _pts(criteria, "c1_nsc_sha256") > 0:
        recs.append(
            "Set a pin expiry date in the pin-set — enables planned certificate rotation "
            "without emergency app update"
        )
    # Check the actual NSC field rather than the score component, which is
    # absent when there is no pinning at all (early-exit path in _score_c1).
    # Without this guard, apps with no pinning would get a spurious cleartext
    # recommendation even when cleartextTrafficPermitted is false.
    if static_report.nsc.cleartext_allowed:
        recs.append(
            "Disable cleartext (HTTP) traffic — set cleartextTrafficPermitted=false "
            "in network_security_config.xml base-config"
        )

    # --- C2: static resistance gaps ---
    if _pts(criteria, "c2_obfuscation") == 0:
        recs.append(
            "Enable ProGuard or R8 code obfuscation — increases reverse-engineering effort "
            "and obscures class names used for hook targeting"
        )
    if _pts(criteria, "c2_no_hardcoded") == 0:
        recs.append(
            "Remove hardcoded pin hashes from plaintext source — store pins in encrypted "
            "configuration or derive them at runtime"
        )
    if _pts(criteria, "c2_integrity") == 0:
        recs.append(
            "Add APK integrity verification (SafetyNet Attestation or Play Integrity API) — "
            "detects repackaged or modified APKs"
        )
    if _pts(criteria, "c2_root_detection") == 0:
        recs.append(
            "Add root / compromised environment detection — refuse to run on rooted devices "
            "or log an anomaly for security monitoring"
        )

    # --- C3: dynamic resistance gaps (only if dynamic ran) ---
    if dynamic_report is not None:
        if _pts(criteria, "c3_generic_bypass") == 0:
            recs.append(
                "Pinning bypassed by generic android-unpinner script — consider implementing "
                "custom pinning logic that resists standard Frida bypass tools"
            )
        if _pts(criteria, "c3_frida_detection") == 0:
            recs.append(
                "Implement Frida / instrumentation detection — check for frida-server process, "
                "gadget libraries, or abnormal memory mappings at runtime"
            )
        if _pts(criteria, "c3_debugger_detection") == 0:
            recs.append(
                "Add debugger detection (Debug.isDebuggerConnected() / ptrace anti-debug) — "
                "makes dynamic analysis harder"
            )

    return recs


def generate_warnings(
    criteria: list[CriterionScore],
    dynamic_skipped: bool,
) -> list[str]:
    """Collect global warnings from criterion scores and analysis state."""
    warnings: list[str] = []

    if dynamic_skipped:
        warnings.append(
            "Dynamic analysis was not performed - C3 (Dynamic Bypass Resistance) excluded "
            "from weighted average; remaining weights normalised to 0.70 total"
        )

    for c in criteria:
        if c.warning:
            warnings.append(c.warning)

    return warnings
