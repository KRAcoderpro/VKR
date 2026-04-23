"""Dynamic analysis orchestrator for TLS-PinEval (V2 §4.3).

Execution flow (fixed order per V2 spec):
    1. Environment pre-checks (_ensure_environment_ready)
    2. APK install
    3. Generic bypass (android-unpinner) + logcat verification
    4. Targeted bypass per HookTarget (only if generic FAILED and targets exist)
    5. Detection tests (Frida / root / debugger)
    6. MITM check (SKIPPED in V1)
    7. Build and save DynamicReport

Raises DynamicAnalysisError on any pre-check failure; never returns a
partial report.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from tls_pineval.dynamic.bypass_runner import run_bypass
from tls_pineval.dynamic.detection_tester import test_detection
from tls_pineval.dynamic.script_generator import (
    generate_detection_script,
    generate_generic_script,
    generate_targeted_script,
)
from tls_pineval.models.common import VerificationResult
from tls_pineval.models.dynamic_report import (
    BypassAttempt,
    DetectionResults,
    DynamicReport,
    Environment,
    MITMCheck,
)
from tls_pineval.models.static_report import StaticReport
from tls_pineval.tools import ToolError, run_adb

logger = logging.getLogger(__name__)


class DynamicAnalysisError(Exception):
    """Raised when the dynamic analysis environment is not ready or fatally fails."""


# ---------------------------------------------------------------------------
# Frida lazy import
# ---------------------------------------------------------------------------


def _get_frida() -> Any:
    """Import frida lazily so the module is importable without frida installed."""
    try:
        import frida  # noqa: PLC0415
        return frida
    except ImportError as exc:
        raise DynamicAnalysisError(
            "frida Python package is not installed. "
            "Install with: pip install frida frida-tools"
        ) from exc


# ---------------------------------------------------------------------------
# Environment pre-checks (V2 §2 — all 5 steps)
# ---------------------------------------------------------------------------


def _ensure_environment_ready(package_name: str) -> tuple[Environment, Any]:
    """Validate the dynamic analysis environment.

    Performs all 5 mandatory pre-checks in order.  Any failure raises
    DynamicAnalysisError with an actionable diagnostic message.

    Returns:
        Tuple of (Environment, frida_device) ready for use.
    """
    frida = _get_frida()

    # Step 1: ADB device in 'device' state
    try:
        adb_output = run_adb("devices", timeout=10)
    except ToolError as exc:
        raise DynamicAnalysisError(
            "ADB not available. Install Android platform-tools and add to PATH."
        ) from exc

    device_lines = [
        line for line in adb_output.splitlines()
        if line.strip() and "\tdevice" in line and not line.startswith("List")
    ]
    if not device_lines:
        raise DynamicAnalysisError(
            "No ADB device found in 'device' state. "
            "Connect device or start emulator, then verify with: adb devices"
        )
    device_id = device_lines[0].split("\t")[0].strip()
    logger.info("ADB device found: %s", device_id)

    # Step 2: Read Android version
    try:
        android_version = run_adb(
            "shell", "getprop", "ro.build.version.release", timeout=10
        ).strip()
    except ToolError as exc:
        raise DynamicAnalysisError(
            "Cannot read device properties. Check USB debugging is enabled."
        ) from exc

    if not android_version:
        raise DynamicAnalysisError(
            "Cannot read device properties. Check USB debugging is enabled."
        )
    logger.info("Android version: %s", android_version)

    # Step 3: Frida connect to device
    try:
        frida_device = frida.get_usb_device(timeout=5000)
    except Exception as exc:
        raise DynamicAnalysisError(
            "Frida cannot connect to device. "
            "Is frida-server running? "
            "Check with: adb shell ps | grep frida-server"
        ) from exc

    # Step 4: frida-server responding
    try:
        frida_device.enumerate_processes()
        frida_version: str = getattr(frida, "__version__", "unknown")
    except Exception as exc:
        raise DynamicAnalysisError(
            "frida-server not responding. "
            "Check version compatibility: frida-server and frida Python package must match."
        ) from exc
    logger.info("frida-server OK, version: %s", frida_version)

    # Step 5: Package installed (informational — install happens next)
    try:
        pm_output = run_adb("shell", "pm", "list", "packages", timeout=20)
        if f"package:{package_name}" not in pm_output:
            logger.info("Package %s not yet installed — will install now", package_name)
    except ToolError:
        logger.warning("Could not query installed packages; will attempt install anyway")

    # Best-effort root check
    is_rooted = False
    try:
        id_output = run_adb("shell", "id", timeout=5)
        is_rooted = "uid=0" in id_output or "root" in id_output.lower()
    except Exception:
        pass

    return (
        Environment(
            device_id=device_id,
            android_version=android_version,
            frida_version=frida_version,
            is_rooted=is_rooted,
        ),
        frida_device,
    )


# ---------------------------------------------------------------------------
# APK installation
# ---------------------------------------------------------------------------


def _install_apk(apk_path: Path) -> None:
    """Install the APK on the connected device (replace existing if present)."""
    logger.info("Installing %s", apk_path.name)
    try:
        run_adb("install", "-r", str(apk_path), timeout=120)
    except ToolError as exc:
        raise DynamicAnalysisError(
            f"APK installation failed: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze(
    apk_path: Path,
    static_report: StaticReport,
    *,
    output_dir: Path,
    bypass_timeout: int = 15,
    detection_timeout: int = 10,
) -> DynamicReport:
    """Run the full dynamic analysis pipeline.

    Args:
        apk_path: Path to the APK file to install and test.
        static_report: Output of Phase 2 static analysis (provides hookable_targets).
        output_dir: Directory where dynamic_report.json will be saved.
        bypass_timeout: Seconds to wait per bypass attempt.
        detection_timeout: Seconds to observe detection behaviour.

    Returns:
        DynamicReport with all bypass attempts and detection results.

    Raises:
        DynamicAnalysisError: If the environment is not ready.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    package_name = static_report.app_info.package_name

    # 1 — Environment pre-checks
    env, frida_device = _ensure_environment_ready(package_name)

    # 2 — Install APK
    _install_apk(apk_path)

    bypass_attempts: list[BypassAttempt] = []
    overall_bypass = False
    targeted_bypass_needed = False

    # 3 — Generic bypass (always first)
    logger.info("Running generic bypass attempt")
    generic_js = generate_generic_script()
    generic_attempt = run_bypass(
        frida_device,
        package_name,
        generic_js,
        "generic_unpinner",
        target=None,
        timeout=bypass_timeout,
    )
    bypass_attempts.append(generic_attempt)

    if generic_attempt.verification == VerificationResult.SUCCESS:
        overall_bypass = True
        logger.info("Generic bypass succeeded — skipping targeted attempts")
    else:
        # 4 — Targeted bypass (only if generic failed and targets available)
        targets = static_report.hookable_targets
        if targets:
            targeted_bypass_needed = True
            logger.info(
                "Generic bypass did not succeed — running %d targeted attempt(s)",
                len(targets),
            )
            for target in targets:
                if overall_bypass:
                    break
                targeted_js = generate_targeted_script(target)
                attempt = run_bypass(
                    frida_device,
                    package_name,
                    targeted_js,
                    f"targeted_{target.category.value.lower()}",
                    target=target,
                    timeout=bypass_timeout,
                )
                bypass_attempts.append(attempt)
                if attempt.verification == VerificationResult.SUCCESS:
                    overall_bypass = True
                    logger.info(
                        "Targeted bypass succeeded on %s.%s",
                        target.class_name, target.method_name,
                    )

    # 5 — Detection tests
    logger.info("Running detection tests")
    detection_js = generate_detection_script()
    detection_results: DetectionResults = test_detection(
        frida_device,
        package_name,
        detection_js,
        timeout=detection_timeout,
    )

    # 6 — MITM check (V1: skipped)
    mitm_check = MITMCheck(
        status="SKIPPED",
        note="MITM check not performed in V1 — requires mitmproxy integration",
    )

    report = DynamicReport(
        app_info=static_report.app_info,
        environment=env,
        bypass_attempts=bypass_attempts,
        detection_results=detection_results,
        mitm_check=mitm_check,
        overall_bypass=overall_bypass,
        targeted_bypass_needed=targeted_bypass_needed,
        timestamp=datetime.now(),
    )

    # Save JSON report
    report_path = output_dir / "dynamic_report.json"
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    logger.info("Dynamic report saved to %s", report_path)

    return report
