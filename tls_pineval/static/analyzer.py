"""Static analysis orchestrator (V2 §4.2).

Coordinates the full static analysis pipeline:
    1. Extract APK metadata (package name, version, SDK)
    2. Decompile with APKTool (resources + Smali)
    3. Decompile with Jadx (Java source)
    4. Run NSC analyzer
    5. Run code analyzer
    6. Run protection analyzer
    7. Merge results into StaticReport
    8. Save JSON report

If a decompilation step fails, analysis continues with whatever data
is available.  The function always returns a valid StaticReport.
"""

from __future__ import annotations

import json
import logging
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from tls_pineval.models.common import AppInfo, Confidence, Finding, Severity
from tls_pineval.models.static_report import StaticReport
from tls_pineval.static.code_analyzer import analyze_code
from tls_pineval.static.nsc_analyzer import analyze_nsc
from tls_pineval.static.protection_analyzer import analyze_protection
from tls_pineval.tools import (
    ToolError,
    extract_package_info_from_aapt,
    run_apktool,
    run_apktool_full,
    run_jadx,
)

logger = logging.getLogger(__name__)


def _extract_app_info(apk_path: Path) -> AppInfo:
    """Extract basic APK metadata using aapt, with fallbacks."""
    info = extract_package_info_from_aapt(apk_path)

    return AppInfo(
        apk_path=apk_path,
        package_name=info.get("package_name", apk_path.stem),
        app_name=info.get("app_name", ""),
        version=info.get("version_name", ""),
        min_sdk=int(info.get("min_sdk", "0") or "0"),
        target_sdk=int(info.get("target_sdk", "0") or "0"),
    )


def _extract_package_from_manifest(apktool_dir: Path) -> Optional[str]:
    """Fallback: extract package name from AndroidManifest.xml."""
    manifest = apktool_dir / "AndroidManifest.xml"
    if not manifest.is_file():
        return None

    try:
        content = manifest.read_text(encoding="utf-8", errors="replace")
        import re
        match = re.search(r'package="([^"]+)"', content)
        if match:
            return match.group(1)
    except OSError:
        pass
    return None


def run_static_analysis(
    apk_path: Path,
    output_dir: Path,
    *,
    skip_jadx: bool = False,
    jadx_timeout: int = 300,
) -> StaticReport:
    """Run the complete static analysis pipeline on an APK.

    Args:
        apk_path: Path to the APK file to analyze.
        output_dir: Directory to write decompiled data and reports to.
        skip_jadx: If True, skip Jadx decompilation (faster, Smali-only).

    Returns:
        A fully populated StaticReport instance.

    The function always returns a valid StaticReport even if some
    sub-analyses fail.  Errors are recorded as findings.
    """
    if not apk_path.is_file():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    all_findings: list[Finding] = []

    logger.info("Starting static analysis of %s", apk_path.name)

    # ------------------------------------------------------------------
    # Step 1: Extract APK metadata
    # ------------------------------------------------------------------
    app_info = _extract_app_info(apk_path)
    logger.info("Package: %s v%s (SDK %d–%d)",
                app_info.package_name, app_info.version,
                app_info.min_sdk, app_info.target_sdk)

    # ------------------------------------------------------------------
    # Step 2: Decompile with APKTool (resources only — for NSC)
    # ------------------------------------------------------------------
    apktool_dir: Optional[Path] = None
    try:
        apktool_dir = run_apktool(apk_path, output_dir)
    except ToolError as exc:
        logger.error("APKTool (resources) failed: %s", exc)
        all_findings.append(
            Finding(
                id="TOOL-APKTOOL-RES",
                category="protection",
                description=f"APKTool resource decompilation failed: {exc}",
                location=str(apk_path),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                raw_evidence=str(exc)[:500],
            )
        )

    # Fallback package name from manifest
    if not app_info.package_name and apktool_dir:
        pkg = _extract_package_from_manifest(apktool_dir)
        if pkg:
            app_info.package_name = pkg

    # ------------------------------------------------------------------
    # Step 3: Decompile with APKTool full (Smali code)
    # ------------------------------------------------------------------
    smali_dir: Optional[Path] = None
    try:
        smali_dir = run_apktool_full(apk_path, output_dir)
    except ToolError as exc:
        logger.error("APKTool (full/Smali) failed: %s", exc)
        all_findings.append(
            Finding(
                id="TOOL-APKTOOL-SMALI",
                category="protection",
                description=f"APKTool Smali decompilation failed: {exc}",
                location=str(apk_path),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                raw_evidence=str(exc)[:500],
            )
        )

    # ------------------------------------------------------------------
    # Step 4: Decompile with Jadx (Java source)
    # ------------------------------------------------------------------
    jadx_dir: Optional[Path] = None
    if not skip_jadx:
        try:
            jadx_dir = run_jadx(apk_path, output_dir, timeout=jadx_timeout)
        except ToolError as exc:
            logger.warning("Jadx failed (continuing with Smali only): %s", exc)
            all_findings.append(
                Finding(
                    id="TOOL-JADX",
                    category="protection",
                    description=f"Jadx decompilation failed: {exc}",
                    location=str(apk_path),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    raw_evidence=str(exc)[:500],
                )
            )

    # ------------------------------------------------------------------
    # Step 5: NSC analysis
    # ------------------------------------------------------------------
    from tls_pineval.models.static_report import NSCResult

    nsc_result = NSCResult()
    if apktool_dir:
        nsc_result, nsc_findings = analyze_nsc(apktool_dir)
        all_findings.extend(nsc_findings)
    else:
        logger.warning("Skipping NSC analysis — no APKTool output available")

    # ------------------------------------------------------------------
    # Step 6: Code analysis
    # ------------------------------------------------------------------
    code_result = analyze_code(smali_dir, jadx_dir)
    all_findings.extend(code_result.findings)

    # ------------------------------------------------------------------
    # Step 7: Protection analysis
    # ------------------------------------------------------------------
    from tls_pineval.models.static_report import ProtectionProfile

    protection = ProtectionProfile()
    if apktool_dir or smali_dir:
        protection, prot_findings = analyze_protection(
            apktool_dir=apktool_dir or smali_dir,  # type: ignore[arg-type]
            smali_dir=smali_dir,
            jadx_dir=jadx_dir,
        )
        all_findings.extend(prot_findings)

    # ------------------------------------------------------------------
    # Step 8: Build and save StaticReport
    # ------------------------------------------------------------------
    report = StaticReport(
        app_info=app_info,
        findings=all_findings,
        nsc=nsc_result,
        pinning_implementations=code_result.pinning_impls,
        protection=protection,
        hookable_targets=code_result.hook_targets,
        timestamp=datetime.now(),
    )

    # Save JSON
    report_path = output_dir / "static_report.json"
    report_path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )
    logger.info("Static report saved to %s", report_path)

    # Summary log
    logger.info(
        "Static analysis complete: %d findings, %d pinning impls, "
        "%d hookable targets, protection: obf=%s native=%d",
        len(report.findings),
        len(report.pinning_implementations),
        len(report.hookable_targets),
        report.protection.obfuscation_level.value,
        len(report.protection.native_libs),
    )

    return report
