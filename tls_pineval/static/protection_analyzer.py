"""Protection analyzer — detects anti-RE and runtime protections (V2 §4.2).

Detects:
    - Obfuscation level (ProGuard/R8 markers, class name entropy)
    - Native .so libraries
    - SafetyNet / Play Integrity API references
    - Root detection code
"""

from __future__ import annotations

import logging
import math
import os
import re
from collections import Counter
from pathlib import Path

from tls_pineval.models.common import Confidence, Finding, ObfuscationLevel, Severity
from tls_pineval.models.static_report import ProtectionProfile
from tls_pineval.static.patterns import (
    PLAY_INTEGRITY_PATTERN,
    ROOT_DETECTION_PATTERNS,
    SAFETYNET_PATTERN,
)

logger = logging.getLogger(__name__)


def _find_native_libs(apktool_dir: Path) -> list[str]:
    """Find all .so libraries in the APK's lib/ directory."""
    libs: list[str] = []
    lib_dir = apktool_dir / "lib"
    if not lib_dir.exists():
        return libs

    for root, _dirs, files in os.walk(lib_dir):
        for fname in files:
            if fname.endswith(".so"):
                rel = str(Path(root, fname).relative_to(apktool_dir))
                libs.append(rel)
    return libs


def _detect_obfuscation_level(smali_dir: Path) -> tuple[ObfuscationLevel, Confidence]:
    """Estimate obfuscation level from class naming patterns.

    Heuristic:
        - ratio > 0.4  of short (≤2 char) class file names → STRONG
        - ratio > 0.15 → BASIC (ProGuard/R8)
        - otherwise   → NONE

    The previous implementation also checked for proguard-rules.pro inside
    smali_dir, but that file is part of the project source tree and is never
    present in APKTool's decompiled output.  That check has been removed.
    """
    if not smali_dir.exists():
        return ObfuscationLevel.NONE, Confidence.LOW

    class_names: list[str] = []
    for root, _dirs, files in os.walk(smali_dir):
        for fname in files:
            if fname.endswith(".smali"):
                class_names.append(fname[:-6])

    if not class_names:
        return ObfuscationLevel.NONE, Confidence.LOW

    total = len(class_names)
    short_names = sum(1 for n in class_names if len(n) <= 2)
    ratio = short_names / total if total > 0 else 0

    if ratio > 0.4:
        return ObfuscationLevel.STRONG, Confidence.MEDIUM
    elif ratio > 0.15:
        return ObfuscationLevel.BASIC, Confidence.MEDIUM
    else:
        return ObfuscationLevel.NONE, Confidence.HIGH


def _search_pattern_in_files(
    directory: Path,
    pattern: re.Pattern[str],
    extensions: tuple[str, ...] = (".smali", ".java", ".xml"),
    max_file_size: int = 2 * 1024 * 1024,
    max_matches: int = 1,
) -> list[tuple[Path, str]]:
    """Search for a pattern across files, returning (path, matched_text).

    Stops after *max_matches* to avoid reading the entire corpus when only
    a presence check is needed (all callers use matches[0] at most).
    """
    matches: list[tuple[Path, str]] = []
    if not directory.exists():
        return matches

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if not any(fname.endswith(ext) for ext in extensions):
                continue
            fpath = Path(root) / fname
            if fpath.stat().st_size > max_file_size:
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                for m in pattern.finditer(content):
                    matches.append((fpath, m.group()))
                    if max_matches and len(matches) >= max_matches:
                        return matches
            except OSError:
                continue
    return matches


def analyze_protection(
    apktool_dir: Path,
    smali_dir: Path | None = None,
    jadx_dir: Path | None = None,
) -> tuple[ProtectionProfile, list[Finding]]:
    """Analyze APK for anti-RE and runtime protection mechanisms.

    Args:
        apktool_dir: APKTool resource output (for native libs, resources).
        smali_dir: APKTool full output with Smali code.
        jadx_dir: Jadx output with Java source.

    Returns:
        Tuple of (ProtectionProfile, list of related Findings).
    """
    findings: list[Finding] = []

    # --- Native libraries ---
    native_libs = _find_native_libs(apktool_dir)
    ssl_native = [lib for lib in native_libs if "ssl" in lib.lower() or "tls" in lib.lower()]

    if native_libs:
        findings.append(
            Finding(
                id="PROT-NATIVE",
                category="protection",
                description=f"Found {len(native_libs)} native .so libraries ({len(ssl_native)} SSL-related)",
                location="lib/",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                raw_evidence=", ".join(native_libs[:10]),
            )
        )

    # --- Obfuscation ---
    scan_dir = smali_dir or apktool_dir
    obf_level, obf_confidence = _detect_obfuscation_level(scan_dir)

    if obf_level != ObfuscationLevel.NONE:
        findings.append(
            Finding(
                id="PROT-OBF",
                category="protection",
                description=f"Code obfuscation detected: {obf_level.value} level",
                location="classes.dex",
                severity=Severity.INFO,
                confidence=obf_confidence,
                raw_evidence=f"Obfuscation heuristic: level={obf_level.value}",
            )
        )

    # Use one best source directory for pattern searches.
    # These patterns target external API names (SafetyNet, Magisk, etc.) which
    # are not obfuscated — Smali and Java are equivalent here.  Prefer smali_dir
    # over jadx_dir: Smali is always fully available (APKTool never times out),
    # while Jadx can be 5–10× larger and may be partial if it timed out.
    search_dir: Path | None = next(
        (d for d in [smali_dir, jadx_dir] if d and d.exists()), None
    )

    # --- SafetyNet ---
    safetynet_found = False
    if search_dir:
        logger.debug("Searching for SafetyNet in %s", search_dir)
        matches = _search_pattern_in_files(search_dir, SAFETYNET_PATTERN.pattern)
        if matches:
            safetynet_found = True
            findings.append(
                Finding(
                    id="PROT-SAFETYNET",
                    category="protection",
                    description="Google SafetyNet API reference detected",
                    location=str(matches[0][0]),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    raw_evidence=matches[0][1][:200],
                )
            )

    # --- Play Integrity ---
    play_integrity_found = False
    if search_dir:
        logger.debug("Searching for Play Integrity in %s", search_dir)
        matches = _search_pattern_in_files(search_dir, PLAY_INTEGRITY_PATTERN.pattern)
        if matches:
            play_integrity_found = True
            findings.append(
                Finding(
                    id="PROT-PLAYINTEGRITY",
                    category="protection",
                    description="Google Play Integrity API reference detected",
                    location=str(matches[0][0]),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    raw_evidence=matches[0][1][:200],
                )
            )

    integrity_checks: list[str] = []
    if safetynet_found:
        integrity_checks.append("SafetyNet")
    if play_integrity_found:
        integrity_checks.append("Play Integrity")

    # --- Root detection ---
    root_detection = False
    if search_dir:
        logger.debug("Searching for root detection in %s", search_dir)
        matches = _search_pattern_in_files(search_dir, ROOT_DETECTION_PATTERNS.pattern)
        if matches:
            root_detection = True
            findings.append(
                Finding(
                    id="PROT-ROOT",
                    category="protection",
                    description="Root detection code found",
                    location=str(matches[0][0]),
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    raw_evidence=matches[0][1][:200],
                )
            )

    profile = ProtectionProfile(
        obfuscation_level=obf_level,
        native_libs=native_libs,
        integrity_checks=integrity_checks,
        root_detection=root_detection,
    )

    logger.info(
        "Protection analysis: obfuscation=%s, native=%d, integrity=%s, root=%s",
        obf_level.value,
        len(native_libs),
        integrity_checks,
        root_detection,
    )

    return profile, findings
