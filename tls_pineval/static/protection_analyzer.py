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
        - If many classes have single-letter names (a.a, b.c) → BASIC (ProGuard)
        - If class names are heavily randomized → STRONG (DexGuard etc.)
        - Otherwise → NONE
    """
    if not smali_dir.exists():
        return ObfuscationLevel.NONE, Confidence.LOW

    class_names: list[str] = []
    for root, _dirs, files in os.walk(smali_dir):
        for fname in files:
            if fname.endswith(".smali"):
                # Use just the filename without extension
                class_names.append(fname[:-6])

    if not class_names:
        return ObfuscationLevel.NONE, Confidence.LOW

    total = len(class_names)
    short_names = sum(1 for n in class_names if len(n) <= 2)
    ratio = short_names / total if total > 0 else 0

    # Also check for proguard mapping file indicator
    has_proguard_marker = any(
        (smali_dir / name).exists()
        for name in ["proguard-rules.pro", "proguard.cfg"]
    )

    if ratio > 0.4:
        return ObfuscationLevel.STRONG, Confidence.MEDIUM
    elif ratio > 0.15 or has_proguard_marker:
        return ObfuscationLevel.BASIC, Confidence.MEDIUM
    else:
        return ObfuscationLevel.NONE, Confidence.HIGH


def _search_pattern_in_files(
    directory: Path,
    pattern: re.Pattern[str],
    extensions: tuple[str, ...] = (".smali", ".java", ".xml"),
    max_file_size: int = 2 * 1024 * 1024,
) -> list[tuple[Path, str]]:
    """Search for a pattern across files, returning (path, matched_text)."""
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

    # --- Search across all available source dirs ---
    search_dirs = [d for d in [smali_dir, jadx_dir, apktool_dir] if d and d.exists()]

    # --- SafetyNet ---
    safetynet_found = False
    for d in search_dirs:
        matches = _search_pattern_in_files(d, SAFETYNET_PATTERN.pattern)
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
            break

    # --- Play Integrity ---
    play_integrity_found = False
    for d in search_dirs:
        matches = _search_pattern_in_files(d, PLAY_INTEGRITY_PATTERN.pattern)
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
            break

    integrity_checks: list[str] = []
    if safetynet_found:
        integrity_checks.append("SafetyNet")
    if play_integrity_found:
        integrity_checks.append("Play Integrity")

    # --- Root detection ---
    root_detection = False
    for d in search_dirs:
        matches = _search_pattern_in_files(d, ROOT_DETECTION_PATTERNS.pattern)
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
            break

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
