"""Network Security Configuration analyzer (V2 §4.2).

Parses ``network_security_config.xml`` from the decompiled APK to extract:
    - pin-set entries (domain, SHA-256 pins, backup pin, expiry)
    - cleartext traffic permission
    - related findings
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from tls_pineval.models.common import Confidence, Finding, Severity
from tls_pineval.models.static_report import NSCResult, PinSet

logger = logging.getLogger(__name__)

_NSC_ROOT_TAG = "network-security-config"

# Canonical filenames tried first for speed; fallback scans all XML by root tag.
_NSC_CANONICAL_NAMES = {
    "network_security_config.xml",
    "network_config.xml",
}


def _find_nsc_files(apktool_dir: Path) -> list[Path]:
    """Search for all NSC files by filename or by XML root tag.

    APKTool sometimes renames resource files to APKTOOL_RENAMED_0xNNNN.xml
    when it cannot resolve the resource name (happens with split APKs or
    obfuscated resource tables).  Fallback: scan all XML files in res/xml/
    and return any whose root element is <network-security-config>.
    """
    xml_dirs: list[Path] = []
    for candidate_dir in apktool_dir.rglob("res/xml"):
        if candidate_dir.is_dir():
            xml_dirs.append(candidate_dir)

    found: list[Path] = []

    # Fast path: canonical names first.
    for xml_dir in xml_dirs:
        for name in _NSC_CANONICAL_NAMES:
            candidate = xml_dir / name
            if candidate.is_file() and candidate not in found:
                found.append(candidate)

    # Slow path: scan all XML files and check root tag.
    for xml_dir in xml_dirs:
        for xml_file in sorted(xml_dir.glob("*.xml")):
            if xml_file in found:
                continue
            try:
                tree = ET.parse(xml_file)
                if tree.getroot().tag == _NSC_ROOT_TAG:
                    logger.info("Found NSC by root tag scan: %s", xml_file.name)
                    found.append(xml_file)
            except ET.ParseError:
                continue

    return found


def _parse_pin_sets(root: ET.Element) -> list[PinSet]:
    """Extract all <pin-set> entries from the NSC XML.

    Covers both <base-config> (global scope) and <domain-config> (per-domain)
    elements.  Previously only <domain-config> was searched, which missed apps
    that place their pin-sets inside <base-config>.
    """
    pin_sets: list[PinSet] = []

    # Build a list of (config_element, domain_labels) to process uniformly.
    # base-config has no domain; domain-config lists one or more domains.
    config_items: list[tuple[ET.Element, list[str]]] = []

    base_config = root.find("base-config")
    if base_config is not None:
        config_items.append((base_config, ["<base-config>"]))

    for domain_config in root.iter("domain-config"):
        domains: list[str] = []
        for domain_el in domain_config.findall("domain"):
            d = domain_el.text or ""
            include_subdomains = domain_el.get("includeSubdomains", "false")
            if include_subdomains.lower() == "true":
                d = f"*.{d}"
            if d:
                domains.append(d)
        config_items.append((domain_config, domains if domains else ["<domain-config>"]))

    for config_el, domains in config_items:
        for pin_set_el in config_el.findall("pin-set"):
            expiry = pin_set_el.get("expiration")
            pins: list[str] = []

            for pin_el in pin_set_el.findall("pin"):
                digest = pin_el.get("digest", "")
                value = (pin_el.text or "").strip()
                if value:
                    pins.append(f"{digest}/{value}" if digest else value)

            has_backup = len(pins) >= 2
            domain_str = ", ".join(domains)
            pin_sets.append(
                PinSet(
                    domain=domain_str,
                    pins=pins,
                    expiry=expiry,
                    has_backup=has_backup,
                )
            )

    return pin_sets


def _check_cleartext(root: ET.Element) -> bool:
    """Check if cleartextTrafficPermitted is enabled anywhere."""
    # Check base-config
    base = root.find("base-config")
    if base is not None:
        ct = base.get("cleartextTrafficPermitted", "").lower()
        if ct == "true":
            return True

    # Check domain-configs
    for dc in root.iter("domain-config"):
        ct = dc.get("cleartextTrafficPermitted", "").lower()
        if ct == "true":
            return True

    return False


def _analyze_single_nsc(nsc_file: Path, findings: list[Finding]) -> tuple[list[PinSet], bool]:
    """Parse one NSC file and append findings.  Returns (pin_sets, cleartext_allowed)."""
    try:
        tree = ET.parse(nsc_file)
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.warning("Failed to parse NSC XML %s: %s", nsc_file.name, exc)
        findings.append(
            Finding(
                id=f"NSC-002-{nsc_file.name[:20]}",
                category="nsc",
                description=f"Malformed network_security_config file: {exc}",
                location=str(nsc_file),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                raw_evidence="",
            )
        )
        return [], False

    pin_sets = _parse_pin_sets(root)
    cleartext_allowed = _check_cleartext(root)

    for ps in pin_sets:
        sha256_pins = [
            p for p in ps.pins
            if p.lower().startswith("sha-256/") or p.lower().startswith("sha256/")
        ]

        findings.append(
            Finding(
                id=f"NSC-PIN-{ps.domain[:30]}",
                category="nsc",
                description=f"Pin-set found for domain '{ps.domain}' with {len(ps.pins)} pin(s)",
                location=str(nsc_file),
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                raw_evidence=f"pins={ps.pins}, expiry={ps.expiry}, backup={ps.has_backup}",
            )
        )

        if sha256_pins:
            findings.append(
                Finding(
                    id=f"NSC-SHA256-{ps.domain[:30]}",
                    category="nsc",
                    description=f"SHA-256 pin hashing used for '{ps.domain}'",
                    location=str(nsc_file),
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    raw_evidence=", ".join(sha256_pins[:3]),
                )
            )

        if not ps.has_backup:
            findings.append(
                Finding(
                    id=f"NSC-NOBACKUP-{ps.domain[:30]}",
                    category="nsc",
                    description=f"No backup pin for '{ps.domain}' — cert rotation may break app",
                    location=str(nsc_file),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    raw_evidence=f"pins count: {len(ps.pins)}",
                )
            )

        if ps.expiry is None:
            findings.append(
                Finding(
                    id=f"NSC-NOEXPIRY-{ps.domain[:30]}",
                    category="nsc",
                    description=f"No pin expiry set for '{ps.domain}' — stale pins risk",
                    location=str(nsc_file),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    raw_evidence="",
                )
            )

    if cleartext_allowed:
        findings.append(
            Finding(
                id=f"NSC-CLEARTEXT-{nsc_file.name[:20]}",
                category="nsc",
                description="Cleartext (HTTP) traffic is explicitly permitted",
                location=str(nsc_file),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                raw_evidence="cleartextTrafficPermitted=true",
            )
        )

    return pin_sets, cleartext_allowed


def analyze_nsc(apktool_dir: Path) -> tuple[NSCResult, list[Finding]]:
    """Analyze network_security_config.xml from decompiled APK.

    Args:
        apktool_dir: Path to APKTool decompiled output directory.

    Returns:
        Tuple of (NSCResult, list of related Findings).
    """
    findings: list[Finding] = []
    nsc_files = _find_nsc_files(apktool_dir)

    if not nsc_files:
        logger.info("No network_security_config.xml found")
        findings.append(
            Finding(
                id="NSC-001",
                category="nsc",
                description="No network_security_config.xml found in APK",
                location="res/xml/",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                raw_evidence="",
            )
        )
        return NSCResult(found=False), findings

    logger.info("Found %d NSC file(s): %s", len(nsc_files), [f.name for f in nsc_files])

    all_pin_sets: list[PinSet] = []
    any_cleartext = False

    for nsc_file in nsc_files:
        pin_sets, cleartext = _analyze_single_nsc(nsc_file, findings)
        all_pin_sets.extend(pin_sets)
        if cleartext:
            any_cleartext = True

    if not all_pin_sets:
        findings.append(
            Finding(
                id="NSC-NOPIN",
                category="nsc",
                description="NSC exists but contains no pin-set entries",
                location=str(nsc_files[0]),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                raw_evidence="",
            )
        )

    return (
        NSCResult(
            found=True,
            pin_sets=all_pin_sets,
            cleartext_allowed=any_cleartext,
        ),
        findings,
    )
