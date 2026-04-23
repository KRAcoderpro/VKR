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

# Possible locations for the NSC file inside the decompiled APK
_NSC_PATHS = [
    "res/xml/network_security_config.xml",
    "res/xml/network_config.xml",
]


def _find_nsc_file(apktool_dir: Path) -> Optional[Path]:
    """Search for the NSC file in known locations."""
    for rel in _NSC_PATHS:
        candidate = apktool_dir / rel
        if candidate.is_file():
            return candidate
    return None


def _parse_pin_sets(root: ET.Element) -> list[PinSet]:
    """Extract all <pin-set> entries from the NSC XML."""
    pin_sets: list[PinSet] = []

    for domain_config in root.iter("domain-config"):
        # Get domains this config applies to
        domains: list[str] = []
        for domain_el in domain_config.findall("domain"):
            d = domain_el.text or ""
            include_subdomains = domain_el.get("includeSubdomains", "false")
            if include_subdomains.lower() == "true":
                d = f"*.{d}"
            if d:
                domains.append(d)

        # Get pin-sets
        for pin_set_el in domain_config.findall("pin-set"):
            expiry = pin_set_el.get("expiration")
            pins: list[str] = []

            for pin_el in pin_set_el.findall("pin"):
                digest = pin_el.get("digest", "")
                value = (pin_el.text or "").strip()
                if value:
                    pins.append(f"{digest}/{value}" if digest else value)

            has_backup = len(pins) >= 2

            domain_str = ", ".join(domains) if domains else "<base-config>"
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


def analyze_nsc(apktool_dir: Path) -> tuple[NSCResult, list[Finding]]:
    """Analyze network_security_config.xml from decompiled APK.

    Args:
        apktool_dir: Path to APKTool decompiled output directory.

    Returns:
        Tuple of (NSCResult, list of related Findings).
    """
    findings: list[Finding] = []
    nsc_file = _find_nsc_file(apktool_dir)

    if nsc_file is None:
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

    # Parse XML
    try:
        tree = ET.parse(nsc_file)
        root = tree.getroot()
    except ET.ParseError as exc:
        logger.warning("Failed to parse NSC XML: %s", exc)
        findings.append(
            Finding(
                id="NSC-002",
                category="nsc",
                description=f"Malformed network_security_config.xml: {exc}",
                location=str(nsc_file),
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                raw_evidence="",
            )
        )
        return NSCResult(found=True), findings

    # Extract data
    pin_sets = _parse_pin_sets(root)
    cleartext_allowed = _check_cleartext(root)

    # Generate findings
    if pin_sets:
        for ps in pin_sets:
            sha256_pins = [p for p in ps.pins if p.lower().startswith("sha-256/") or p.lower().startswith("sha256/")]
            non_sha256 = [p for p in ps.pins if p not in sha256_pins]

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
    else:
        findings.append(
            Finding(
                id="NSC-NOPIN",
                category="nsc",
                description="NSC exists but contains no pin-set entries",
                location=str(nsc_file),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                raw_evidence="",
            )
        )

    if cleartext_allowed:
        findings.append(
            Finding(
                id="NSC-CLEARTEXT",
                category="nsc",
                description="Cleartext (HTTP) traffic is explicitly permitted",
                location=str(nsc_file),
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                raw_evidence="cleartextTrafficPermitted=true",
            )
        )

    return (
        NSCResult(
            found=True,
            pin_sets=pin_sets,
            cleartext_allowed=cleartext_allowed,
        ),
        findings,
    )
