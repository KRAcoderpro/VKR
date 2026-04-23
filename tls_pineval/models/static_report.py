"""Static analysis report models (V2 §5.3).

Defines:
    PinSet            — A single pin-set entry from network_security_config.xml
    NSCResult         — Network Security Configuration analysis result
    PinningImpl       — A detected TLS pinning implementation in code
    ProtectionProfile — Anti-reverse-engineering protection indicators
    StaticReport      — Complete static analysis output
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from tls_pineval.models.common import (
    AppInfo,
    Confidence,
    Finding,
    HookCategory,
    HookTarget,
    ObfuscationLevel,
)


class PinSet(BaseModel):
    """A single ``<pin-set>`` entry from ``network_security_config.xml``.

    Captures the domain scope, pinned key hashes, expiration date,
    and whether a backup pin is configured.
    """

    domain: str = Field(
        ...,
        description="Domain the pin-set applies to, e.g. '*.example.com'",
    )
    pins: list[str] = Field(
        default_factory=list,
        description="SHA-256 public key hashes, e.g. ['sha256/AAAA...']",
    )
    expiry: Optional[str] = Field(
        default=None,
        description="Pin expiration date as string, e.g. '2026-01-01', or None if not set",
    )
    has_backup: bool = Field(
        default=False,
        description="Whether at least one backup pin is configured",
    )


class NSCResult(BaseModel):
    """Analysis result for ``network_security_config.xml`` (V2 §5.3).

    ``found`` is False when the APK does not contain a network security
    config at all — in that case ``pin_sets`` will be empty.
    """

    found: bool = Field(
        default=False,
        description="Whether network_security_config.xml exists in the APK",
    )
    pin_sets: list[PinSet] = Field(
        default_factory=list,
        description="All <pin-set> entries found in the config",
    )
    cleartext_allowed: bool = Field(
        default=False,
        description="Whether cleartextTrafficPermitted is true (insecure)",
    )


class PinningImpl(BaseModel):
    """A detected TLS pinning implementation in decompiled code.

    Each instance represents one class/method that participates in
    certificate or hostname validation.
    """

    type: HookCategory = Field(
        ...,
        description="Implementation type: TRUST_MANAGER, CERTIFICATE_PINNER, etc.",
    )
    class_name: str = Field(
        ...,
        description="Fully-qualified class name, e.g. 'com.app.ssl.CustomTrustManager'",
    )
    is_vulnerable: bool = Field(
        default=False,
        description=(
            "Whether this implementation is insecure: "
            "trust-all TrustManager, allow-all HostnameVerifier, "
            "or proceed-on-error in WebView"
        ),
    )
    confidence: Confidence = Field(
        default=Confidence.HIGH,
        description="Confidence in the detection accuracy",
    )


class ProtectionProfile(BaseModel):
    """Anti-reverse-engineering and runtime protection indicators (V2 §5.3).

    Captures obfuscation level, native library usage, integrity checks,
    and root detection — all relevant to C2 (Static Bypass Resistance)
    and C4 (Comprehensive Protection) scoring.
    """

    obfuscation_level: ObfuscationLevel = Field(
        default=ObfuscationLevel.NONE,
        description="Detected obfuscation level: NONE, BASIC, or STRONG",
    )
    native_libs: list[str] = Field(
        default_factory=list,
        description="Paths to native .so libraries found in the APK",
    )
    integrity_checks: list[str] = Field(
        default_factory=list,
        description="Detected integrity check mechanisms, e.g. ['SafetyNet', 'Play Integrity']",
    )
    root_detection: bool = Field(
        default=False,
        description="Whether root/environment detection code was found",
    )


class StaticReport(BaseModel):
    """Complete output of the static analysis module (V2 §5.3).

    Contains all findings, structured analysis results, and the
    ``hookable_targets`` list that bridges static → dynamic analysis.
    """

    app_info: AppInfo
    findings: list[Finding] = Field(
        default_factory=list,
        description="Flat list of all findings from static analysis",
    )
    nsc: NSCResult = Field(
        default_factory=NSCResult,
        description="Network Security Configuration analysis",
    )
    pinning_implementations: list[PinningImpl] = Field(
        default_factory=list,
        description="All detected TLS pinning implementations in code",
    )
    protection: ProtectionProfile = Field(
        default_factory=ProtectionProfile,
        description="Anti-RE and runtime protection profile",
    )
    hookable_targets: list[HookTarget] = Field(
        default_factory=list,
        description=(
            "TLS-related methods suitable for Frida hooking. "
            "This is the bridge between static and dynamic analysis."
        ),
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the static analysis was performed",
    )
