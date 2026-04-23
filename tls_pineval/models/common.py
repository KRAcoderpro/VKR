"""Common enums and base models shared across all TLS-PinEval modules.

Defines:
    Enums      — Confidence, Severity, SecurityLevel, HookCategory,
                 AppReaction, VerificationResult, MITMStatus, ObfuscationLevel
    Models     — AppInfo, Finding, HookTarget
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums (V2 §5.1)
# ---------------------------------------------------------------------------


class Confidence(str, Enum):
    """Detection confidence level.

    HIGH   — deterministic check, clear evidence
    MEDIUM — heuristic match, likely correct but not certain
    LOW    — indirect indicator, may be false positive/negative
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Severity(str, Enum):
    """Finding severity level, following standard security severity scale."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SecurityLevel(str, Enum):
    """Final security assessment level (V2 §6 — Aggregation).

    HIGH     — 85–100 points
    MEDIUM   — 60–84  points
    LOW      — 30–59  points
    CRITICAL —  0–29  points
    """

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CRITICAL = "CRITICAL"


class HookCategory(str, Enum):
    """Category of a hookable TLS pinning target."""

    TRUST_MANAGER = "TRUST_MANAGER"
    CERTIFICATE_PINNER = "CERTIFICATE_PINNER"
    HOSTNAME_VERIFIER = "HOSTNAME_VERIFIER"
    WEBVIEW_SSL = "WEBVIEW_SSL"
    CUSTOM = "CUSTOM"


class AppReaction(str, Enum):
    """How the application reacts to detection of instrumentation / tampering."""

    CRASH = "CRASH"
    BLOCK = "BLOCK"
    IGNORE = "IGNORE"
    NONE = "NONE"


class VerificationResult(str, Enum):
    """Result of bypass verification (CRITICAL-1 fix).

    SUCCESS      — bypass confirmed via logcat / MITM traffic
    FAILED       — hook fired but TLS connection still failed
    INCONCLUSIVE — no network activity observed or check was skipped
    """

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class MITMStatus(str, Enum):
    """Status of the optional MITM traffic interception check."""

    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"


class ObfuscationLevel(str, Enum):
    """Detected level of code obfuscation."""

    NONE = "NONE"
    BASIC = "BASIC"
    STRONG = "STRONG"


# ---------------------------------------------------------------------------
# Core Models (V2 §5.2)
# ---------------------------------------------------------------------------


class AppInfo(BaseModel):
    """Basic metadata extracted from the APK during static analysis."""

    apk_path: Path
    package_name: str
    app_name: str = ""
    version: str = ""
    min_sdk: int = 0
    target_sdk: int = 0

    model_config = {"json_encoders": {Path: str}}


class Finding(BaseModel):
    """A single finding from static or dynamic analysis.

    Each finding carries a unique ID, category tag, human-readable
    description, source location, severity, confidence, and a snippet
    of the matched code / config as evidence.
    """

    id: str
    category: str = Field(
        ...,
        description=(
            "Finding category: nsc | okhttp | trustmanager | hostname "
            "| webview | protection | secrets"
        ),
    )
    description: str
    location: str = Field(
        ...,
        description="Source location, e.g. 'file.smali:42' or 'com.app.Net.check'",
    )
    severity: Severity
    confidence: Confidence
    raw_evidence: str = Field(
        default="",
        description="Matched code/config snippet used as evidence",
    )


class HookTarget(BaseModel):
    """A TLS-related method that can be hooked with Frida during dynamic analysis.

    This is the **bridge** between static and dynamic analysis (V2 §4.2).
    Static analyzer extracts these; dynamic analyzer uses them to generate
    targeted Frida scripts.

    The ``overloads`` field stores Java method descriptors for precise hooking.
    An empty list means "hook all overloads" (fallback, confidence MEDIUM).
    """

    class_name: str = Field(
        ...,
        description="Fully-qualified Java class name, e.g. 'com.app.net.PinManager'",
    )
    method_name: str = Field(
        ...,
        description="Method name to hook, e.g. 'checkServerTrusted'",
    )
    category: HookCategory
    overloads: list[str] = Field(
        default_factory=list,
        description=(
            "Java parameter type descriptors for each known overload, "
            "e.g. ['[Ljava.security.cert.X509Certificate;, java.lang.String']. "
            "Empty list = hook all overloads (fallback)."
        ),
    )
    source_file: str = Field(
        ...,
        description="File where the target was found, e.g. 'com/app/net/PinManager.smali'",
    )
    confidence: Confidence
