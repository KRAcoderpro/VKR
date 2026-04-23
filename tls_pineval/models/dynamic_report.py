"""Dynamic analysis report models (V2 §5.4).

Defines:
    Environment      — Device/emulator metadata captured during dynamic analysis
    BypassAttempt    — A single bypass attempt with verification result
    DetectionResults — App reaction to Frida, root, and debugger presence
    MITMCheck        — Optional MITM traffic interception check
    DynamicReport    — Complete dynamic analysis output
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from tls_pineval.models.common import (
    AppInfo,
    AppReaction,
    Confidence,
    HookTarget,
    MITMStatus,
    VerificationResult,
)


class Environment(BaseModel):
    """Device/emulator metadata captured at the start of dynamic analysis.

    Records the execution environment for reproducibility.
    """

    device_id: str = Field(
        ...,
        description="ADB device identifier, e.g. 'emulator-5554' or 'XXXXXXXX'",
    )
    android_version: str = Field(
        ...,
        description="Android version string, e.g. '14' or '11'",
    )
    frida_version: str = Field(
        ...,
        description="Frida client version, e.g. '16.2.1'",
    )
    is_rooted: bool = Field(
        default=False,
        description="Whether the device has root access",
    )


class BypassAttempt(BaseModel):
    """A single TLS pinning bypass attempt with verification (V2 §5.4).

    Incorporates CRITICAL-1 fix: bypass success is verified via logcat
    or MITM traffic, not just whether the Frida hook callback fired.
    """

    script_name: str = Field(
        ...,
        description="Name of the Frida script used, e.g. 'generic_unpinner' or 'trustmanager_hook'",
    )
    target: Optional[HookTarget] = Field(
        default=None,
        description="The specific HookTarget this attempt hooks. None for generic scripts.",
    )
    hook_triggered: bool = Field(
        default=False,
        description="Whether the Frida hook callback actually fired during execution",
    )
    verification: VerificationResult = Field(
        default=VerificationResult.INCONCLUSIVE,
        description=(
            "Verified outcome of the bypass attempt. "
            "SUCCESS = bypass confirmed (traffic intercepted or no SSL errors). "
            "FAILED = hook fired but TLS still enforced. "
            "INCONCLUSIVE = no network activity observed."
        ),
    )
    verification_method: str = Field(
        default="hook_only",
        description="How verification was performed: 'logcat', 'mitm', or 'hook_only'",
    )
    confidence: Confidence = Field(
        default=Confidence.MEDIUM,
        description="Confidence in this bypass result",
    )
    duration_ms: int = Field(
        default=0,
        description="Duration of the bypass attempt in milliseconds",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if the attempt failed or raised an exception",
    )
    generated_script: str = Field(
        default="",
        description=(
            "Full Frida JavaScript source code that was generated and injected. "
            "Stored for thesis evidence and reproducibility."
        ),
    )
    logs: list[str] = Field(
        default_factory=list,
        description="Raw log lines captured during this attempt (Frida + logcat)",
    )


class DetectionResults(BaseModel):
    """Results of testing whether the app detects instrumentation (V2 §5.4).

    Checks for Frida detection, root detection, and debugger detection,
    and records how the app reacts (crash, block, ignore, or none).
    """

    frida_detected: bool = Field(
        default=False,
        description="Whether the app detected Frida instrumentation",
    )
    root_detected: bool = Field(
        default=False,
        description="Whether the app detected a rooted environment",
    )
    debugger_detected: bool = Field(
        default=False,
        description="Whether the app detected a debugger attached",
    )
    app_reaction: AppReaction = Field(
        default=AppReaction.NONE,
        description="How the app reacted to detection: CRASH, BLOCK, IGNORE, or NONE",
    )


class MITMCheck(BaseModel):
    """Result of the optional MITM traffic interception check (V2 §5.4).

    In V1 this is minimal: just a connectivity check, not full mitmproxy
    orchestration.
    """

    status: MITMStatus = Field(
        default=MITMStatus.SKIPPED,
        description="MITM check result: SUCCESS, FAILED, INCONCLUSIVE, or SKIPPED",
    )
    note: str = Field(
        default="",
        description="Additional context about the MITM check result",
    )


class DynamicReport(BaseModel):
    """Complete output of the dynamic analysis module (V2 §5.4).

    Contains all bypass attempts with verification, detection test results,
    optional MITM check, and overall bypass outcome.
    """

    app_info: AppInfo
    environment: Environment
    bypass_attempts: list[BypassAttempt] = Field(
        default_factory=list,
        description="All bypass attempts executed during dynamic analysis",
    )
    detection_results: DetectionResults = Field(
        default_factory=DetectionResults,
        description="Results of anti-Frida/root/debug detection tests",
    )
    mitm_check: MITMCheck = Field(
        default_factory=MITMCheck,
        description="Optional MITM traffic interception check result",
    )
    overall_bypass: bool = Field(
        default=False,
        description="Whether any bypass attempt was verified as successful",
    )
    targeted_bypass_needed: bool = Field(
        default=False,
        description=(
            "Whether targeted (static-analysis-guided) hooks were needed to bypass. "
            "False if generic script was sufficient, or if no bypass succeeded."
        ),
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="When the dynamic analysis was performed",
    )
