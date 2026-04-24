"""Frida bypass execution and logcat-based verification (V2 §4.3, CRITICAL-1).

Implements the CRITICAL-1 fix: hook firing is NOT treated as bypass success.
Verification is done via logcat monitoring — SSL error patterns → FAILED,
HTTP 200 patterns → SUCCESS, no network activity → INCONCLUSIVE.

Key design decisions:
- Logcat is started AFTER spawn() so we know the PID for precise filtering.
- Logcat is filtered by PID to avoid SSL errors from other system processes.
- SSL-fail check still takes priority over HTTP-ok to avoid false SUCCESS
  when a hook error coexists with unrelated successful HTTP traffic.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Any, Optional

from tls_pineval.models.common import Confidence, HookTarget, VerificationResult
from tls_pineval.models.dynamic_report import BypassAttempt

logger = logging.getLogger(__name__)

# logcat patterns that confirm bypass FAILED (TLS still enforced)
_SSL_FAIL_PATTERNS: list[str] = [
    "SSLHandshakeException",
    "SSLPeerUnverifiedException",
    "CERTIFICATE_VERIFY_FAILED",
    "CertPathValidatorException",
    "certificate verify failed",
    "Trust anchor for certification path not found",
    "SSL_ERROR_BAD_CERT",
]

# logcat patterns that confirm bypass SUCCEEDED (traffic flowing)
_HTTP_OK_PATTERNS: list[str] = [
    "HTTP/1.1 200",
    "HTTP/2 200",
    "<-- 200 ",
    "200 OK",
    "onResponse",  # OkHttp callback indicating a successful response
]


class _LogcatMonitor:
    """Captures adb logcat output in a background thread, filtered by device and PID."""

    def __init__(self, device_id: str, pid: int) -> None:
        self._device_id = device_id
        self._pid = pid
        self._proc: Optional[subprocess.Popen[str]] = None
        self._lines: list[str] = []
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        # Clear stale logcat entries for this specific device
        try:
            subprocess.run(
                ["adb", "-s", self._device_id, "logcat", "-c"],
                capture_output=True,
                timeout=5,
            )
        except Exception:
            pass

        # Filter by PID so only the target app's logs are captured.
        # --pid is supported from Android 7 (API 24) onward; on older devices
        # the flag is silently ignored and all processes are captured.
        cmd = [
            "adb", "-s", self._device_id,
            "logcat", "-v", "tag",
            f"--pid={self._pid}",
        ]
        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            self._thread = threading.Thread(target=self._read, daemon=True)
            self._thread.start()
        except Exception as exc:
            logger.warning("Failed to start logcat monitor: %s", exc)

    def _read(self) -> None:
        try:
            assert self._proc is not None
            assert self._proc.stdout is not None
            for line in self._proc.stdout:
                with self._lock:
                    self._lines.append(line.rstrip())
        except Exception:
            pass

    def stop(self) -> list[str]:
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        with self._lock:
            return list(self._lines)


def _classify_logcat(lines: list[str]) -> tuple[VerificationResult, str]:
    """Classify bypass outcome from logcat lines.

    Priority: FAILED (SSL error) > SUCCESS (HTTP 200) > INCONCLUSIVE.

    SSL errors take priority because a failed bypass that also produces some
    HTTP traffic (e.g. from an unrelated endpoint) must not be reported as
    SUCCESS.  The caller is responsible for ensuring logcat is PID-filtered
    to reduce noise from other processes.
    """
    text = "\n".join(lines)
    for pattern in _SSL_FAIL_PATTERNS:
        if pattern in text:
            return VerificationResult.FAILED, "logcat"
    for pattern in _HTTP_OK_PATTERNS:
        if pattern in text:
            return VerificationResult.SUCCESS, "logcat"
    return VerificationResult.INCONCLUSIVE, "logcat"


def run_bypass(
    device: Any,
    package_name: str,
    script_js: str,
    script_name: str,
    device_id: str,
    target: Optional[HookTarget] = None,
    *,
    timeout: int = 15,
) -> BypassAttempt:
    """Execute one bypass attempt and verify via logcat.

    Args:
        device: Frida device object (frida.core.Device).
        package_name: Android package identifier to spawn.
        script_js: Full Frida JavaScript to inject.
        script_name: Human-readable name stored in the result.
        device_id: ADB device serial used for logcat and adb commands.
        target: HookTarget this attempt addresses, or None for generic.
        timeout: Seconds to wait for network activity before giving up.

    Returns:
        BypassAttempt with hook_triggered, verification, logs, etc.
    """
    start_ms = int(time.monotonic() * 1000)
    hook_triggered = False
    logs: list[str] = []
    error: Optional[str] = None
    pid: Optional[int] = None
    session: Any = None
    logcat: Optional[_LogcatMonitor] = None

    try:
        # Spawn first so we have the PID before starting logcat, enabling
        # precise PID-based filtering (eliminates SSL noise from other apps).
        pid = device.spawn([package_name])

        logcat = _LogcatMonitor(device_id=device_id, pid=pid)
        logcat.start()

        session = device.attach(pid)

        def _on_message(message: dict, data: Any) -> None:
            nonlocal hook_triggered
            if message.get("type") == "send":
                payload = message.get("payload", {})
                if isinstance(payload, dict) and payload.get("type") == "hook_triggered":
                    hook_triggered = True
            logs.append(str(message))

        script = session.create_script(script_js)
        script.on("message", _on_message)
        script.load()
        device.resume(pid)

        time.sleep(timeout)

    except Exception as exc:
        error = str(exc)
        logger.debug("Bypass attempt exception: %s", exc)
    finally:
        try:
            if session is not None:
                session.detach()
        except Exception:
            pass
        try:
            if pid is not None:
                device.kill(pid)
        except Exception:
            pass

    logcat_lines = logcat.stop() if logcat is not None else []
    logs.extend(logcat_lines[:200])

    duration_ms = int(time.monotonic() * 1000) - start_ms

    if error and not hook_triggered:
        # Script failed to load — can't make a determination
        verification = VerificationResult.INCONCLUSIVE
        verification_method = "hook_only"
        confidence = Confidence.LOW
    else:
        verification, verification_method = _classify_logcat(logcat_lines)
        confidence = (
            Confidence.MEDIUM
            if verification == VerificationResult.INCONCLUSIVE
            else Confidence.HIGH
        )

    logger.info(
        "Bypass '%s': hook_triggered=%s verification=%s",
        script_name, hook_triggered, verification.value,
    )

    return BypassAttempt(
        script_name=script_name,
        target=target,
        hook_triggered=hook_triggered,
        verification=verification,
        verification_method=verification_method,
        confidence=confidence,
        duration_ms=duration_ms,
        error=error,
        generated_script=script_js,
        logs=logs,
    )
