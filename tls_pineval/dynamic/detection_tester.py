"""Detection capability testing (V2 §4.3).

Tests whether the app actively detects Frida instrumentation, root access,
and debugger presence.  The app is spawned with a passive monitoring script —
no hooks modify TLS behaviour during detection testing.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from tls_pineval.models.common import AppReaction
from tls_pineval.models.dynamic_report import DetectionResults

logger = logging.getLogger(__name__)

# Substrings that appear specifically in Frida exception messages when the
# target process terminates itself in response to instrumentation.  These are
# intentionally narrow to avoid false positives from generic Android exceptions
# that contain words like "process" or "closed".
_CRASH_KEYWORDS = (
    "frida",
    "gadget",
    "instrumentation",
    "jdwp",
    "process exited",
    "process terminated",
    "process killed",
)


def test_detection(
    device: Any,
    package_name: str,
    detection_script: str,
    device_id: str,
    *,
    timeout: int = 10,
) -> DetectionResults:
    """Attach Frida to the app and observe self-defense behaviour.

    The detection script monitors Root/debugger checks without altering
    any TLS logic.  If the app terminates while Frida is attached we infer
    Frida detection; individual send() messages report root/debugger checks.

    Args:
        device: Frida device object.
        package_name: Android package identifier.
        detection_script: Full Frida JS for the detection_check.js script.
        device_id: ADB device serial (used for targeted logcat if needed).
        timeout: Seconds to observe the app.

    Returns:
        DetectionResults populated from observed events.
    """
    frida_detected = False
    root_detected = False
    debugger_detected = False
    app_reaction = AppReaction.NONE

    pid: int | None = None
    session: Any = None

    try:
        pid = device.spawn([package_name])
        session = device.attach(pid)

        def _on_message(message: dict, data: Any) -> None:
            nonlocal root_detected, debugger_detected
            if message.get("type") != "send":
                return
            payload = message.get("payload", {})
            if not isinstance(payload, dict):
                return
            event = payload.get("type")
            if event == "root_check":
                root_detected = True
                logger.debug("Root check (exec): %s", payload.get("cmd"))
            elif event == "file_root_check":
                # File.exists() / File.canExecute() on known root paths
                root_detected = True
                logger.debug(
                    "Root check (file.%s): %s",
                    payload.get("method", "?"),
                    payload.get("path", "?"),
                )
            elif event == "package_root_check":
                # PackageManager.getPackageInfo() for known root packages
                root_detected = True
                logger.debug("Root check (package): %s", payload.get("package", "?"))
            elif event == "debugger_check":
                debugger_detected = True
                logger.debug("Debugger check observed")

        script = session.create_script(detection_script)
        script.on("message", _on_message)
        script.load()
        device.resume(pid)

        time.sleep(timeout)

    except Exception as exc:
        err = str(exc).lower()
        # Only infer Frida detection when the exception text contains keywords
        # that are specific to Frida's own error messages, not generic Android
        # errors (e.g. "process", "closed", "killed" match too broadly).
        if any(kw in err for kw in _CRASH_KEYWORDS):
            frida_detected = True
            app_reaction = AppReaction.CRASH
            logger.info(
                "App terminated while Frida was attached — Frida detection inferred: %s", exc
            )
        else:
            logger.debug("Detection test exception (not Frida detection): %s", exc)
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

    return DetectionResults(
        frida_detected=frida_detected,
        root_detected=root_detected,
        debugger_detected=debugger_detected,
        app_reaction=app_reaction,
    )
