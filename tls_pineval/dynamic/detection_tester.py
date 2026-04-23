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

# Substrings in Frida exception messages that indicate the app terminated
# on its own after detecting instrumentation.
_CRASH_KEYWORDS = ("killed", "process", "crash", "detach", "terminate", "closed")


def test_detection(
    device: Any,
    package_name: str,
    detection_script: str,
    *,
    timeout: int = 10,
) -> DetectionResults:
    """Attach Frida to the app and observe self-defense behaviour.

    The detection script monitors Root/debugger checks without altering
    any TLS logic.  If the app crashes while Frida is attached we infer
    Frida detection; individual send() messages report root/debugger checks.

    Args:
        device: Frida device object.
        package_name: Android package identifier.
        detection_script: Full Frida JS for the detection_check.js script.
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
                logger.debug("Root check observed: %s", payload.get("cmd"))
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
        if any(kw in err for kw in _CRASH_KEYWORDS):
            frida_detected = True
            app_reaction = AppReaction.CRASH
            logger.info("App crashed while Frida was attached — Frida detection inferred")
        else:
            logger.debug("Detection test exception: %s", exc)
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
