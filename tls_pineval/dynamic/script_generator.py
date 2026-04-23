"""Frida JavaScript generator for TLS-PinEval (V2 §4.3).

Loads standalone scripts from the scripts/ directory and generates
targeted bypass scripts from HookTarget metadata.
"""

from __future__ import annotations

from pathlib import Path

from tls_pineval.models.common import HookCategory, HookTarget

_SCRIPTS_DIR = Path(__file__).parent / "scripts"


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def generate_generic_script() -> str:
    """Return the generic TLS unpinner Frida script."""
    return (_SCRIPTS_DIR / "generic_unpinner.js").read_text(encoding="utf-8")


def generate_detection_script() -> str:
    """Return the detection check Frida script."""
    return (_SCRIPTS_DIR / "detection_check.js").read_text(encoding="utf-8")


def generate_targeted_script(target: HookTarget) -> str:
    """Generate a targeted Frida bypass script for the given HookTarget.

    Selects the correct template based on *target.category* and substitutes:
    - ``{{CLASS_NAME}}``     — target.class_name
    - ``{{METHOD_NAME}}``    — target.method_name
    - ``{{OVERLOADS_CODE}}`` — per-overload hook code

    If *target.overloads* is empty, all overloads are hooked via
    ``.overloads.forEach()`` (fallback mode, confidence MEDIUM).
    """
    if target.category == HookCategory.WEBVIEW_SSL:
        template_name = "webview_hook.js"
    elif target.category == HookCategory.CERTIFICATE_PINNER:
        template_name = "okhttp_hook.js"
    else:
        template_name = "trustmanager_hook.js"

    template = (_SCRIPTS_DIR / template_name).read_text(encoding="utf-8")
    overloads_code = _build_overloads_code(target)

    return (
        template
        .replace("{{CLASS_NAME}}", target.class_name)
        .replace("{{METHOD_NAME}}", target.method_name)
        .replace("{{OVERLOADS_CODE}}", overloads_code)
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _build_overloads_code(target: HookTarget) -> str:
    """Return JavaScript that installs hooks for all overloads."""
    method = target.method_name
    category = target.category
    body = _hook_body(method, category)

    if not target.overloads:
        # Hook-all-overloads fallback
        return (
            f"TargetClass['{method}'].overloads.forEach(function (o) {{\n"
            f"    o.implementation = function () {{\n"
            f"        {body}\n"
            f"    }};\n"
            f"}});"
        )

    blocks: list[str] = []
    for overload_str in target.overloads:
        params = [p.strip() for p in overload_str.split(",") if p.strip()]
        quoted_params = ", ".join(f'"{p}"' for p in params)
        blocks.append(
            f"TargetClass['{method}'].overload({quoted_params}).implementation = "
            f"function () {{\n"
            f"            {body}\n"
            f"        }};"
        )

    return "\n        ".join(blocks)


def _hook_body(method: str, category: HookCategory) -> str:
    """Return the JS body (send + return expression) for a hooked method."""
    send_stmt = f"send({{ type: 'hook_triggered', method: '{method}' }});"

    if category == HookCategory.HOSTNAME_VERIFIER:
        return f"{send_stmt}\n            return true;"
    if category == HookCategory.WEBVIEW_SSL:
        # arguments[1] is the SslErrorHandler
        return f"{send_stmt}\n            arguments[1].proceed();"
    # TRUST_MANAGER, CERTIFICATE_PINNER, CUSTOM — void; just return
    return f"{send_stmt}\n            return;"
