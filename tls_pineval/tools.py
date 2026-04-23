"""Thin wrappers for external tool invocation (V2 §4.1).

Provides subprocess-based wrappers for APKTool and Jadx.
No lifecycle management — call tool, return path to output.

Each function raises ``ToolError`` if the tool is not found or fails.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolError(Exception):
    """Raised when an external tool invocation fails."""


def _find_tool(name: str) -> str:
    """Locate a tool on PATH, raise ``ToolError`` if not found.

    On Windows, bare names like 'jadx' may resolve to a Unix shell script
    that cannot be executed directly (WinError 193).  This function tries
    .bat / .cmd / .exe suffixes first so the correct Windows wrapper is
    picked up before the script.
    """
    candidates = [name]
    if sys.platform == "win32" and not name.endswith((".bat", ".cmd", ".exe")):
        candidates = [name + ".bat", name + ".cmd", name + ".exe", name]

    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return path

    raise ToolError(
        f"'{name}' not found on PATH. "
        f"Please install it and ensure it is accessible."
    )


def _android_sdk_root() -> Path | None:
    """Return the Android SDK root from well-known environment variables."""
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        value = os.environ.get(var)
        if value:
            p = Path(value)
            if p.is_dir():
                return p
    return None


def _find_aapt_in_sdk() -> str | None:
    """Locate aapt2 (or aapt) inside the Android SDK build-tools directory.

    Searches ANDROID_HOME / ANDROID_SDK_ROOT environment variables.
    Returns the full path string, or None if not found.
    """
    sdk = _android_sdk_root()
    if sdk is None:
        return None

    build_tools = sdk / "build-tools"
    if not build_tools.is_dir():
        return None

    # Collect all version directories, newest first.
    versions = sorted(build_tools.iterdir(), reverse=True)
    for version_dir in versions:
        for tool_name in ("aapt2.exe", "aapt2", "aapt.exe", "aapt"):
            candidate = version_dir / tool_name
            if candidate.is_file():
                logger.debug("Found %s at %s", tool_name, candidate)
                return str(candidate)

    return None


def _run(cmd: list[str], *, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    """Run a command, capture output, raise on failure."""
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            # Avoid interactive prompts from tools like apktool
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"Command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc

    if result.returncode != 0:
        stderr_snippet = (result.stderr or "").strip()[:1000]
        stdout_snippet = (result.stdout or "").strip()[:1000]
        detail = stderr_snippet or stdout_snippet or "(no output)"
        raise ToolError(
            f"Command failed (exit {result.returncode}): {' '.join(cmd)}\n"
            f"{detail}"
        )
    return result


# ---------------------------------------------------------------------------
# APKTool
# ---------------------------------------------------------------------------


def run_apktool(apk_path: Path, output_dir: Path) -> Path:
    """Decompile APK using APKTool → Smali + resources.

    Args:
        apk_path: Path to the APK file.
        output_dir: Directory to write decompiled output into.

    Returns:
        Path to the decompiled output directory.

    Raises:
        ToolError: If apktool is not installed or decompilation fails.
    """
    tool = _find_tool("apktool")
    out = output_dir / "apktool_out"

    # Remove previous output to avoid apktool "directory exists" error
    if out.exists():
        shutil.rmtree(out)

    _run([tool, "d", str(apk_path), "-o", str(out), "-f", "--no-src"])
    # --no-src: skip dex→smali (we use jadx for Java; apktool for resources)
    # -f: force overwrite

    if not out.exists():
        raise ToolError(f"APKTool produced no output at {out}")

    logger.info("APKTool decompiled %s → %s", apk_path.name, out)
    return out


def run_apktool_full(apk_path: Path, output_dir: Path) -> Path:
    """Decompile APK with full Smali output (resources + smali code).

    Same as ``run_apktool`` but includes Smali disassembly for pattern
    matching on bytecode level.
    """
    tool = _find_tool("apktool")
    out = output_dir / "apktool_full"

    if out.exists():
        shutil.rmtree(out)

    _run([tool, "d", str(apk_path), "-o", str(out), "-f"])

    if not out.exists():
        raise ToolError(f"APKTool (full) produced no output at {out}")

    logger.info("APKTool (full) decompiled %s → %s", apk_path.name, out)
    return out


# ---------------------------------------------------------------------------
# Jadx
# ---------------------------------------------------------------------------


def run_jadx(apk_path: Path, output_dir: Path, *, timeout: int = 300) -> Path:
    """Decompile APK using Jadx → Java/Kotlin source.

    Args:
        apk_path: Path to the APK file.
        output_dir: Directory to write decompiled Java source into.

    Returns:
        Path to the jadx output directory (contains ``sources/`` subtree).

    Raises:
        ToolError: If jadx is not installed or produced no output at all.
    """
    tool = _find_tool("jadx")
    out = output_dir / "jadx_out"

    if out.exists():
        shutil.rmtree(out)

    cmd = [
        tool,
        str(apk_path),
        "-d", str(out),
        "--no-imports",       # keep fully-qualified names for grep
        "--no-debug-info",    # smaller output
        # --deobf intentionally omitted: deobfuscation renaming is O(n²) on
        # large APKs and takes hours. TLS pinning targets are Android SDK
        # classes (TrustManager, CertificatePinner, etc.) whose references
        # are never obfuscated — only application class names are.
    ]
    logger.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        raise ToolError(f"Command not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ToolError(
            f"Jadx timed out after {timeout}s. "
            "Use --skip-jadx for very large APKs, or raise jadx_timeout in config."
        ) from exc

    if result.returncode != 0:
        if not out.exists():
            # Complete failure — jadx produced nothing at all.
            detail = (result.stderr or result.stdout or "(no output)").strip()[:1000]
            raise ToolError(
                f"Jadx failed completely (exit {result.returncode}): {detail}"
            )
        # Partial failure — jadx hit errors on individual classes but still
        # produced output for the rest.  This is normal for obfuscated or
        # complex APKs; continue with whatever was decompiled.
        error_lines = [
            l for l in (result.stdout + result.stderr).splitlines()
            if "ERROR" in l
        ]
        logger.warning(
            "Jadx finished with %d error(s) on individual classes "
            "(exit %d) — continuing with partial decompilation output",
            len(error_lines), result.returncode,
        )

    if not out.exists():
        raise ToolError(f"Jadx produced no output at {out}")

    logger.info("Jadx decompiled %s → %s", apk_path.name, out)
    return out


# ---------------------------------------------------------------------------
# Manifest helpers
# ---------------------------------------------------------------------------


def run_adb(*args: str, timeout: int = 30) -> str:
    """Run an adb command and return stdout as a string.

    Args:
        *args: Arguments to pass to adb, e.g. ``"devices"``, ``"shell"``, ``"getprop"``.
        timeout: Maximum seconds to wait.

    Returns:
        stdout output as a string.

    Raises:
        ToolError: If adb is not found or the command exits non-zero.
    """
    tool = _find_tool("adb")
    result = _run([tool] + list(args), timeout=timeout)
    return result.stdout


# ---------------------------------------------------------------------------
# AAPT helpers
# ---------------------------------------------------------------------------


def extract_package_info_from_aapt(apk_path: Path) -> dict[str, str]:
    """Extract package name, version, SDK info from APK using aapt2.

    Returns a dict with keys: package_name, version_name, version_code,
    min_sdk, target_sdk.  Missing values default to empty string / "0".

    Falls back gracefully if aapt2 is not available.
    """
    info: dict[str, str] = {
        "package_name": "",
        "version_name": "",
        "version_code": "",
        "min_sdk": "0",
        "target_sdk": "0",
    }

    # Try PATH first, then fall back to Android SDK build-tools directory.
    tool: str | None = None
    for name in ("aapt2", "aapt"):
        try:
            tool = _find_tool(name)
            break
        except ToolError:
            pass

    if tool is None:
        tool = _find_aapt_in_sdk()

    if tool is None:
        logger.warning(
            "Neither aapt2 nor aapt found on PATH or in ANDROID_HOME/ANDROID_SDK_ROOT. "
            "Set ANDROID_HOME to your SDK root or add build-tools to PATH."
        )
        return info

    try:
        result = _run([tool, "dump", "badging", str(apk_path)])
    except ToolError:
        logger.warning("aapt dump failed for %s", apk_path)
        return info

    for line in result.stdout.splitlines():
        if line.startswith("package:"):
            for token in line.split():
                if token.startswith("name='"):
                    info["package_name"] = token.split("'")[1]
                elif token.startswith("versionName='"):
                    info["version_name"] = token.split("'")[1]
                elif token.startswith("versionCode='"):
                    info["version_code"] = token.split("'")[1]
        elif line.startswith("sdkVersion:'"):
            info["min_sdk"] = line.split("'")[1]
        elif line.startswith("targetSdkVersion:'"):
            info["target_sdk"] = line.split("'")[1]
        elif line.startswith("application-label:'"):
            info["app_name"] = line.split("'")[1]

    return info
