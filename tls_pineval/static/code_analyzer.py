"""Code analyzer — scans decompiled source for TLS pinning patterns (V2 §4.2).

Detects:
    - CertificatePinner (OkHttp)
    - Custom TrustManager / checkServerTrusted (including trust-all)
    - HostnameVerifier (including allow-all)
    - WebViewClient.onReceivedSslError (including proceed-on-error)
    - Hardcoded pinning secrets

Extracts ``HookTarget`` instances with overloads and ``PinningImpl`` entries.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from tls_pineval.models.common import (
    Confidence,
    Finding,
    HookCategory,
    HookTarget,
    Severity,
)
from tls_pineval.models.static_report import PinningImpl
from tls_pineval.static.patterns import (
    JAVA_ALLOW_ALL_HOSTNAME,
    JAVA_CERTIFICATE_PINNER,
    JAVA_CHECK_SERVER_TRUSTED,
    JAVA_HOSTNAME_VERIFIER,
    JAVA_TRUST_ALL,
    JAVA_TRUST_MANAGER,
    JAVA_WEBVIEW_PROCEED,
    JAVA_WEBVIEW_SSL_ERROR,
    SMALI_ALLOW_ALL_HOSTNAME,
    SMALI_CERT_PINNER_BUILDER,
    SMALI_CERTIFICATE_PINNER,
    SMALI_CHECK_SERVER_TRUSTED,
    SMALI_HOSTNAME_VERIFIER,
    SMALI_HOSTNAME_VERIFY_METHOD,
    SMALI_TRUST_ALL,
    SMALI_TRUST_MANAGER_IMPL,
    SMALI_WEBVIEW_PROCEED,
    SMALI_WEBVIEW_SSL_ERROR,
    HARDCODED_PIN_PATTERNS,
)

logger = logging.getLogger(__name__)

# Maximum file size to scan (skip huge generated files)
_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


def _smali_path_to_class(path: Path, base: Path) -> str:
    """Convert a Smali file path to a Java class name.

    Example: base/smali/com/app/ssl/Manager.smali → com.app.ssl.Manager
    """
    try:
        rel = path.relative_to(base)
    except ValueError:
        return path.stem

    # Remove smali/ or smali_classesN/ prefix
    parts = list(rel.parts)
    if parts and parts[0].startswith("smali"):
        parts = parts[1:]

    # Join and strip .smali
    class_path = "/".join(parts)
    if class_path.endswith(".smali"):
        class_path = class_path[:-6]

    return class_path.replace("/", ".")


def _java_path_to_class(path: Path, base: Path) -> str:
    """Convert a Java file path to a class name.

    Example: base/sources/com/app/ssl/Manager.java → com.app.ssl.Manager
    """
    try:
        rel = path.relative_to(base)
    except ValueError:
        return path.stem

    parts = list(rel.parts)
    # Remove sources/ prefix if present
    if parts and parts[0] == "sources":
        parts = parts[1:]

    class_path = "/".join(parts)
    if class_path.endswith(".java"):
        class_path = class_path[:-5]

    return class_path.replace("/", ".")


def _extract_smali_overloads(content: str, method_name: str) -> list[str]:
    """Extract method overload descriptors from Smali source.

    Returns list of parameter type strings, e.g.:
    ["[Ljava.security.cert.X509Certificate;, java.lang.String"]
    """
    overloads: list[str] = []
    pattern = re.compile(
        rf"\.method\s+(?:public|private|protected)\s+(?:\w+\s+)*{re.escape(method_name)}"
        rf"\(([^)]*)\)",
        re.MULTILINE,
    )
    for m in pattern.finditer(content):
        raw_params = m.group(1)
        if raw_params:
            # Convert Smali descriptors to Java-style
            params = _smali_params_to_java(raw_params)
            if params:
                overloads.append(params)
    return overloads


def _smali_params_to_java(raw: str) -> str:
    """Convert Smali parameter descriptor to readable format.

    Example: [Ljava/security/cert/X509Certificate;Ljava/lang/String;
           → [Ljava.security.cert.X509Certificate;, java.lang.String
    """
    parts: list[str] = []
    i = 0
    while i < len(raw):
        if raw[i] == "[":
            # Array type — find the element type
            arr_prefix = "["
            i += 1
            while i < len(raw) and raw[i] == "[":
                arr_prefix += "["
                i += 1
            if i < len(raw) and raw[i] == "L":
                end = raw.index(";", i)
                class_name = raw[i:end + 1].replace("/", ".")
                parts.append(arr_prefix + class_name)
                i = end + 1
            elif i < len(raw):
                parts.append(arr_prefix + raw[i])
                i += 1
        elif raw[i] == "L":
            end = raw.index(";", i)
            class_name = raw[i + 1:end].replace("/", ".")
            parts.append(class_name)
            i = end + 1
        elif raw[i] in "ZBCSIJFD":
            type_map = {
                "Z": "boolean", "B": "byte", "C": "char", "S": "short",
                "I": "int", "J": "long", "F": "float", "D": "double",
            }
            parts.append(type_map.get(raw[i], raw[i]))
            i += 1
        else:
            i += 1

    return ", ".join(parts)


def _scan_files(directory: Path, extension: str) -> list[tuple[Path, str]]:
    """Recursively read all files with given extension, returning (path, content)."""
    results: list[tuple[Path, str]] = []
    if not directory.exists():
        return results

    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if not fname.endswith(extension):
                continue
            fpath = Path(root) / fname
            if fpath.stat().st_size > _MAX_FILE_SIZE:
                logger.debug("Skipping large file: %s", fpath)
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
                results.append((fpath, content))
            except OSError as exc:
                logger.warning("Cannot read %s: %s", fpath, exc)
    return results


class CodeAnalysisResult:
    """Accumulator for code analysis results."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.pinning_impls: list[PinningImpl] = []
        self.hook_targets: list[HookTarget] = []
        self._finding_counter = 0
        self._seen_classes: set[str] = set()

    def _next_id(self, prefix: str) -> str:
        self._finding_counter += 1
        return f"{prefix}-{self._finding_counter:03d}"

    def add_finding(self, **kwargs: object) -> None:
        if "id" not in kwargs:
            kwargs["id"] = self._next_id("CODE")
        self.findings.append(Finding(**kwargs))  # type: ignore[arg-type]

    def add_impl(self, impl: PinningImpl) -> None:
        self.pinning_impls.append(impl)

    def add_hook_target(self, target: HookTarget) -> None:
        key = f"{target.class_name}.{target.method_name}"
        if key not in self._seen_classes:
            self._seen_classes.add(key)
            self.hook_targets.append(target)


def _analyze_smali_file(
    path: Path,
    content: str,
    base_dir: Path,
    result: CodeAnalysisResult,
) -> None:
    """Analyze a single Smali file for TLS pinning patterns."""
    class_name = _smali_path_to_class(path, base_dir)
    rel_path = str(path.relative_to(base_dir)) if base_dir in path.parents else path.name

    # --- TrustManager ---
    if SMALI_TRUST_MANAGER_IMPL.pattern.search(content):
        is_trust_all = bool(SMALI_TRUST_ALL.pattern.search(content))
        overloads = _extract_smali_overloads(content, "checkServerTrusted")

        result.add_finding(
            category="trustmanager",
            description=(
                f"{'INSECURE trust-all' if is_trust_all else 'Custom'} "
                f"TrustManager implementation found"
            ),
            location=class_name,
            severity=Severity.CRITICAL if is_trust_all else Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence=SMALI_TRUST_MANAGER_IMPL.pattern.pattern[:100],
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.TRUST_MANAGER,
                class_name=class_name,
                is_vulnerable=is_trust_all,
                confidence=Confidence.HIGH,
            )
        )

        if SMALI_CHECK_SERVER_TRUSTED.pattern.search(content):
            result.add_hook_target(
                HookTarget(
                    class_name=class_name,
                    method_name="checkServerTrusted",
                    category=HookCategory.TRUST_MANAGER,
                    overloads=overloads,
                    source_file=rel_path,
                    confidence=Confidence.HIGH,
                )
            )

    # --- CertificatePinner ---
    if SMALI_CERT_PINNER_BUILDER.pattern.search(content):
        result.add_finding(
            category="okhttp",
            description="OkHttp CertificatePinner.Builder usage detected",
            location=class_name,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence="Lokhttp3/CertificatePinner$Builder;",
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.CERTIFICATE_PINNER,
                class_name=class_name,
                is_vulnerable=False,
                confidence=Confidence.HIGH,
            )
        )

        # OkHttp CertificatePinner.check method
        result.add_hook_target(
            HookTarget(
                class_name="okhttp3.CertificatePinner",
                method_name="check",
                category=HookCategory.CERTIFICATE_PINNER,
                overloads=["java.lang.String, java.util.List"],
                source_file=rel_path,
                confidence=Confidence.HIGH,
            )
        )

    elif SMALI_CERTIFICATE_PINNER.pattern.search(content):
        result.add_finding(
            category="okhttp",
            description="OkHttp CertificatePinner reference found (no Builder)",
            location=class_name,
            severity=Severity.INFO,
            confidence=Confidence.MEDIUM,
            raw_evidence="Lokhttp3/CertificatePinner",
        )

    # --- HostnameVerifier ---
    if SMALI_HOSTNAME_VERIFIER.pattern.search(content):
        is_allow_all = bool(SMALI_ALLOW_ALL_HOSTNAME.pattern.search(content))
        overloads = _extract_smali_overloads(content, "verify")

        result.add_finding(
            category="hostname",
            description=(
                f"{'INSECURE allow-all' if is_allow_all else 'Custom'} "
                f"HostnameVerifier implementation found"
            ),
            location=class_name,
            severity=Severity.CRITICAL if is_allow_all else Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence=SMALI_HOSTNAME_VERIFIER.pattern.pattern[:100],
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.HOSTNAME_VERIFIER,
                class_name=class_name,
                is_vulnerable=is_allow_all,
                confidence=Confidence.HIGH,
            )
        )

        if SMALI_HOSTNAME_VERIFY_METHOD.pattern.search(content):
            result.add_hook_target(
                HookTarget(
                    class_name=class_name,
                    method_name="verify",
                    category=HookCategory.HOSTNAME_VERIFIER,
                    overloads=overloads if overloads else [
                        "java.lang.String, javax.net.ssl.SSLSession"
                    ],
                    source_file=rel_path,
                    confidence=Confidence.HIGH,
                )
            )

    # --- WebView SSL ---
    if SMALI_WEBVIEW_SSL_ERROR.pattern.search(content):
        proceeds = bool(SMALI_WEBVIEW_PROCEED.pattern.search(content))

        result.add_finding(
            category="webview",
            description=(
                f"WebViewClient.onReceivedSslError override found"
                f"{' — INSECURE: calls handler.proceed()' if proceeds else ''}"
            ),
            location=class_name,
            severity=Severity.CRITICAL if proceeds else Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence="onReceivedSslError" + (" → proceed()" if proceeds else ""),
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.WEBVIEW_SSL,
                class_name=class_name,
                is_vulnerable=proceeds,
                confidence=Confidence.HIGH,
            )
        )

        result.add_hook_target(
            HookTarget(
                class_name=class_name,
                method_name="onReceivedSslError",
                category=HookCategory.WEBVIEW_SSL,
                overloads=[
                    "android.webkit.WebView, android.webkit.SslErrorHandler, android.net.http.SslError"
                ],
                source_file=rel_path,
                confidence=Confidence.HIGH,
            )
        )

    # --- Hardcoded secrets ---
    secret_matches = HARDCODED_PIN_PATTERNS.pattern.findall(content)
    if secret_matches:
        for secret in secret_matches[:5]:  # cap to avoid noise
            result.add_finding(
                category="secrets",
                description="Hardcoded pinning-related secret found in code",
                location=class_name,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                raw_evidence=secret[:100],
            )


def _analyze_java_file(
    path: Path,
    content: str,
    base_dir: Path,
    result: CodeAnalysisResult,
) -> None:
    """Analyze a single Java file for TLS pinning patterns.

    Java analysis is supplementary to Smali — it catches patterns that
    are clearer in decompiled source but may have been missed in Smali
    due to obfuscation or complex control flow.
    """
    class_name = _java_path_to_class(path, base_dir)
    rel_path = str(path.relative_to(base_dir)) if base_dir in path.parents else path.name

    # --- TrustManager ---
    if JAVA_TRUST_MANAGER.pattern.search(content):
        is_trust_all = bool(JAVA_TRUST_ALL.pattern.search(content))

        result.add_finding(
            category="trustmanager",
            description=(
                f"{'INSECURE trust-all' if is_trust_all else 'Custom'} "
                f"TrustManager found in Java source"
            ),
            location=class_name,
            severity=Severity.CRITICAL if is_trust_all else Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence="implements X509TrustManager",
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.TRUST_MANAGER,
                class_name=class_name,
                is_vulnerable=is_trust_all,
                confidence=Confidence.HIGH,
            )
        )

        if JAVA_CHECK_SERVER_TRUSTED.pattern.search(content):
            result.add_hook_target(
                HookTarget(
                    class_name=class_name,
                    method_name="checkServerTrusted",
                    category=HookCategory.TRUST_MANAGER,
                    overloads=[],  # Java decompilation doesn't give precise descriptors
                    source_file=rel_path,
                    confidence=Confidence.HIGH if not is_trust_all else Confidence.HIGH,
                )
            )

    # --- CertificatePinner ---
    if JAVA_CERTIFICATE_PINNER.pattern.search(content):
        result.add_finding(
            category="okhttp",
            description="OkHttp CertificatePinner usage in Java source",
            location=class_name,
            severity=Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence="CertificatePinner",
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.CERTIFICATE_PINNER,
                class_name=class_name,
                is_vulnerable=False,
                confidence=Confidence.HIGH,
            )
        )

        result.add_hook_target(
            HookTarget(
                class_name="okhttp3.CertificatePinner",
                method_name="check",
                category=HookCategory.CERTIFICATE_PINNER,
                overloads=["java.lang.String, java.util.List"],
                source_file=rel_path,
                confidence=Confidence.HIGH,
            )
        )

    # --- HostnameVerifier ---
    if JAVA_HOSTNAME_VERIFIER.pattern.search(content):
        is_allow_all = bool(JAVA_ALLOW_ALL_HOSTNAME.pattern.search(content))

        result.add_finding(
            category="hostname",
            description=(
                f"{'INSECURE allow-all' if is_allow_all else 'Custom'} "
                f"HostnameVerifier in Java source"
            ),
            location=class_name,
            severity=Severity.CRITICAL if is_allow_all else Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence="implements HostnameVerifier",
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.HOSTNAME_VERIFIER,
                class_name=class_name,
                is_vulnerable=is_allow_all,
                confidence=Confidence.HIGH,
            )
        )

        result.add_hook_target(
            HookTarget(
                class_name=class_name,
                method_name="verify",
                category=HookCategory.HOSTNAME_VERIFIER,
                overloads=["java.lang.String, javax.net.ssl.SSLSession"],
                source_file=rel_path,
                confidence=Confidence.HIGH,
            )
        )

    # --- WebView SSL ---
    if JAVA_WEBVIEW_SSL_ERROR.pattern.search(content):
        proceeds = bool(JAVA_WEBVIEW_PROCEED.pattern.search(content))

        result.add_finding(
            category="webview",
            description=(
                f"onReceivedSslError in Java source"
                f"{' — INSECURE: calls handler.proceed()' if proceeds else ''}"
            ),
            location=class_name,
            severity=Severity.CRITICAL if proceeds else Severity.INFO,
            confidence=Confidence.HIGH,
            raw_evidence="onReceivedSslError" + (" → proceed()" if proceeds else ""),
        )

        result.add_impl(
            PinningImpl(
                type=HookCategory.WEBVIEW_SSL,
                class_name=class_name,
                is_vulnerable=proceeds,
                confidence=Confidence.HIGH,
            )
        )

        result.add_hook_target(
            HookTarget(
                class_name=class_name,
                method_name="onReceivedSslError",
                category=HookCategory.WEBVIEW_SSL,
                overloads=[
                    "android.webkit.WebView, android.webkit.SslErrorHandler, android.net.http.SslError"
                ],
                source_file=rel_path,
                confidence=Confidence.HIGH,
            )
        )


def analyze_code(
    smali_dir: Path | None,
    jadx_dir: Path | None,
) -> CodeAnalysisResult:
    """Run code analysis on decompiled Smali and/or Java sources.

    Args:
        smali_dir: APKTool full output dir (contains smali/ subdirs).
        jadx_dir: Jadx output dir (contains sources/ subdir).

    Returns:
        CodeAnalysisResult with findings, pinning implementations, and hook targets.
    """
    result = CodeAnalysisResult()

    # Scan Smali files
    if smali_dir and smali_dir.exists():
        smali_files = _scan_files(smali_dir, ".smali")
        logger.info("Scanning %d Smali files", len(smali_files))
        for path, content in smali_files:
            _analyze_smali_file(path, content, smali_dir, result)

    # Scan Java files (supplementary)
    if jadx_dir and jadx_dir.exists():
        sources_dir = jadx_dir / "sources"
        if sources_dir.exists():
            java_files = _scan_files(sources_dir, ".java")
            logger.info("Scanning %d Java files", len(java_files))
            for path, content in java_files:
                _analyze_java_file(path, content, jadx_dir, result)

    logger.info(
        "Code analysis complete: %d findings, %d implementations, %d hook targets",
        len(result.findings),
        len(result.pinning_impls),
        len(result.hook_targets),
    )
    return result
