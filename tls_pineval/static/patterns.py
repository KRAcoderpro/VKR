"""Central registry of search patterns for static analysis (V2 §4.2).

Contains regex and string patterns used to detect TLS pinning-related
code in both Smali bytecode and decompiled Java/Kotlin source.

Pattern categories:
    - TrustManager implementations
    - CertificatePinner (OkHttp)
    - HostnameVerifier
    - WebView SSL error handling
    - Obfuscation markers
    - Integrity checks (SafetyNet, Play Integrity)
    - Root detection
    - Hardcoded pinning secrets
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class PatternSource(str, Enum):
    """Where a pattern is expected to match."""

    SMALI = "smali"
    JAVA = "java"
    BOTH = "both"


@dataclass(frozen=True)
class SearchPattern:
    """A single search pattern with metadata."""

    name: str
    pattern: re.Pattern[str]
    category: str
    source: PatternSource
    description: str = ""


# ---------------------------------------------------------------------------
# Smali patterns
# ---------------------------------------------------------------------------

# TrustManager — detect class implementing X509TrustManager
SMALI_TRUST_MANAGER_IMPL = SearchPattern(
    name="smali_trustmanager_impl",
    pattern=re.compile(
        r"\.implements\s+Ljavax/net/ssl/X509TrustManager;",
        re.MULTILINE,
    ),
    category="trustmanager",
    source=PatternSource.SMALI,
    description="Class implements X509TrustManager interface",
)

# TrustManager — checkServerTrusted method
SMALI_CHECK_SERVER_TRUSTED = SearchPattern(
    name="smali_check_server_trusted",
    pattern=re.compile(
        r"\.method\s+public\s+(?:final\s+)?checkServerTrusted\("
        r"(\[Ljava/security/cert/X509Certificate;[^)]*)\)V",
        re.MULTILINE,
    ),
    category="trustmanager",
    source=PatternSource.SMALI,
    description="checkServerTrusted method declaration in Smali",
)

# TrustManager — trust-all indicator (empty method or immediate return)
SMALI_TRUST_ALL = SearchPattern(
    name="smali_trust_all",
    pattern=re.compile(
        r"\.method\s+public\s+(?:final\s+)?checkServerTrusted\([^)]*\)V"
        r"\s*\.registers\s+\d+\s*"
        r"(?:\.(?:annotation|param)[^\n]*\n)*"
        r"\s*return-void",
        re.MULTILINE | re.DOTALL,
    ),
    category="trustmanager",
    source=PatternSource.SMALI,
    description="Trust-all TrustManager (checkServerTrusted returns immediately)",
)

# CertificatePinner (OkHttp)
SMALI_CERTIFICATE_PINNER = SearchPattern(
    name="smali_certificate_pinner",
    pattern=re.compile(
        r"Lokhttp3/CertificatePinner",
        re.MULTILINE,
    ),
    category="okhttp",
    source=PatternSource.SMALI,
    description="Reference to OkHttp CertificatePinner class",
)

SMALI_CERT_PINNER_BUILDER = SearchPattern(
    name="smali_cert_pinner_builder",
    pattern=re.compile(
        r"Lokhttp3/CertificatePinner\$Builder;",
        re.MULTILINE,
    ),
    category="okhttp",
    source=PatternSource.SMALI,
    description="CertificatePinner.Builder usage (active pinning configuration)",
)

# HostnameVerifier
SMALI_HOSTNAME_VERIFIER = SearchPattern(
    name="smali_hostname_verifier",
    pattern=re.compile(
        r"\.implements\s+Ljavax/net/ssl/HostnameVerifier;",
        re.MULTILINE,
    ),
    category="hostname",
    source=PatternSource.SMALI,
    description="Class implements HostnameVerifier interface",
)

SMALI_HOSTNAME_VERIFY_METHOD = SearchPattern(
    name="smali_hostname_verify_method",
    pattern=re.compile(
        r"\.method\s+public\s+(?:final\s+)?verify\("
        r"Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z",
        re.MULTILINE,
    ),
    category="hostname",
    source=PatternSource.SMALI,
    description="HostnameVerifier.verify() method declaration",
)

# HostnameVerifier — allow-all (returns true without checking)
SMALI_ALLOW_ALL_HOSTNAME = SearchPattern(
    name="smali_allow_all_hostname",
    pattern=re.compile(
        r"\.method\s+public\s+(?:final\s+)?verify\("
        r"Ljava/lang/String;Ljavax/net/ssl/SSLSession;\)Z"
        r"\s*\.registers\s+\d+\s*"
        r"(?:\.(?:annotation|param)[^\n]*\n)*"
        r"\s*const/4\s+v\d+,\s*0x1\s*\n"
        r"\s*return\s+v\d+",
        re.MULTILINE | re.DOTALL,
    ),
    category="hostname",
    source=PatternSource.SMALI,
    description="Allow-all HostnameVerifier (verify returns true immediately)",
)

# WebView SSL error handler
SMALI_WEBVIEW_SSL_ERROR = SearchPattern(
    name="smali_webview_ssl_error",
    pattern=re.compile(
        r"\.method\s+public\s+(?:final\s+)?onReceivedSslError\(",
        re.MULTILINE,
    ),
    category="webview",
    source=PatternSource.SMALI,
    description="WebViewClient.onReceivedSslError override",
)

# WebView — proceed on SSL error (insecure)
SMALI_WEBVIEW_PROCEED = SearchPattern(
    name="smali_webview_proceed",
    pattern=re.compile(
        r"invoke-virtual\s+\{[^}]*\},\s*Landroid/webkit/SslErrorHandler;->proceed\(\)V",
        re.MULTILINE,
    ),
    category="webview",
    source=PatternSource.SMALI,
    description="SslErrorHandler.proceed() call (ignores SSL errors)",
)

# ---------------------------------------------------------------------------
# Java / Kotlin patterns (for Jadx output)
# ---------------------------------------------------------------------------

JAVA_TRUST_MANAGER = SearchPattern(
    name="java_trustmanager",
    pattern=re.compile(
        r"implements\s+X509TrustManager",
        re.MULTILINE,
    ),
    category="trustmanager",
    source=PatternSource.JAVA,
    description="Class implements X509TrustManager",
)

JAVA_CHECK_SERVER_TRUSTED = SearchPattern(
    name="java_check_server_trusted",
    pattern=re.compile(
        r"(?:public|protected)\s+void\s+checkServerTrusted\s*\(",
        re.MULTILINE,
    ),
    category="trustmanager",
    source=PatternSource.JAVA,
    description="checkServerTrusted method declaration in Java",
)

JAVA_TRUST_ALL = SearchPattern(
    name="java_trust_all",
    pattern=re.compile(
        r"void\s+checkServerTrusted\s*\([^)]*\)\s*"
        r"(?:throws\s+[^{]*)?\{"
        r"\s*\}",
        re.MULTILINE | re.DOTALL,
    ),
    category="trustmanager",
    source=PatternSource.JAVA,
    description="Trust-all TrustManager (empty checkServerTrusted body)",
)

JAVA_CERTIFICATE_PINNER = SearchPattern(
    name="java_certificate_pinner",
    pattern=re.compile(
        r"CertificatePinner(?:\.Builder)?",
        re.MULTILINE,
    ),
    category="okhttp",
    source=PatternSource.JAVA,
    description="OkHttp CertificatePinner reference in Java source",
)

JAVA_HOSTNAME_VERIFIER = SearchPattern(
    name="java_hostname_verifier",
    pattern=re.compile(
        r"implements\s+HostnameVerifier",
        re.MULTILINE,
    ),
    category="hostname",
    source=PatternSource.JAVA,
    description="Class implements HostnameVerifier",
)

JAVA_ALLOW_ALL_HOSTNAME = SearchPattern(
    name="java_allow_all_hostname",
    pattern=re.compile(
        r"(?:public\s+)?boolean\s+verify\s*\([^)]*\)\s*\{"
        r"\s*return\s+true\s*;?\s*\}",
        re.MULTILINE | re.DOTALL,
    ),
    category="hostname",
    source=PatternSource.JAVA,
    description="Allow-all HostnameVerifier (returns true)",
)

JAVA_WEBVIEW_SSL_ERROR = SearchPattern(
    name="java_webview_ssl_error",
    pattern=re.compile(
        r"(?:public\s+)?void\s+onReceivedSslError\s*\(",
        re.MULTILINE,
    ),
    category="webview",
    source=PatternSource.JAVA,
    description="WebViewClient.onReceivedSslError override in Java",
)

JAVA_WEBVIEW_PROCEED = SearchPattern(
    name="java_webview_proceed",
    pattern=re.compile(
        r"handler\s*\.\s*proceed\s*\(\s*\)",
        re.MULTILINE,
    ),
    category="webview",
    source=PatternSource.JAVA,
    description="SslErrorHandler.proceed() call in Java",
)

# ---------------------------------------------------------------------------
# Protection patterns (both sources)
# ---------------------------------------------------------------------------

PROGUARD_MAPPING = SearchPattern(
    name="proguard_mapping",
    pattern=re.compile(r"proguard", re.IGNORECASE),
    category="protection",
    source=PatternSource.BOTH,
    description="ProGuard reference (mapping file or config)",
)

SAFETYNET_PATTERN = SearchPattern(
    name="safetynet",
    pattern=re.compile(
        r"SafetyNet|com\.google\.android\.gms\.safetynet",
        re.MULTILINE,
    ),
    category="protection",
    source=PatternSource.BOTH,
    description="Google SafetyNet API reference",
)

PLAY_INTEGRITY_PATTERN = SearchPattern(
    name="play_integrity",
    pattern=re.compile(
        r"PlayIntegrity|com\.google\.android\.play\.core\.integrity|"
        r"IntegrityManager|IntegrityTokenRequest",
        re.MULTILINE,
    ),
    category="protection",
    source=PatternSource.BOTH,
    description="Google Play Integrity API reference",
)

ROOT_DETECTION_PATTERNS = SearchPattern(
    name="root_detection",
    pattern=re.compile(
        r"(?:isDeviceRooted|checkRoot|RootBeer|RootDetect|"
        r"/su\b|/system/xbin/su|com\.noshufou\.android\.su|"
        r"eu\.chainfire\.supersu|com\.topjohnwu\.magisk|"
        r"isRooted|detectRoot|checkForRoot)",
        re.MULTILINE | re.IGNORECASE,
    ),
    category="protection",
    source=PatternSource.BOTH,
    description="Root/superuser detection patterns",
)

# Hardcoded secrets related to pinning
HARDCODED_PIN_PATTERNS = SearchPattern(
    name="hardcoded_pins",
    pattern=re.compile(
        r"(?:sha256/[A-Za-z0-9+/=]{20,}|"
        r"-----BEGIN CERTIFICATE-----|"
        r"\"[A-Fa-f0-9]{64}\")",  # SHA-256 hex
        re.MULTILINE,
    ),
    category="secrets",
    source=PatternSource.BOTH,
    description="Hardcoded certificate pins or embedded certificates",
)


# ---------------------------------------------------------------------------
# Pattern groups for convenient access
# ---------------------------------------------------------------------------

SMALI_PATTERNS: list[SearchPattern] = [
    SMALI_TRUST_MANAGER_IMPL,
    SMALI_CHECK_SERVER_TRUSTED,
    SMALI_TRUST_ALL,
    SMALI_CERTIFICATE_PINNER,
    SMALI_CERT_PINNER_BUILDER,
    SMALI_HOSTNAME_VERIFIER,
    SMALI_HOSTNAME_VERIFY_METHOD,
    SMALI_ALLOW_ALL_HOSTNAME,
    SMALI_WEBVIEW_SSL_ERROR,
    SMALI_WEBVIEW_PROCEED,
]

JAVA_PATTERNS: list[SearchPattern] = [
    JAVA_TRUST_MANAGER,
    JAVA_CHECK_SERVER_TRUSTED,
    JAVA_TRUST_ALL,
    JAVA_CERTIFICATE_PINNER,
    JAVA_HOSTNAME_VERIFIER,
    JAVA_ALLOW_ALL_HOSTNAME,
    JAVA_WEBVIEW_SSL_ERROR,
    JAVA_WEBVIEW_PROCEED,
]

PROTECTION_PATTERNS: list[SearchPattern] = [
    PROGUARD_MAPPING,
    SAFETYNET_PATTERN,
    PLAY_INTEGRITY_PATTERN,
    ROOT_DETECTION_PATTERNS,
]

SECRET_PATTERNS: list[SearchPattern] = [
    HARDCODED_PIN_PATTERNS,
]

ALL_PATTERNS: list[SearchPattern] = (
    SMALI_PATTERNS + JAVA_PATTERNS + PROTECTION_PATTERNS + SECRET_PATTERNS
)
