"""Unit tests for the Phase 2 static analyzer (V2 §4.2).

All tests use synthetic content written to tmp_path — no real APK required.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from tls_pineval.models.common import Confidence, HookCategory, ObfuscationLevel, Severity
from tls_pineval.static.code_analyzer import (
    CodeAnalysisResult,
    _smali_params_to_java,
    _smali_path_to_class,
    _java_path_to_class,
    analyze_code,
)
from tls_pineval.static.nsc_analyzer import analyze_nsc
from tls_pineval.static.patterns import (
    SMALI_TRUST_MANAGER_IMPL,
    SMALI_TRUST_ALL,
    SMALI_CHECK_SERVER_TRUSTED,
    SMALI_CERT_PINNER_BUILDER,
    SMALI_HOSTNAME_VERIFIER,
    SMALI_ALLOW_ALL_HOSTNAME,
    SMALI_WEBVIEW_SSL_ERROR,
    SMALI_WEBVIEW_PROCEED,
    JAVA_TRUST_MANAGER,
    JAVA_TRUST_ALL,
    JAVA_CERTIFICATE_PINNER,
    JAVA_HOSTNAME_VERIFIER,
    JAVA_ALLOW_ALL_HOSTNAME,
    JAVA_WEBVIEW_SSL_ERROR,
    JAVA_WEBVIEW_PROCEED,
)
from tls_pineval.static.protection_analyzer import analyze_protection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def _smali_dir(tmp_path: Path) -> Path:
    return tmp_path / "apktool_full"


def _smali_file(tmp_path: Path, rel: str, content: str) -> tuple[Path, Path]:
    base = _smali_dir(tmp_path)
    fpath = _write(base / rel, content)
    return base, fpath


# ---------------------------------------------------------------------------
# patterns.py — regex smoke tests
# ---------------------------------------------------------------------------

class TestSmaliPatterns:
    def test_trust_manager_impl_matches(self):
        snippet = ".implements Ljavax/net/ssl/X509TrustManager;"
        assert SMALI_TRUST_MANAGER_IMPL.pattern.search(snippet)

    def test_trust_manager_impl_no_false_positive(self):
        snippet = ".implements Ljavax/net/ssl/SSLSocket;"
        assert not SMALI_TRUST_MANAGER_IMPL.pattern.search(snippet)

    def test_check_server_trusted_matches(self):
        snippet = (
            ".method public checkServerTrusted("
            "[Ljava/security/cert/X509Certificate;Ljava/lang/String;)V"
        )
        assert SMALI_CHECK_SERVER_TRUSTED.pattern.search(snippet)

    def test_trust_all_matches_empty_body(self):
        snippet = textwrap.dedent("""\
            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                return-void
            .end method
        """)
        assert SMALI_TRUST_ALL.pattern.search(snippet)

    def test_trust_all_no_match_nonempty_body(self):
        snippet = textwrap.dedent("""\
            .method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
                .registers 3
                invoke-static {p1}, Lcom/example/PinVerifier;->verify([Ljava/security/cert/X509Certificate;)V
                return-void
            .end method
        """)
        assert not SMALI_TRUST_ALL.pattern.search(snippet)

    def test_cert_pinner_builder_matches(self):
        snippet = "invoke-virtual {v0}, Lokhttp3/CertificatePinner$Builder;->add(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner$Builder;"
        assert SMALI_CERT_PINNER_BUILDER.pattern.search(snippet)

    def test_hostname_verifier_matches(self):
        snippet = ".implements Ljavax/net/ssl/HostnameVerifier;"
        assert SMALI_HOSTNAME_VERIFIER.pattern.search(snippet)

    def test_allow_all_hostname_matches(self):
        snippet = textwrap.dedent("""\
            .method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
                .registers 2
                const/4 v0, 0x1
                return v0
            .end method
        """)
        assert SMALI_ALLOW_ALL_HOSTNAME.pattern.search(snippet)

    def test_webview_ssl_error_matches(self):
        snippet = ".method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V"
        assert SMALI_WEBVIEW_SSL_ERROR.pattern.search(snippet)

    def test_webview_proceed_matches(self):
        snippet = "invoke-virtual {v1}, Landroid/webkit/SslErrorHandler;->proceed()V"
        assert SMALI_WEBVIEW_PROCEED.pattern.search(snippet)


class TestJavaPatterns:
    def test_trust_manager_matches(self):
        assert JAVA_TRUST_MANAGER.pattern.search("public class Foo implements X509TrustManager {")

    def test_trust_all_matches_empty_body(self):
        snippet = textwrap.dedent("""\
            public void checkServerTrusted(X509Certificate[] chain, String authType) {
            }
        """)
        assert JAVA_TRUST_ALL.pattern.search(snippet)

    def test_trust_all_no_match_throws(self):
        snippet = textwrap.dedent("""\
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                verifyPin(chain);
            }
        """)
        assert not JAVA_TRUST_ALL.pattern.search(snippet)

    def test_certificate_pinner_matches(self):
        assert JAVA_CERTIFICATE_PINNER.pattern.search("new CertificatePinner.Builder()")

    def test_hostname_verifier_matches(self):
        assert JAVA_HOSTNAME_VERIFIER.pattern.search("implements HostnameVerifier {")

    def test_allow_all_hostname_matches(self):
        snippet = textwrap.dedent("""\
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        """)
        assert JAVA_ALLOW_ALL_HOSTNAME.pattern.search(snippet)

    def test_webview_ssl_error_matches(self):
        assert JAVA_WEBVIEW_SSL_ERROR.pattern.search("public void onReceivedSslError(WebView view,")

    def test_webview_proceed_matches(self):
        assert JAVA_WEBVIEW_PROCEED.pattern.search("handler.proceed()")


# ---------------------------------------------------------------------------
# _smali_params_to_java
# ---------------------------------------------------------------------------

class TestSmaliParamsToJava:
    def test_object_array_and_string(self):
        raw = "[Ljava/security/cert/X509Certificate;Ljava/lang/String;"
        result = _smali_params_to_java(raw)
        assert result == "[Ljava.security.cert.X509Certificate;, java.lang.String"

    def test_primitives(self):
        assert _smali_params_to_java("ZIJ") == "boolean, int, long"

    def test_empty(self):
        assert _smali_params_to_java("") == ""

    def test_single_object(self):
        result = _smali_params_to_java("Ljava/lang/String;")
        assert result == "java.lang.String"

    def test_two_objects(self):
        result = _smali_params_to_java("Ljava/lang/String;Ljava/lang/String;")
        assert result == "java.lang.String, java.lang.String"

    def test_array_of_primitives(self):
        result = _smali_params_to_java("[I")
        assert result == "[I"

    def test_webview_params(self):
        raw = (
            "Landroid/webkit/WebView;"
            "Landroid/webkit/SslErrorHandler;"
            "Landroid/net/http/SslError;"
        )
        result = _smali_params_to_java(raw)
        assert result == (
            "android.webkit.WebView, "
            "android.webkit.SslErrorHandler, "
            "android.net.http.SslError"
        )


# ---------------------------------------------------------------------------
# _smali_path_to_class / _java_path_to_class
# ---------------------------------------------------------------------------

class TestPathToClass:
    def test_smali_standard(self, tmp_path):
        base = tmp_path / "apktool_full"
        path = base / "smali" / "com" / "app" / "ssl" / "Manager.smali"
        assert _smali_path_to_class(path, base) == "com.app.ssl.Manager"

    def test_smali_classes2(self, tmp_path):
        base = tmp_path / "apktool_full"
        path = base / "smali_classes2" / "com" / "app" / "X.smali"
        assert _smali_path_to_class(path, base) == "com.app.X"

    def test_smali_fallback_outside_base(self, tmp_path):
        base = tmp_path / "apktool_full"
        path = tmp_path / "other" / "Foo.smali"
        result = _smali_path_to_class(path, base)
        assert result == "Foo"

    def test_java_with_sources_prefix(self, tmp_path):
        base = tmp_path / "jadx_out"
        path = base / "sources" / "com" / "app" / "Net.java"
        assert _java_path_to_class(path, base) == "com.app.Net"

    def test_java_without_sources_prefix(self, tmp_path):
        base = tmp_path / "jadx_out"
        path = base / "com" / "app" / "Net.java"
        assert _java_path_to_class(path, base) == "com.app.Net"


# ---------------------------------------------------------------------------
# analyze_code — Smali scenarios
# ---------------------------------------------------------------------------

_TRUSTMANAGER_SMALI = """\
.class public Lcom/example/ssl/PinningTM;
.super Ljava/lang/Object;
.implements Ljavax/net/ssl/X509TrustManager;

.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .registers 3
    invoke-static {p1}, Lcom/example/PinVerifier;->verify([Ljava/security/cert/X509Certificate;)V
    return-void
.end method
"""

_TRUST_ALL_SMALI = """\
.class public Lcom/example/ssl/TrustAll;
.super Ljava/lang/Object;
.implements Ljavax/net/ssl/X509TrustManager;

.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .registers 3
    return-void
.end method
"""

_CERT_PINNER_SMALI = """\
.class public Lcom/example/net/ApiClient;
.super Ljava/lang/Object;

.method public buildClient()V
    .registers 2
    new-instance v0, Lokhttp3/CertificatePinner$Builder;
    invoke-direct {v0}, Lokhttp3/CertificatePinner$Builder;-><init>()V
    return-void
.end method
"""

_ALLOW_ALL_HOSTNAME_SMALI = """\
.class public Lcom/example/net/AllowAll;
.super Ljava/lang/Object;
.implements Ljavax/net/ssl/HostnameVerifier;

.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .registers 2
    const/4 v0, 0x1
    return v0
.end method
"""

_WEBVIEW_PROCEED_SMALI = """\
.class public Lcom/example/web/MyClient;
.super Landroid/webkit/WebViewClient;

.method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
    .registers 4
    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->proceed()V
    return-void
.end method
"""

_WEBVIEW_SAFE_SMALI = """\
.class public Lcom/example/web/SafeClient;
.super Landroid/webkit/WebViewClient;

.method public onReceivedSslError(Landroid/webkit/WebView;Landroid/webkit/SslErrorHandler;Landroid/net/http/SslError;)V
    .registers 4
    invoke-virtual {p2}, Landroid/webkit/SslErrorHandler;->cancel()V
    return-void
.end method
"""


class TestAnalyzeCodeSmali:
    def _run(self, tmp_path: Path, filename: str, content: str) -> CodeAnalysisResult:
        base, _ = _smali_file(tmp_path, f"smali/com/example/{filename}", content)
        return analyze_code(smali_dir=base, jadx_dir=None)

    def test_trustmanager_non_vulnerable(self, tmp_path):
        result = self._run(tmp_path, "ssl/PinningTM.smali", _TRUSTMANAGER_SMALI)
        assert len(result.pinning_impls) == 1
        impl = result.pinning_impls[0]
        assert impl.type == HookCategory.TRUST_MANAGER
        assert impl.is_vulnerable is False
        assert impl.confidence == Confidence.HIGH
        # 1 hook target
        assert len(result.hook_targets) == 1
        ht = result.hook_targets[0]
        assert ht.method_name == "checkServerTrusted"
        assert ht.confidence == Confidence.HIGH
        assert len(ht.overloads) > 0

    def test_trustmanager_trust_all_is_vulnerable(self, tmp_path):
        result = self._run(tmp_path, "ssl/TrustAll.smali", _TRUST_ALL_SMALI)
        assert any(impl.is_vulnerable for impl in result.pinning_impls)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert critical, "Expected a CRITICAL finding for trust-all TM"

    def test_cert_pinner_builder(self, tmp_path):
        result = self._run(tmp_path, "net/ApiClient.smali", _CERT_PINNER_SMALI)
        assert len(result.pinning_impls) == 1
        assert result.pinning_impls[0].type == HookCategory.CERTIFICATE_PINNER
        assert result.pinning_impls[0].is_vulnerable is False
        # Hook target should point to okhttp3.CertificatePinner.check
        ht = result.hook_targets[0]
        assert ht.class_name == "okhttp3.CertificatePinner"
        assert ht.method_name == "check"

    def test_hostname_verifier_allow_all(self, tmp_path):
        result = self._run(tmp_path, "net/AllowAll.smali", _ALLOW_ALL_HOSTNAME_SMALI)
        hv = [i for i in result.pinning_impls if i.type == HookCategory.HOSTNAME_VERIFIER]
        assert hv and hv[0].is_vulnerable is True
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_webview_proceed_is_vulnerable(self, tmp_path):
        result = self._run(tmp_path, "web/MyClient.smali", _WEBVIEW_PROCEED_SMALI)
        wv = [i for i in result.pinning_impls if i.type == HookCategory.WEBVIEW_SSL]
        assert wv and wv[0].is_vulnerable is True

    def test_webview_cancel_is_not_vulnerable(self, tmp_path):
        result = self._run(tmp_path, "web/SafeClient.smali", _WEBVIEW_SAFE_SMALI)
        wv = [i for i in result.pinning_impls if i.type == HookCategory.WEBVIEW_SSL]
        assert wv and wv[0].is_vulnerable is False

    def test_empty_dir_returns_empty_result(self, tmp_path):
        base = tmp_path / "apktool_full"
        base.mkdir()
        result = analyze_code(smali_dir=base, jadx_dir=None)
        assert result.findings == []
        assert result.pinning_impls == []
        assert result.hook_targets == []

    def test_none_dirs_returns_empty_result(self, tmp_path):
        result = analyze_code(smali_dir=None, jadx_dir=None)
        assert result.findings == []

    def test_deduplication_same_class_two_files(self, tmp_path):
        base = _smali_dir(tmp_path)
        # Write the same TrustManager class in two different smali subdirs
        _write(base / "smali" / "com" / "example" / "TM.smali", _TRUSTMANAGER_SMALI)
        _write(base / "smali_classes2" / "com" / "example" / "TM.smali", _TRUSTMANAGER_SMALI)
        result = analyze_code(smali_dir=base, jadx_dir=None)
        # Same class_name.method_name should not be duplicated
        keys = [f"{t.class_name}.{t.method_name}" for t in result.hook_targets]
        assert len(keys) == len(set(keys)), "Duplicate hook targets found"

    def test_overload_extraction_content(self, tmp_path):
        result = self._run(tmp_path, "ssl/PinningTM.smali", _TRUSTMANAGER_SMALI)
        ht = result.hook_targets[0]
        assert any(
            "X509Certificate" in ol for ol in ht.overloads
        ), f"Expected X509Certificate in overloads, got: {ht.overloads}"


# ---------------------------------------------------------------------------
# analyze_code — Java scenarios
# ---------------------------------------------------------------------------

_TRUSTMANAGER_JAVA = """\
package com.example.ssl;

import javax.net.ssl.X509TrustManager;

public class PinningTM implements X509TrustManager {
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType)
            throws java.security.cert.CertificateException {
        verifyPin(chain);
    }
}
"""

_TRUST_ALL_JAVA = """\
package com.example.ssl;

import javax.net.ssl.X509TrustManager;

public class TrustAllTM implements X509TrustManager {
    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
    }
}
"""

_CERT_PINNER_JAVA = """\
package com.example.net;

import okhttp3.CertificatePinner;

public class ApiClient {
    private static CertificatePinner buildPinner() {
        return new CertificatePinner.Builder()
            .add("api.example.com", "sha256/AAAA=")
            .build();
    }
}
"""


class TestAnalyzeCodeJava:
    def _run(self, tmp_path: Path, rel: str, content: str) -> CodeAnalysisResult:
        jadx_base = tmp_path / "jadx_out"
        _write(jadx_base / "sources" / rel, content)
        return analyze_code(smali_dir=None, jadx_dir=jadx_base)

    def test_trustmanager_non_vulnerable(self, tmp_path):
        result = self._run(tmp_path, "com/example/ssl/PinningTM.java", _TRUSTMANAGER_JAVA)
        impls = [i for i in result.pinning_impls if i.type == HookCategory.TRUST_MANAGER]
        assert impls and impls[0].is_vulnerable is False

    def test_trustmanager_trust_all(self, tmp_path):
        result = self._run(tmp_path, "com/example/ssl/TrustAllTM.java", _TRUST_ALL_JAVA)
        impls = [i for i in result.pinning_impls if i.type == HookCategory.TRUST_MANAGER]
        assert impls and impls[0].is_vulnerable is True

    def test_cert_pinner_java(self, tmp_path):
        result = self._run(tmp_path, "com/example/net/ApiClient.java", _CERT_PINNER_JAVA)
        impls = [i for i in result.pinning_impls if i.type == HookCategory.CERTIFICATE_PINNER]
        assert impls

    def test_java_overloads_are_empty_or_default(self, tmp_path):
        result = self._run(tmp_path, "com/example/ssl/PinningTM.java", _TRUSTMANAGER_JAVA)
        ht = next(
            (t for t in result.hook_targets if t.method_name == "checkServerTrusted"),
            None,
        )
        assert ht is not None
        # Java source can't give precise Smali descriptors
        assert isinstance(ht.overloads, list)


# ---------------------------------------------------------------------------
# analyze_nsc
# ---------------------------------------------------------------------------

class TestAnalyzeNsc:
    def test_no_nsc_file(self, tmp_path):
        apktool_dir = tmp_path / "apktool_out"
        apktool_dir.mkdir()
        nsc, findings = analyze_nsc(apktool_dir)
        assert nsc.found is False
        assert any(f.id == "NSC-001" for f in findings)

    def test_sha256_with_backup_pin(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0" encoding="utf-8"?>
            <network-security-config>
                <domain-config>
                    <domain includeSubdomains="false">api.example.com</domain>
                    <pin-set expiration="2027-01-01">
                        <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
                        <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
                    </pin-set>
                </domain-config>
            </network-security-config>
        """)
        apktool_dir = tmp_path / "apktool_out"
        _write(apktool_dir / "res" / "xml" / "network_security_config.xml", xml)
        nsc, findings = analyze_nsc(apktool_dir)
        assert nsc.found is True
        assert len(nsc.pin_sets) == 1
        ps = nsc.pin_sets[0]
        assert ps.has_backup is True
        assert ps.expiry == "2027-01-01"
        assert not any(f.id.startswith("NSC-NOBACKUP") for f in findings)
        assert not any(f.id.startswith("NSC-NOEXPIRY") for f in findings)

    def test_single_pin_no_backup(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0" encoding="utf-8"?>
            <network-security-config>
                <domain-config>
                    <domain>api.example.com</domain>
                    <pin-set>
                        <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
                    </pin-set>
                </domain-config>
            </network-security-config>
        """)
        apktool_dir = tmp_path / "apktool_out"
        _write(apktool_dir / "res" / "xml" / "network_security_config.xml", xml)
        nsc, findings = analyze_nsc(apktool_dir)
        assert nsc.pin_sets[0].has_backup is False
        assert any(f.id.startswith("NSC-NOBACKUP") for f in findings)

    def test_no_expiry_generates_finding(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0" encoding="utf-8"?>
            <network-security-config>
                <domain-config>
                    <domain>api.example.com</domain>
                    <pin-set>
                        <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
                    </pin-set>
                </domain-config>
            </network-security-config>
        """)
        apktool_dir = tmp_path / "apktool_out"
        _write(apktool_dir / "res" / "xml" / "network_security_config.xml", xml)
        nsc, findings = analyze_nsc(apktool_dir)
        assert nsc.pin_sets[0].expiry is None
        assert any(f.id.startswith("NSC-NOEXPIRY") for f in findings)

    def test_cleartext_allowed(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0" encoding="utf-8"?>
            <network-security-config>
                <base-config cleartextTrafficPermitted="true" />
            </network-security-config>
        """)
        apktool_dir = tmp_path / "apktool_out"
        _write(apktool_dir / "res" / "xml" / "network_security_config.xml", xml)
        nsc, findings = analyze_nsc(apktool_dir)
        assert nsc.cleartext_allowed is True
        assert any(f.id == "NSC-CLEARTEXT" for f in findings)

    def test_nsc_exists_no_pins(self, tmp_path):
        xml = textwrap.dedent("""\
            <?xml version="1.0" encoding="utf-8"?>
            <network-security-config>
                <base-config cleartextTrafficPermitted="false" />
            </network-security-config>
        """)
        apktool_dir = tmp_path / "apktool_out"
        _write(apktool_dir / "res" / "xml" / "network_security_config.xml", xml)
        nsc, findings = analyze_nsc(apktool_dir)
        assert nsc.found is True
        assert nsc.pin_sets == []
        assert any(f.id == "NSC-NOPIN" for f in findings)

    def test_malformed_xml(self, tmp_path):
        apktool_dir = tmp_path / "apktool_out"
        _write(
            apktool_dir / "res" / "xml" / "network_security_config.xml",
            "<not-valid-xml><<<",
        )
        nsc, findings = analyze_nsc(apktool_dir)
        assert nsc.found is True
        assert any(f.id == "NSC-002" for f in findings)


# ---------------------------------------------------------------------------
# analyze_protection
# ---------------------------------------------------------------------------

class TestAnalyzeProtection:
    def test_no_native_libs(self, tmp_path):
        apktool_dir = tmp_path / "apktool_out"
        apktool_dir.mkdir()
        profile, _ = analyze_protection(apktool_dir=apktool_dir)
        assert profile.native_libs == []

    def test_native_libs_detected(self, tmp_path):
        apktool_dir = tmp_path / "apktool_out"
        lib = apktool_dir / "lib" / "arm64-v8a" / "libssl_pinning.so"
        lib.parent.mkdir(parents=True)
        lib.write_bytes(b"\x7fELF")
        profile, findings = analyze_protection(apktool_dir=apktool_dir)
        assert len(profile.native_libs) == 1
        assert any(f.id == "PROT-NATIVE" for f in findings)

    def test_no_obfuscation_long_names(self, tmp_path):
        smali_dir = tmp_path / "apktool_full"
        smali = smali_dir / "smali"
        smali.mkdir(parents=True)
        for name in ["AuthenticationManager", "NetworkRequestHandler", "CertificateValidator"]:
            (smali / f"{name}.smali").write_text("", encoding="utf-8")
        profile, _ = analyze_protection(apktool_dir=smali_dir, smali_dir=smali_dir)
        assert profile.obfuscation_level == ObfuscationLevel.NONE

    def test_strong_obfuscation_short_names(self, tmp_path):
        smali_dir = tmp_path / "apktool_full"
        smali = smali_dir / "smali"
        smali.mkdir(parents=True)
        # >40% short names triggers STRONG
        short = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]
        long_ = ["LongName1", "LongName2"]
        for name in short + long_:
            (smali / f"{name}.smali").write_text("", encoding="utf-8")
        profile, _ = analyze_protection(apktool_dir=smali_dir, smali_dir=smali_dir)
        assert profile.obfuscation_level == ObfuscationLevel.STRONG

    def test_safetynet_detected(self, tmp_path):
        smali_dir = tmp_path / "apktool_full"
        smali = smali_dir / "smali"
        smali.mkdir(parents=True)
        _write(
            smali / "com" / "app" / "SafetyCheck.smali",
            "invoke-static {}, Lcom/google/android/gms/safetynet/SafetyNet;->getClient()V",
        )
        profile, findings = analyze_protection(apktool_dir=smali_dir, smali_dir=smali_dir)
        assert "SafetyNet" in profile.integrity_checks
        assert any(f.id == "PROT-SAFETYNET" for f in findings)

    def test_play_integrity_detected(self, tmp_path):
        smali_dir = tmp_path / "apktool_full"
        smali = smali_dir / "smali"
        smali.mkdir(parents=True)
        _write(
            smali / "com" / "app" / "IntegrityCheck.smali",
            "const-string v0, \"com.google.android.play.core.integrity.IntegrityManager\"",
        )
        profile, findings = analyze_protection(apktool_dir=smali_dir, smali_dir=smali_dir)
        assert "Play Integrity" in profile.integrity_checks
        assert any(f.id == "PROT-PLAYINTEGRITY" for f in findings)

    def test_root_detection_detected(self, tmp_path):
        smali_dir = tmp_path / "apktool_full"
        smali = smali_dir / "smali"
        smali.mkdir(parents=True)
        _write(
            smali / "com" / "app" / "RootCheck.smali",
            "invoke-static {}, Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z",
        )
        profile, findings = analyze_protection(apktool_dir=smali_dir, smali_dir=smali_dir)
        assert profile.root_detection is True
        assert any(f.id == "PROT-ROOT" for f in findings)

    def test_no_protection_patterns(self, tmp_path):
        smali_dir = tmp_path / "apktool_full"
        smali = smali_dir / "smali"
        smali.mkdir(parents=True)
        _write(smali / "com" / "app" / "Plain.smali", "# plain smali with nothing special")
        profile, _ = analyze_protection(apktool_dir=smali_dir, smali_dir=smali_dir)
        assert profile.integrity_checks == []
        assert profile.root_detection is False
