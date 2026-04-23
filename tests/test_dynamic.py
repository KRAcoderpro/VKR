"""Unit tests for the dynamic analysis module (Phase 4).

All tests run without a real Android device or Frida installation.
Frida is mocked via sys.modules; ADB subprocess calls are patched.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

from tls_pineval.models.common import (
    AppInfo,
    AppReaction,
    Confidence,
    HookCategory,
    HookTarget,
    VerificationResult,
)
from tls_pineval.models.dynamic_report import BypassAttempt, DetectionResults
from tls_pineval.models.static_report import StaticReport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_frida():
    """Inject a mock frida module into sys.modules for the duration of the test."""
    m = MagicMock()
    m.__version__ = "16.2.1"
    with patch.dict(sys.modules, {"frida": m}):
        yield m


def _make_app_info(pkg: str = "com.example.app") -> AppInfo:
    return AppInfo(
        apk_path=Path("/tmp/app.apk"),
        package_name=pkg,
        app_name="ExampleApp",
        version="1.0",
    )


def _make_static_report(targets: list[HookTarget] | None = None) -> StaticReport:
    return StaticReport(
        app_info=_make_app_info(),
        hookable_targets=targets or [],
    )


def _make_target(
    category: HookCategory = HookCategory.TRUST_MANAGER,
    overloads: list[str] | None = None,
) -> HookTarget:
    return HookTarget(
        class_name="com.app.PinManager",
        method_name="checkServerTrusted",
        category=category,
        overloads=overloads or [],
        source_file="com/app/PinManager.smali",
        confidence=Confidence.HIGH,
    )


# ---------------------------------------------------------------------------
# script_generator tests
# ---------------------------------------------------------------------------


class TestScriptGenerator:
    def test_generic_script_loads(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_generic_script

        js = generate_generic_script()
        assert len(js) > 100
        assert "Java.perform" in js
        assert "hook_triggered" in js

    def test_detection_script_loads(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_detection_script

        js = generate_detection_script()
        assert "Java.perform" in js
        assert "detection_script_ready" in js

    def test_targeted_trustmanager_with_overloads(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = _make_target(
            HookCategory.TRUST_MANAGER,
            overloads=["[Ljava.security.cert.X509Certificate;, java.lang.String"],
        )
        js = generate_targeted_script(t)
        assert "com.app.PinManager" in js
        assert "checkServerTrusted" in js
        assert "X509Certificate" in js
        assert "return;" in js  # void method

    def test_targeted_trustmanager_no_overloads(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = _make_target(HookCategory.TRUST_MANAGER, overloads=[])
        js = generate_targeted_script(t)
        assert "overloads.forEach" in js
        assert "return;" in js

    def test_targeted_hostname_verifier_returns_true(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = HookTarget(
            class_name="com.app.HV",
            method_name="verify",
            category=HookCategory.HOSTNAME_VERIFIER,
            overloads=[],
            source_file="com/app/HV.smali",
            confidence=Confidence.HIGH,
        )
        js = generate_targeted_script(t)
        assert "return true;" in js

    def test_targeted_certificate_pinner_uses_okhttp_template(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = HookTarget(
            class_name="com.app.Pinner",
            method_name="check",
            category=HookCategory.CERTIFICATE_PINNER,
            overloads=[],
            source_file="com/app/Pinner.smali",
            confidence=Confidence.HIGH,
        )
        js = generate_targeted_script(t)
        assert "com.app.Pinner" in js
        assert "return;" in js

    def test_targeted_webview_calls_proceed(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = HookTarget(
            class_name="com.app.MyWebViewClient",
            method_name="onReceivedSslError",
            category=HookCategory.WEBVIEW_SSL,
            overloads=[],
            source_file="com/app/MyWebViewClient.smali",
            confidence=Confidence.HIGH,
        )
        js = generate_targeted_script(t)
        assert "proceed" in js
        assert "com.app.MyWebViewClient" in js

    def test_targeted_webview_with_overloads_calls_proceed(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = HookTarget(
            class_name="com.app.WVC",
            method_name="onReceivedSslError",
            category=HookCategory.WEBVIEW_SSL,
            overloads=["android.webkit.WebView, android.webkit.SslErrorHandler, android.net.http.SslError"],
            source_file="com/app/WVC.smali",
            confidence=Confidence.HIGH,
        )
        js = generate_targeted_script(t)
        assert "proceed" in js

    def test_targeted_custom_returns_void(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = HookTarget(
            class_name="com.app.Custom",
            method_name="doPin",
            category=HookCategory.CUSTOM,
            overloads=[],
            source_file="com/app/Custom.smali",
            confidence=Confidence.MEDIUM,
        )
        js = generate_targeted_script(t)
        assert "com.app.Custom" in js
        assert "doPin" in js
        # CUSTOM is treated same as TRUST_MANAGER: void return
        assert "return;" in js

    def test_class_name_substituted_fully(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = _make_target()
        js = generate_targeted_script(t)
        assert "{{CLASS_NAME}}" not in js
        assert "{{METHOD_NAME}}" not in js
        assert "{{OVERLOADS_CODE}}" not in js

    def test_multiple_overloads_each_hooked(self) -> None:
        from tls_pineval.dynamic.script_generator import generate_targeted_script

        t = HookTarget(
            class_name="com.app.PM",
            method_name="checkServerTrusted",
            category=HookCategory.TRUST_MANAGER,
            overloads=[
                "[Ljava.security.cert.X509Certificate;, java.lang.String",
                "[Ljava.security.cert.X509Certificate;, java.lang.String, java.lang.String",
            ],
            source_file="x.smali",
            confidence=Confidence.HIGH,
        )
        js = generate_targeted_script(t)
        # Both overloads should appear in the actual Java.perform block
        java_block = js[js.index("Java.perform"):]
        assert java_block.count(".overload(") >= 2


# ---------------------------------------------------------------------------
# _classify_logcat tests
# ---------------------------------------------------------------------------


class TestClassifyLogcat:
    def _classify(self, lines: list[str]):
        from tls_pineval.dynamic.bypass_runner import _classify_logcat
        return _classify_logcat(lines)

    def test_ssl_handshake_exception_is_failed(self) -> None:
        v, m = self._classify(["W/App: javax.net.ssl.SSLHandshakeException: cert"])
        assert v == VerificationResult.FAILED
        assert m == "logcat"

    def test_ssl_peer_unverified_is_failed(self) -> None:
        v, _ = self._classify(["SSLPeerUnverifiedException: hostname not verified"])
        assert v == VerificationResult.FAILED

    def test_certificate_verify_failed_is_failed(self) -> None:
        v, _ = self._classify(["CERTIFICATE_VERIFY_FAILED"])
        assert v == VerificationResult.FAILED

    def test_trust_anchor_not_found_is_failed(self) -> None:
        v, _ = self._classify(["Trust anchor for certification path not found"])
        assert v == VerificationResult.FAILED

    def test_http_200_is_success(self) -> None:
        v, m = self._classify(["D/OkHttp: <-- 200 OK https://api.example.com"])
        assert v == VerificationResult.SUCCESS

    def test_http11_200_is_success(self) -> None:
        v, _ = self._classify(["HTTP/1.1 200 OK"])
        assert v == VerificationResult.SUCCESS

    def test_empty_lines_is_inconclusive(self) -> None:
        v, _ = self._classify([])
        assert v == VerificationResult.INCONCLUSIVE

    def test_unrelated_log_is_inconclusive(self) -> None:
        v, _ = self._classify(["D/ActivityManager: Process started"])
        assert v == VerificationResult.INCONCLUSIVE

    def test_ssl_error_takes_priority_over_200(self) -> None:
        # Both in log — FAILED takes priority (checked first)
        v, _ = self._classify(["SSLHandshakeException", "HTTP/1.1 200"])
        assert v == VerificationResult.FAILED


# ---------------------------------------------------------------------------
# bypass_runner.run_bypass tests
# ---------------------------------------------------------------------------


class TestRunBypass:
    """Tests for run_bypass using a mocked Frida device."""

    def _make_device(
        self,
        on_message_trigger: bool = False,
        spawn_error: Exception | None = None,
    ) -> tuple[MagicMock, list]:
        """Return (mock_device, messages_list).

        If on_message_trigger is True, the script.on() call will immediately
        invoke the registered callback with a hook_triggered payload.
        """
        device = MagicMock()
        messages: list = []

        if spawn_error:
            device.spawn.side_effect = spawn_error
        else:
            device.spawn.return_value = 42  # pid

        session = MagicMock()
        device.attach.return_value = session

        script = MagicMock()
        session.create_script.return_value = script

        if on_message_trigger:
            def fake_on(event, callback):
                if event == "message":
                    callback(
                        {"type": "send", "payload": {"type": "hook_triggered", "method": "test"}},
                        None,
                    )
            script.on.side_effect = fake_on

        return device, messages

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_ssl_exception_in_logcat_is_failed(self, MockMonitor, mock_sleep) -> None:
        from tls_pineval.dynamic.bypass_runner import run_bypass

        monitor = MagicMock()
        monitor.stop.return_value = ["W/App: SSLHandshakeException: cert error"]
        MockMonitor.return_value = monitor

        device, _ = self._make_device(on_message_trigger=True)
        result = run_bypass(device, "com.example", "Java.perform(function(){});", "test")

        assert result.verification == VerificationResult.FAILED
        assert result.verification_method == "logcat"
        assert result.hook_triggered is True

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_http_200_in_logcat_is_success(self, MockMonitor, mock_sleep) -> None:
        from tls_pineval.dynamic.bypass_runner import run_bypass

        monitor = MagicMock()
        monitor.stop.return_value = ["D/OkHttp: <-- 200 OK https://api.example.com"]
        MockMonitor.return_value = monitor

        device, _ = self._make_device(on_message_trigger=True)
        result = run_bypass(device, "com.example", "Java.perform(function(){});", "test")

        assert result.verification == VerificationResult.SUCCESS
        assert result.hook_triggered is True
        assert result.confidence == Confidence.HIGH

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_no_network_activity_is_inconclusive(self, MockMonitor, mock_sleep) -> None:
        from tls_pineval.dynamic.bypass_runner import run_bypass

        monitor = MagicMock()
        monitor.stop.return_value = ["D/ActivityManager: Process started"]
        MockMonitor.return_value = monitor

        device, _ = self._make_device(on_message_trigger=False)
        result = run_bypass(device, "com.example", "Java.perform(function(){});", "test")

        assert result.verification == VerificationResult.INCONCLUSIVE
        assert result.confidence == Confidence.MEDIUM

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_spawn_error_returns_low_confidence_inconclusive(
        self, MockMonitor, mock_sleep
    ) -> None:
        from tls_pineval.dynamic.bypass_runner import run_bypass

        monitor = MagicMock()
        monitor.stop.return_value = []
        MockMonitor.return_value = monitor

        device, _ = self._make_device(spawn_error=RuntimeError("Process not found"))
        result = run_bypass(device, "com.example", "Java.perform(function(){});", "test")

        assert result.error is not None
        assert "Process not found" in result.error
        assert result.hook_triggered is False
        assert result.verification == VerificationResult.INCONCLUSIVE
        assert result.confidence == Confidence.LOW

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_target_stored_in_result(self, MockMonitor, mock_sleep) -> None:
        from tls_pineval.dynamic.bypass_runner import run_bypass

        monitor = MagicMock()
        monitor.stop.return_value = []
        MockMonitor.return_value = monitor

        device, _ = self._make_device()
        target = _make_target()
        result = run_bypass(
            device, "com.example", "Java.perform(function(){});", "targeted_tm",
            target=target,
        )

        assert result.target == target
        assert result.script_name == "targeted_tm"
        assert result.generated_script == "Java.perform(function(){});"

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_logcat_lines_stored_in_logs(self, MockMonitor, mock_sleep) -> None:
        from tls_pineval.dynamic.bypass_runner import run_bypass

        monitor = MagicMock()
        monitor.stop.return_value = ["line1", "line2", "line3"]
        MockMonitor.return_value = monitor

        device, _ = self._make_device()
        result = run_bypass(device, "com.example", "Java.perform(function(){});", "test")

        assert "line1" in result.logs
        assert "line2" in result.logs

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_duration_ms_is_positive(self, MockMonitor, mock_sleep) -> None:
        from tls_pineval.dynamic.bypass_runner import run_bypass

        monitor = MagicMock()
        monitor.stop.return_value = []
        MockMonitor.return_value = monitor

        device, _ = self._make_device()
        result = run_bypass(device, "com.example", "Java.perform(function(){});", "test")

        assert result.duration_ms >= 0


# ---------------------------------------------------------------------------
# detection_tester.test_detection tests
# ---------------------------------------------------------------------------


class TestDetectionTester:
    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    def test_no_events_returns_none_detected(self, mock_sleep) -> None:
        from tls_pineval.dynamic.detection_tester import test_detection

        device = MagicMock()
        device.spawn.return_value = 99
        session = MagicMock()
        device.attach.return_value = session
        script = MagicMock()
        session.create_script.return_value = script

        result = test_detection(device, "com.example", "Java.perform(function(){});")

        assert result.frida_detected is False
        assert result.root_detected is False
        assert result.debugger_detected is False
        assert result.app_reaction == AppReaction.NONE

    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    def test_root_check_event_sets_root_detected(self, mock_sleep) -> None:
        from tls_pineval.dynamic.detection_tester import test_detection

        device = MagicMock()
        device.spawn.return_value = 99
        session = MagicMock()
        device.attach.return_value = session
        script = MagicMock()
        session.create_script.return_value = script

        def fake_on(event, callback):
            if event == "message":
                callback(
                    {"type": "send", "payload": {"type": "root_check", "cmd": "su"}},
                    None,
                )

        script.on.side_effect = fake_on

        result = test_detection(device, "com.example", "Java.perform(function(){});")

        assert result.root_detected is True

    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    def test_debugger_check_event_sets_debugger_detected(self, mock_sleep) -> None:
        from tls_pineval.dynamic.detection_tester import test_detection

        device = MagicMock()
        device.spawn.return_value = 99
        session = MagicMock()
        device.attach.return_value = session
        script = MagicMock()
        session.create_script.return_value = script

        def fake_on(event, callback):
            if event == "message":
                callback(
                    {"type": "send", "payload": {"type": "debugger_check"}},
                    None,
                )

        script.on.side_effect = fake_on

        result = test_detection(device, "com.example", "Java.perform(function(){});")

        assert result.debugger_detected is True

    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    def test_app_crash_sets_frida_detected(self, mock_sleep) -> None:
        from tls_pineval.dynamic.detection_tester import test_detection

        device = MagicMock()
        device.spawn.return_value = 99
        session = MagicMock()
        device.attach.return_value = session
        script = MagicMock()
        session.create_script.return_value = script
        # Simulate app killing Frida session during sleep
        mock_sleep.side_effect = RuntimeError("process terminated: killed")

        result = test_detection(device, "com.example", "Java.perform(function(){});")

        assert result.frida_detected is True
        assert result.app_reaction == AppReaction.CRASH

    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    def test_spawn_failure_no_detection_inferred(self, mock_sleep) -> None:
        from tls_pineval.dynamic.detection_tester import test_detection

        device = MagicMock()
        device.spawn.side_effect = RuntimeError("package not found")

        result = test_detection(device, "com.example", "Java.perform(function(){});")

        # A spawn error is not a crash-during-Frida-attach, so frida_detected stays False
        assert result.frida_detected is False


# ---------------------------------------------------------------------------
# _ensure_environment_ready tests
# ---------------------------------------------------------------------------


class TestEnsureEnvironmentReady:
    """Tests for the 5-step environment pre-check."""

    def _adb_ok_output(self, pkg: str = "com.example.app") -> dict[str, str]:
        return {
            "devices": "List of devices attached\nemulator-5554\tdevice\n",
            "getprop": "14\n",
            "pm": f"package:{pkg}\n",
            "id": "uid=0(root) gid=0(root)\n",
        }

    def _patch_run_adb(self, outputs: dict[str, str]):
        """Return a side_effect function for run_adb based on first arg."""
        def fake_run_adb(*args, timeout=30):
            first = args[0] if args else ""
            if first == "devices":
                return outputs.get("devices", "")
            if first == "shell" and len(args) > 1:
                second = args[1]
                if second == "getprop":
                    return outputs.get("getprop", "14\n")
                if second == "pm":
                    return outputs.get("pm", "")
                if second == "id":
                    return outputs.get("id", "")
            return ""
        return fake_run_adb

    def test_success_returns_environment(self, mock_frida) -> None:
        from tls_pineval.dynamic.analyzer import _ensure_environment_ready

        mock_device = MagicMock()
        mock_frida.get_usb_device.return_value = mock_device
        mock_frida.__version__ = "16.2.1"
        outputs = self._adb_ok_output()

        with patch(
            "tls_pineval.dynamic.analyzer.run_adb",
            side_effect=self._patch_run_adb(outputs),
        ):
            env, device = _ensure_environment_ready("com.example.app")

        assert env.device_id == "emulator-5554"
        assert env.android_version == "14"
        assert env.frida_version == "16.2.1"
        assert env.is_rooted is True
        assert device is mock_device

    def test_no_adb_device_raises(self, mock_frida) -> None:
        from tls_pineval.dynamic.analyzer import DynamicAnalysisError, _ensure_environment_ready

        def fake_run_adb(*args, timeout=30):
            if args and args[0] == "devices":
                return "List of devices attached\n"  # no device line
            return ""

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=fake_run_adb):
            with pytest.raises(DynamicAnalysisError, match="No ADB device"):
                _ensure_environment_ready("com.example.app")

    def test_adb_not_found_raises(self, mock_frida) -> None:
        from tls_pineval.dynamic.analyzer import DynamicAnalysisError, _ensure_environment_ready
        from tls_pineval.tools import ToolError

        with patch(
            "tls_pineval.dynamic.analyzer.run_adb",
            side_effect=ToolError("adb not found"),
        ):
            with pytest.raises(DynamicAnalysisError, match="ADB not available"):
                _ensure_environment_ready("com.example.app")

    def test_empty_android_version_raises(self, mock_frida) -> None:
        from tls_pineval.dynamic.analyzer import DynamicAnalysisError, _ensure_environment_ready

        def fake_run_adb(*args, timeout=30):
            if args and args[0] == "devices":
                return "List of devices attached\nemulator-5554\tdevice\n"
            if args and args[0] == "shell" and len(args) > 1 and args[1] == "getprop":
                return "   "  # whitespace only → empty after strip
            return ""

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=fake_run_adb):
            with pytest.raises(DynamicAnalysisError, match="Cannot read device properties"):
                _ensure_environment_ready("com.example.app")

    def test_frida_get_device_fails_raises(self, mock_frida) -> None:
        from tls_pineval.dynamic.analyzer import DynamicAnalysisError, _ensure_environment_ready

        mock_frida.get_usb_device.side_effect = Exception("Frida server not found")
        outputs = self._adb_ok_output()

        with patch(
            "tls_pineval.dynamic.analyzer.run_adb",
            side_effect=self._patch_run_adb(outputs),
        ):
            with pytest.raises(DynamicAnalysisError, match="Frida cannot connect"):
                _ensure_environment_ready("com.example.app")

    def test_frida_enumerate_fails_raises(self, mock_frida) -> None:
        from tls_pineval.dynamic.analyzer import DynamicAnalysisError, _ensure_environment_ready

        mock_device = MagicMock()
        mock_device.enumerate_processes.side_effect = Exception("timeout")
        mock_frida.get_usb_device.return_value = mock_device
        outputs = self._adb_ok_output()

        with patch(
            "tls_pineval.dynamic.analyzer.run_adb",
            side_effect=self._patch_run_adb(outputs),
        ):
            with pytest.raises(DynamicAnalysisError, match="frida-server not responding"):
                _ensure_environment_ready("com.example.app")

    def test_frida_not_installed_raises(self) -> None:
        from tls_pineval.dynamic.analyzer import DynamicAnalysisError, _ensure_environment_ready

        # Remove frida from sys.modules (simulate not installed)
        with patch.dict(sys.modules, {"frida": None}):
            with pytest.raises((DynamicAnalysisError, ImportError)):
                _ensure_environment_ready("com.example.app")


# ---------------------------------------------------------------------------
# analyze() integration tests (full flow, all mocked)
# ---------------------------------------------------------------------------


class TestAnalyze:
    def _setup_mocks(
        self,
        mock_frida: MagicMock,
        logcat_lines: list[str] | None = None,
        generic_verification: VerificationResult = VerificationResult.FAILED,
    ):
        """Wire up all mocks for a successful analyze() call."""
        mock_device = MagicMock()
        mock_frida.get_usb_device.return_value = mock_device
        mock_frida.__version__ = "16.2.1"
        mock_device.spawn.return_value = 42
        mock_device.attach.return_value = MagicMock()

        script = MagicMock()
        mock_device.attach.return_value.create_script.return_value = script

        return mock_device

    def _patch_run_adb_all_ok(self, pkg: str = "com.example.app"):
        def fake(  *args, timeout=30):
            first = args[0] if args else ""
            if first == "devices":
                return f"List of devices attached\nemulator-5554\tdevice\n"
            if first == "shell":
                second = args[1] if len(args) > 1 else ""
                if second == "getprop":
                    return "14\n"
                if second == "pm":
                    return f"package:{pkg}\n"
                if second == "id":
                    return "uid=0(root)\n"
            if first == "install":
                return "Success\n"
            return ""
        return fake

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_generic_success_skips_targeted(
        self, MockMonitor, mock_det_sleep, mock_bp_sleep, mock_frida, tmp_path
    ) -> None:
        from tls_pineval.dynamic.analyzer import analyze

        monitor = MagicMock()
        monitor.stop.return_value = ["HTTP/1.1 200 OK"]
        MockMonitor.return_value = monitor

        static_report = _make_static_report(targets=[_make_target()])

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=self._patch_run_adb_all_ok()):
            mock_device = self._setup_mocks(mock_frida)
            report = analyze(
                Path("/tmp/app.apk"),
                static_report,
                output_dir=tmp_path,
            )

        assert report.overall_bypass is True
        assert report.targeted_bypass_needed is False
        # Only the generic attempt
        assert len(report.bypass_attempts) == 1
        assert report.bypass_attempts[0].script_name == "generic_unpinner"

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_generic_fail_triggers_targeted(
        self, MockMonitor, mock_det_sleep, mock_bp_sleep, mock_frida, tmp_path
    ) -> None:
        from tls_pineval.dynamic.analyzer import analyze

        # Generic: SSL error (FAILED), Targeted: 200 (SUCCESS)
        call_count = [0]

        def stop_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return ["SSLHandshakeException: cert error"]
            return ["HTTP/1.1 200 OK"]

        monitor = MagicMock()
        monitor.stop.side_effect = stop_side_effect
        MockMonitor.return_value = monitor

        static_report = _make_static_report(targets=[_make_target()])

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=self._patch_run_adb_all_ok()):
            self._setup_mocks(mock_frida)
            report = analyze(Path("/tmp/app.apk"), static_report, output_dir=tmp_path)

        assert report.targeted_bypass_needed is True
        assert report.overall_bypass is True
        # Generic + 1 targeted attempt
        assert len(report.bypass_attempts) == 2
        assert report.bypass_attempts[0].script_name == "generic_unpinner"

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_report_saved_to_output_dir(
        self, MockMonitor, mock_det_sleep, mock_bp_sleep, mock_frida, tmp_path
    ) -> None:
        from tls_pineval.dynamic.analyzer import analyze

        monitor = MagicMock()
        monitor.stop.return_value = []
        MockMonitor.return_value = monitor

        static_report = _make_static_report()

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=self._patch_run_adb_all_ok()):
            self._setup_mocks(mock_frida)
            analyze(Path("/tmp/app.apk"), static_report, output_dir=tmp_path)

        report_file = tmp_path / "dynamic_report.json"
        assert report_file.exists()
        content = report_file.read_text()
        assert "bypass_attempts" in content

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_no_targets_no_targeted_bypass(
        self, MockMonitor, mock_det_sleep, mock_bp_sleep, mock_frida, tmp_path
    ) -> None:
        from tls_pineval.dynamic.analyzer import analyze

        monitor = MagicMock()
        monitor.stop.return_value = ["SSLHandshakeException"]
        MockMonitor.return_value = monitor

        static_report = _make_static_report(targets=[])  # no hookable targets

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=self._patch_run_adb_all_ok()):
            self._setup_mocks(mock_frida)
            report = analyze(Path("/tmp/app.apk"), static_report, output_dir=tmp_path)

        # Generic failed, no targets → targeted_bypass_needed stays False
        assert report.targeted_bypass_needed is False
        assert len(report.bypass_attempts) == 1

    def test_environment_failure_raises_dynamic_analysis_error(
        self, mock_frida, tmp_path
    ) -> None:
        from tls_pineval.dynamic.analyzer import DynamicAnalysisError, analyze

        def bad_adb(*args, timeout=30):
            if args and args[0] == "devices":
                return "List of devices attached\n"  # no device
            return ""

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=bad_adb):
            with pytest.raises(DynamicAnalysisError):
                analyze(
                    Path("/tmp/app.apk"),
                    _make_static_report(),
                    output_dir=tmp_path,
                )

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_mitm_check_is_skipped(
        self, MockMonitor, mock_det_sleep, mock_bp_sleep, mock_frida, tmp_path
    ) -> None:
        from tls_pineval.dynamic.analyzer import analyze

        monitor = MagicMock()
        monitor.stop.return_value = []
        MockMonitor.return_value = monitor

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=self._patch_run_adb_all_ok()):
            self._setup_mocks(mock_frida)
            report = analyze(Path("/tmp/app.apk"), _make_static_report(), output_dir=tmp_path)

        assert report.mitm_check.status.value == "SKIPPED"

    @patch("tls_pineval.dynamic.bypass_runner.time.sleep")
    @patch("tls_pineval.dynamic.detection_tester.time.sleep")
    @patch("tls_pineval.dynamic.bypass_runner._LogcatMonitor")
    def test_environment_metadata_in_report(
        self, MockMonitor, mock_det_sleep, mock_bp_sleep, mock_frida, tmp_path
    ) -> None:
        from tls_pineval.dynamic.analyzer import analyze

        monitor = MagicMock()
        monitor.stop.return_value = []
        MockMonitor.return_value = monitor

        with patch("tls_pineval.dynamic.analyzer.run_adb", side_effect=self._patch_run_adb_all_ok()):
            self._setup_mocks(mock_frida)
            report = analyze(Path("/tmp/app.apk"), _make_static_report(), output_dir=tmp_path)

        assert report.environment.device_id == "emulator-5554"
        assert report.environment.android_version == "14"
        assert report.environment.frida_version == "16.2.1"
