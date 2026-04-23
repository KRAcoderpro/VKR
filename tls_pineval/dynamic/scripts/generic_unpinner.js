'use strict';
/**
 * TLS-PinEval Generic Unpinner
 *
 * Hooks the most common Android TLS certificate pinning APIs in one pass.
 * Designed for spawn-gating: inject before app code runs so hooks are active
 * on the very first network connection.
 *
 * Sends Frida messages:
 *   { type: 'hook_triggered', hook: '<name>' }  — when a hook fires
 *   { type: 'ready', hooks_installed: [...] }    — after setup completes
 */

Java.perform(function () {
    var installed = [];

    // -----------------------------------------------------------------------
    // OkHttp3 CertificatePinner
    // -----------------------------------------------------------------------
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        ['check', 'check$okhttp'].forEach(function (m) {
            try {
                CP[m].overloads.forEach(function (overload) {
                    overload.implementation = function () {
                        send({ type: 'hook_triggered', hook: 'okhttp3.CertificatePinner.' + m });
                    };
                });
                installed.push('okhttp3.CertificatePinner.' + m);
            } catch (ignored) {}
        });
    } catch (e) {}

    // -----------------------------------------------------------------------
    // Android Network Security Config pin check (API 24+)
    // -----------------------------------------------------------------------
    try {
        var NSC = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSC.checkPins.overload('java.util.List').implementation = function (chain) {
            send({ type: 'hook_triggered', hook: 'NetworkSecurityTrustManager.checkPins' });
        };
        installed.push('NetworkSecurityTrustManager.checkPins');
    } catch (e) {}

    // -----------------------------------------------------------------------
    // SSLContext.init — replace caller-supplied TrustManager with trust-all
    // -----------------------------------------------------------------------
    try {
        var X509TM  = Java.use('javax.net.ssl.X509TrustManager');
        var SSLCtx  = Java.use('javax.net.ssl.SSLContext');

        var TrustAll = Java.registerClass({
            name: 'com.tlspineval.TrustAll',
            implements: [X509TM],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        SSLCtx.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            send({ type: 'hook_triggered', hook: 'SSLContext.init' });
            this.init(km, [TrustAll.$new()], sr);
        };
        installed.push('SSLContext.init');
    } catch (e) {}

    // -----------------------------------------------------------------------
    // WebViewClient.onReceivedSslError — proceed instead of cancel
    // -----------------------------------------------------------------------
    try {
        var WVC = Java.use('android.webkit.WebViewClient');
        WVC.onReceivedSslError.overload(
            'android.webkit.WebView',
            'android.webkit.SslErrorHandler',
            'android.net.http.SslError'
        ).implementation = function (view, handler, error) {
            send({ type: 'hook_triggered', hook: 'WebViewClient.onReceivedSslError' });
            handler.proceed();
        };
        installed.push('WebViewClient.onReceivedSslError');
    } catch (e) {}

    // -----------------------------------------------------------------------
    // Conscrypt TrustManagerImpl (present on AOSP / most devices)
    // -----------------------------------------------------------------------
    try {
        var CTM = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        CTM.verifyChain.implementation = function (
            untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
        ) {
            send({ type: 'hook_triggered', hook: 'ConscryptTM.verifyChain' });
            return untrustedChain;
        };
        installed.push('ConscryptTM.verifyChain');
    } catch (e) {}

    send({ type: 'ready', hooks_installed: installed });
});
