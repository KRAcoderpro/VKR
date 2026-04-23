'use strict';
/**
 * TLS-PinEval WebViewClient SSL Error Hook Template
 *
 * Hooks onReceivedSslError() to call handler.proceed() instead of
 * handler.cancel(), bypassing WebView SSL certificate errors.
 *
 * Template variables substituted by script_generator.py:
 *   {{CLASS_NAME}}     — WebViewClient subclass, e.g. "com.app.AppWebViewClient"
 *   {{METHOD_NAME}}    — "onReceivedSslError"
 *   {{OVERLOADS_CODE}} — generated hook bodies
 */

Java.perform(function () {
    try {
        var TargetClass = Java.use('{{CLASS_NAME}}');
        {{OVERLOADS_CODE}}
        send({ type: 'ready', class: '{{CLASS_NAME}}', method: '{{METHOD_NAME}}' });
    } catch (e) {
        send({ type: 'error', message: e.toString() });
    }
});
