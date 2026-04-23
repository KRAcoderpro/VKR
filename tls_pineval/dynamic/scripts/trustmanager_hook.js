'use strict';
/**
 * TLS-PinEval TrustManager Hook Template
 *
 * Hooks a specific X509TrustManager implementation so that
 * checkServerTrusted() returns without throwing, bypassing the pin check.
 *
 * Template variables substituted by script_generator.py:
 *   {{CLASS_NAME}}     — fully-qualified Java class, e.g. "com.app.PinTrustManager"
 *   {{METHOD_NAME}}    — method to hook, usually "checkServerTrusted"
 *   {{OVERLOADS_CODE}} — generated hook bodies for each overload
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
