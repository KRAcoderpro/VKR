'use strict';
/**
 * TLS-PinEval OkHttp CertificatePinner Hook Template
 *
 * Hooks a CertificatePinner or subclass so that check() returns without
 * throwing, bypassing the pin check for all hostnames.
 *
 * Template variables substituted by script_generator.py:
 *   {{CLASS_NAME}}     — fully-qualified class, e.g. "com.app.net.PinnerImpl"
 *   {{METHOD_NAME}}    — method to hook, usually "check"
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
