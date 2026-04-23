'use strict';
/**
 * TLS-PinEval Detection Check Script
 *
 * Attaches to the app without modifying any TLS code.  Monitors for
 * self-defense behavior:
 *   - Root detection (su / which commands via Runtime.exec)
 *   - Debugger detection (Debug.isDebuggerConnected)
 *   - Frida / process enumeration (ActivityManager.getRunningAppProcesses)
 *
 * Sends Frida messages:
 *   { type: 'detection_script_ready' }
 *   { type: 'root_check',    cmd: '<command>' }
 *   { type: 'debugger_check' }
 *   { type: 'process_enum',  note: 'possible_frida_detection' }
 */

Java.perform(function () {

    // Root detection via Runtime.exec
    try {
        var Runtime = Java.use('java.lang.Runtime');
        var origExec = Runtime.exec.overload('java.lang.String');
        origExec.implementation = function (cmd) {
            if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 ||
                        cmd.indexOf('busybox') !== -1)) {
                send({ type: 'root_check', cmd: cmd });
            }
            return origExec.call(this, cmd);
        };
    } catch (e) {}

    // Root detection via ProcessBuilder
    try {
        var PB = Java.use('java.lang.ProcessBuilder');
        PB.start.implementation = function () {
            var cmds = this.command().toArray();
            for (var i = 0; i < cmds.length; i++) {
                var c = String(cmds[i]);
                if (c === 'su' || c === 'which' || c === 'busybox') {
                    send({ type: 'root_check', cmd: c });
                    break;
                }
            }
            return this.start();
        };
    } catch (e) {}

    // Debugger detection
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            send({ type: 'debugger_check' });
            return this.isDebuggerConnected();
        };
    } catch (e) {}

    // Process enumeration (common Frida detection technique)
    try {
        var AM = Java.use('android.app.ActivityManager');
        var origProcs = AM.getRunningAppProcesses;
        if (origProcs) {
            origProcs.implementation = function () {
                send({ type: 'process_enum', note: 'possible_frida_detection' });
                return this.getRunningAppProcesses();
            };
        }
    } catch (e) {}

    send({ type: 'detection_script_ready' });
});
