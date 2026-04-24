'use strict';
/**
 * TLS-PinEval Detection Check Script
 *
 * Attaches to the app without modifying any TLS code.  Monitors for
 * self-defense behaviour across four detection surfaces:
 *
 *   1. exec-based root checks  — Runtime.exec / ProcessBuilder.start
 *   2. file-based root checks  — File.exists / File.canExecute on su/magisk paths
 *   3. package-based root checks — PackageManager.getPackageInfo for known root apps
 *   4. debugger detection      — Debug.isDebuggerConnected
 *   5. Frida / process enum    — ActivityManager.getRunningAppProcesses
 *
 * Sends Frida messages:
 *   { type: 'detection_script_ready' }
 *   { type: 'root_check',         cmd: '<command>' }           — exec-based
 *   { type: 'file_root_check',    path: '<path>', method: 'exists'|'canExecute' }
 *   { type: 'package_root_check', package: '<pkg>' }
 *   { type: 'debugger_check' }
 *   { type: 'process_enum',       note: 'possible_frida_detection' }
 */

Java.perform(function () {

    // -----------------------------------------------------------------------
    // 1. exec-based root detection — Runtime.exec / ProcessBuilder
    // -----------------------------------------------------------------------
    try {
        var Runtime = Java.use('java.lang.Runtime');
        Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
            if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1 ||
                        cmd.indexOf('busybox') !== -1)) {
                send({ type: 'root_check', cmd: cmd });
            }
            return this.exec(cmd);
        };
    } catch (e) {}

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

    // -----------------------------------------------------------------------
    // 2. File-based root detection — File.exists() / File.canExecute()
    //
    // Most root-detection libraries (RootBeer, manual checks) use File.exists()
    // rather than exec.  We hook it with an O(1) lookup table so performance
    // impact on the hundreds of legitimate exists() calls is minimal.
    // -----------------------------------------------------------------------
    var ROOT_PATHS = {};
    [
        '/system/app/Superuser.apk',
        '/system/app/SuperSU.apk',
        '/system/xbin/su',
        '/system/bin/su',
        '/data/local/tmp/su',
        '/sbin/su',
        '/su/bin/su',
        '/system/xbin/busybox',
        '/system/bin/busybox',
        '/system/xbin/daemonsu',
        '/data/adb/magisk',
        '/sbin/.magisk',
        '/data/local/tmp/.magisk',
    ].forEach(function (p) { ROOT_PATHS[p] = true; });

    try {
        var File = Java.use('java.io.File');

        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (ROOT_PATHS[path]) {
                send({ type: 'file_root_check', path: path, method: 'exists' });
            }
            return this.exists();
        };

        File.canExecute.implementation = function () {
            var path = this.getAbsolutePath();
            if (ROOT_PATHS[path]) {
                send({ type: 'file_root_check', path: path, method: 'canExecute' });
            }
            return this.canExecute();
        };
    } catch (e) {}

    // -----------------------------------------------------------------------
    // 3. Package-based root detection — PackageManager.getPackageInfo
    //
    // Apps check for Magisk, SuperSU etc. by querying the package manager.
    // A NameNotFoundException means the package is absent; but the attempt
    // itself reveals intent to detect root.
    // -----------------------------------------------------------------------
    var ROOT_PACKAGES = {};
    [
        'com.topjohnwu.magisk',
        'eu.chainfire.supersu',
        'com.noshufou.android.su',
        'com.noshufou.android.su.elite',
        'com.koushikdutta.superuser',
        'com.zachspong.temprootremovejb',
        'com.ramdroid.appquarantine',
        'com.scottyab.rootbeer',
        'com.formyhm.hideroot',
    ].forEach(function (p) { ROOT_PACKAGES[p] = true; });

    try {
        var APM = Java.use('android.app.ApplicationPackageManager');
        APM.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
            if (ROOT_PACKAGES[pkg]) {
                send({ type: 'package_root_check', package: pkg });
            }
            return this.getPackageInfo(pkg, flags);
        };
    } catch (e) {}

    // -----------------------------------------------------------------------
    // 4. Debugger detection
    // -----------------------------------------------------------------------
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function () {
            send({ type: 'debugger_check' });
            return this.isDebuggerConnected();
        };
    } catch (e) {}

    // -----------------------------------------------------------------------
    // 5. Process enumeration (common Frida detection technique)
    // -----------------------------------------------------------------------
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
