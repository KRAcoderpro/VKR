# TLS-PinEval — Environment Setup Guide

This guide prepares everything TLS-PinEval needs to run.
Static analysis requires only Python and two command-line tools (APKTool + Jadx).
Dynamic analysis additionally requires an Android device/emulator with Frida.

---

## Contents

1. [Python Environment](#1-python-environment)
2. [APKTool](#2-apktool)
3. [Jadx](#3-jadx)
4. [ADB (Android Debug Bridge)](#4-adb-android-debug-bridge)
5. [Android Device or Emulator](#5-android-device-or-emulator)
6. [Frida](#6-frida)
7. [mitmproxy (Optional)](#7-mitmproxy-optional)
8. [Pre-flight Checklist](#8-pre-flight-checklist)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Python Environment

**Requirement:** Python 3.11 or newer.

```bash
# Verify Python version
python --version
# Expected: Python 3.11.x or 3.12.x
```

### Install Poetry (if not already installed)

```bash
# Windows (PowerShell)
(Invoke-WebRequest -Uri https://install.python-poetry.org -UseBasicParsing).Content | python -

# Linux / macOS
curl -sSL https://install.python-poetry.org | python3 -
```

Verify:

```bash
poetry --version
# Expected: Poetry (version 1.7.x or newer)
```

### Install project dependencies

```bash
# In the project root (d:\VKR_new)
poetry install
```

This creates a managed virtual environment and installs all required packages
(`pydantic`, `jinja2`, `click`, `PyYAML`).

### Verify installation

```bash
poetry run tls-pineval --version
# Expected: tls-pineval, version 0.1.0
```

> **Note:** All subsequent `tls-pineval` commands assume the Poetry environment
> is active (`poetry shell`) or that you prefix commands with `poetry run`.

---

## 2. APKTool

APKTool decodes APK resources and AndroidManifest.xml.
TLS-PinEval calls it as `apktool` — it must be on your PATH.

### Install (Windows)

1. Download the latest `apktool.jar` from https://apktool.org/
2. Download the wrapper script `apktool.bat` from the same page.
3. Place both files in a directory that is on your PATH (e.g. `C:\tools\`).
4. Verify:

```cmd
apktool --version
# Expected: 2.9.x or newer
```

### Install (Linux / macOS)

```bash
# Debian / Ubuntu
sudo apt install apktool

# macOS (Homebrew)
brew install apktool
```

### Verify

```bash
apktool --version
```

---

## 3. Jadx

Jadx decompiles APK bytecode to Java/Kotlin source for pattern matching.
TLS-PinEval calls it as `jadx` — it must be on your PATH.

### Install

1. Download the latest `jadx-<version>-no-jvm.zip` (or the JVM bundle if you
   don't have Java) from https://github.com/skylot/jadx/releases
2. Extract to a permanent directory (e.g. `C:\tools\jadx\`).
3. Add the `bin\` sub-directory to your PATH:
   - Windows: `C:\tools\jadx\bin`
   - Linux/macOS: `/opt/jadx/bin`

### Verify

```bash
jadx --version
# Expected: jadx-1.5.x or newer
```

> **Tip:** If Jadx is slow or memory-heavy, pass `--skip-jadx` to any
> TLS-PinEval command to run Smali-only static analysis instead.

---

## 4. ADB (Android Debug Bridge)

ADB communicates with the connected Android device.

### Install

ADB is included in **Android Platform Tools**.

- Download from: https://developer.android.com/tools/releases/platform-tools
- Extract and add the directory to your PATH.

### Verify

```bash
adb version
# Expected: Android Debug Bridge version 1.0.41 (or newer)
```

---

## 5. Android Device or Emulator

TLS-PinEval does **not** manage device lifecycle. You provide the device.

### Supported configurations

| Configuration | Android | Root Required | Notes |
|--------------|---------|--------------|-------|
| Android Emulator (AVD) | 11–14, x86_64 | Yes (userdebug/eng image) | Recommended for testing |
| Genymotion | 11–14 | Yes (built-in) | Simpler root setup |
| Physical device | 11–14 | Yes | Use Magisk for root |

### Option A — Android Emulator (AVD)

1. Install **Android Studio** from https://developer.android.com/studio
2. Open **Virtual Device Manager** → **Create Device**
3. Pick a phone profile, then select a system image:
   - Use **x86_64** images for speed
   - Choose **Android 11–14**
   - **Do not use Google Play images** — they prevent root access
   - Use **Google APIs** or plain AOSP images (marked `(Google APIs)` not `(Google Play)`)
4. Start the emulator.
5. Verify the device appears:

```bash
adb devices
# Expected:
# List of devices attached
# emulator-5554   device
```

### Option B — Physical Device

1. Enable **Developer Options**:
   - Go to **Settings → About phone**
   - Tap **Build number** 7 times
2. Enable **USB Debugging** in **Developer Options**.
3. Connect via USB and authorize the connection when prompted.
4. Root the device using **Magisk** (https://topjohnwu.github.io/Magisk/).
5. Verify:

```bash
adb devices
# Expected:
# List of devices attached
# R5CT103XXXX   device
```

### Root verification

```bash
adb shell id
# Expected to contain: uid=0(root) — or run as root via "adb shell su -c id"
```

---

## 6. Frida

Frida is a dynamic instrumentation toolkit. It has two parts:
- **Python package** (runs on your computer, in the Poetry environment)
- **frida-server** (runs on the Android device)

**Both must be the exact same version.**

### Step 1 — Determine the required version

Check the version available in PyPI:

```bash
pip index versions frida 2>/dev/null | head -1
# Or simply pick the latest stable: e.g. 16.5.9
```

Pick a version number (example below uses `16.5.9`).

### Step 2 — Install the Python package

```bash
# Inside the project (Poetry environment)
poetry run pip install frida==16.5.9 frida-tools==12.5.3
# frida-tools version may vary; check https://pypi.org/project/frida-tools/
```

> Frida is intentionally not in `pyproject.toml` because its version must
> match frida-server exactly. Installing it separately prevents accidental
> version drift.

### Step 3 — Download frida-server

1. Go to: https://github.com/frida/frida/releases
2. Find the release matching your Frida Python version.
3. Download the server binary matching your device architecture:
   - **Emulator (x86_64):** `frida-server-<version>-android-x86_64.xz`
   - **Emulator (x86):** `frida-server-<version>-android-x86.xz`
   - **Physical ARM64 device:** `frida-server-<version>-android-arm64.xz`
   - **Physical ARM device:** `frida-server-<version>-android-arm.xz`

4. Extract the `.xz` archive to get the binary.

### Step 4 — Push frida-server to the device

```bash
# Push the extracted binary
adb push frida-server-16.5.9-android-x86_64 /data/local/tmp/frida-server

# Set permissions
adb shell chmod 755 /data/local/tmp/frida-server
```

### Step 5 — Start frida-server

Open a terminal and keep this running in the background while TLS-PinEval runs:

```bash
adb shell "su -c '/data/local/tmp/frida-server &'"
```

For emulators that are already root:

```bash
adb shell "/data/local/tmp/frida-server &"
```

### Step 6 — Verify Frida connectivity

```bash
poetry run frida-ps -U
# Expected: list of running processes on the device
```

### Version compatibility check

```bash
# Python package version
poetry run python -c "import frida; print(frida.__version__)"

# frida-server version (on device)
adb shell "/data/local/tmp/frida-server --version"

# Both must output the same version number.
```

---

## 7. mitmproxy (Optional)

mitmproxy is used for MITM traffic interception. In V1, the MITM check is
**skipped** by default — the bypass verifier uses logcat instead.

You only need mitmproxy if you want to manually verify that intercepted
traffic flows through a proxy after a bypass.

```bash
pip install mitmproxy

# Start proxy
mitmweb --listen-port 8080

# Configure proxy on device
adb shell settings put global http_proxy <YOUR_HOST_IP>:8080
```

To disable the proxy after testing:

```bash
adb shell settings put global http_proxy :0
```

---

## 8. Pre-flight Checklist

Run through this checklist before every TLS-PinEval session:

```
[ ] Python 3.11+ is installed
[ ] Poetry environment installed: poetry install
[ ] APKTool is on PATH: apktool --version
[ ] Jadx is on PATH: jadx --version
[ ] ADB is on PATH: adb version
[ ] Device/emulator appears in: adb devices  (status must be "device")
[ ] frida-server is running on device: adb shell ps | grep frida-server
[ ] Frida Python package installed: poetry run python -c "import frida"
[ ] Frida versions match: compare Python and server outputs above
[ ] APK file is present and accessible
[ ] Output directory is writable (default: ./results)
```

---

## 9. Troubleshooting

### `apktool: command not found`
Add the APKTool directory to your system PATH. On Windows, restart the terminal after editing PATH.

### `jadx: command not found`
Add `<jadx-dir>/bin` to PATH. Verify with `where jadx` (Windows) or `which jadx` (Linux/macOS).

### `adb devices` shows `unauthorized`
The device is waiting for you to accept the USB debugging prompt. Check the device screen, tap "Allow", then re-run.

### `adb devices` shows `offline`
Try: `adb kill-server && adb start-server`, then reconnect the device.

### `No ADB device found in 'device' state`
- Emulator not started, or still booting — wait until the home screen appears.
- Physical device USB debugging not enabled.
- USB cable is charge-only — use a data-capable cable.

### `Frida cannot connect to device`
- frida-server is not running. Start it: `adb shell "/data/local/tmp/frida-server &"`
- frida-server is not executable. Set permissions: `adb shell chmod 755 /data/local/tmp/frida-server`

### `frida-server not responding — check version compatibility`
The Python package version and frida-server binary version do not match.
Run both version checks (Step 6) and reinstall the Python package or download
a matching server binary.

### `ToolError: 'apktool' not found on PATH`
Same as `apktool: command not found` — the tool is not on PATH when the
Poetry-managed Python process runs. On Windows, ensure PATH is set at the
system level, not just in the current terminal session.

### Static analysis produces 0 findings
- The APK may be heavily obfuscated.
- Try with `--skip-jadx` removed to ensure Java source is also scanned.
- Check the `static_report.json` — the `protection` field shows the detected obfuscation level.

### HTML report does not open correctly
Open the `.html` file in a browser directly (double-click). The report is
self-contained (CSS embedded) — no server needed.
