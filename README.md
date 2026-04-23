# TLS-PinEval

Quantitative security assessment tool for Android application TLS pinning implementations.

TLS-PinEval statically analyzes an APK and optionally performs Frida-based dynamic bypass testing, then computes a weighted 4-criterion security score and generates an explainable HTML report.

---

## Overview

| Criterion | Weight | What it measures |
|-----------|--------|-----------------|
| C1 — Implementation Correctness | 30% | Correct use of NSC, TrustManager, HostnameVerifier, WebView SSL |
| C2 — Static Bypass Resistance | 25% | Obfuscation, native pinning, integrity checks, hardcoded secrets |
| C3 — Dynamic Bypass Resistance | 30% | Frida generic + targeted bypass results, Frida/root/debug detection |
| C4 — Comprehensive Protection | 15% | Multi-layer defense, custom logic, anti-tampering |

**Score range:** 0–100. Security levels: CRITICAL (0–29) · LOW (30–59) · MEDIUM (60–84) · HIGH (85–100).

---

## Quick Start

### 1. Set up the Python environment

```bash
# Requires Python 3.11+
poetry install

# Verify
poetry run tls-pineval --version
```

### 2. Install external tools

| Tool | Required for | Install guide |
|------|-------------|---------------|
| APKTool | Static analysis (all modes) | [docs/environment_setup.md §2](docs/environment_setup.md#2-apktool) |
| Jadx | Static analysis (Java decompilation) | [docs/environment_setup.md §3](docs/environment_setup.md#3-jadx) |
| ADB | Dynamic analysis | [docs/environment_setup.md §4](docs/environment_setup.md#4-adb-android-debug-bridge) |
| Frida | Dynamic analysis | [docs/environment_setup.md §6](docs/environment_setup.md#6-frida) |

### 3. Connect an Android device

- Android device or emulator (Android 11–14, rooted)
- frida-server running on device, same version as Python package
- See [docs/environment_setup.md](docs/environment_setup.md) for complete setup

### 4. Run a full analysis

```bash
poetry run tls-pineval analyze app.apk -o ./results
```

### 5. Open the report

```
results/
├── static_report.json
├── dynamic_report.json
└── report.html          ← open this in a browser
```

---

## Installation

```bash
# Clone or extract the project
cd d:/VKR_new

# Install dependencies
poetry install

# Install Frida manually (version must match frida-server on device)
# Example for Frida 16.5.9:
poetry run pip install frida==16.5.9 frida-tools
```

---

## CLI Reference

All commands share these global options:

| Option | Default | Description |
|--------|---------|-------------|
| `-o`, `--output-dir PATH` | `./results` | Directory for all output files |
| `-v`, `--verbose` | off | Enable debug logging to stderr |
| `-c`, `--config PATH` | built-in defaults | YAML config override file |

---

### `analyze` — Full pipeline

Runs static analysis → dynamic bypass testing → scoring → HTML report.

```bash
poetry run tls-pineval analyze app.apk
poetry run tls-pineval analyze app.apk -o ./results
poetry run tls-pineval analyze app.apk --skip-dynamic        # static + score only
poetry run tls-pineval analyze app.apk --skip-jadx           # faster, Smali-only
poetry run tls-pineval -v analyze app.apk                    # with debug output
```

**Options:**

| Option | Description |
|--------|-------------|
| `--skip-dynamic` | Skip dynamic analysis (no device required) |
| `--skip-jadx` | Skip Jadx decompilation (faster, Smali-only) |

**Expected output (stdout):**

```
--------------------------------------------------------
 TLS-PinEval | Security Assessment
--------------------------------------------------------
 App:     com.example.app
 Package: com.example.app | v2.1.0 | SDK 33
--------------------------------------------------------
 Score:   42.3 / 100  [########............]   LOW
--------------------------------------------------------
  C1  Implementation Correctness            35/100  30%
  C2  Static Bypass Resistance             60/100  25%
  C3  Dynamic Bypass Resistance            28/100  30%
  C4  Comprehensive Protection             55/100  15%
--------------------------------------------------------
 Recommendations (3):
   1. Add a backup pin to your NSC configuration
   2. Enable code obfuscation (ProGuard/R8)
   3. … and 2 more (see report)
--------------------------------------------------------
 Report:  results/report.html
--------------------------------------------------------
```

If dynamic analysis fails (device not available), the pipeline continues with
static-only scoring. C3 is excluded and weights are normalized automatically.

---

### `static` — Static analysis only

No device or Frida required.

```bash
poetry run tls-pineval static app.apk
poetry run tls-pineval static app.apk -o ./results
poetry run tls-pineval static app.apk --skip-jadx
```

**Output files:**
- `results/static_report.json`

**Expected stdout:**

```
--------------------------------------------------------
 TLS-PinEval  ·  Static Analysis
--------------------------------------------------------
 App:     com.example.app
 Package: com.example.app
 Findings:         12
 Pinning impls:    2
 Hookable targets: 3
 Obfuscation:      BASIC
--------------------------------------------------------
 Report:  results/static_report.json
--------------------------------------------------------
```

---

### `dynamic` — Dynamic analysis only

Requires a prior `static` run output.

```bash
poetry run tls-pineval dynamic app.apk \
    --static-report ./results/static_report.json
```

**Options:**

| Option | Required | Description |
|--------|----------|-------------|
| `--static-report PATH` | Yes | Path to `static_report.json` from a prior `static` run |

**Output files:**
- `results/dynamic_report.json`

**Expected stdout:**

```
--------------------------------------------------------
 TLS-PinEval  ·  Dynamic Analysis
--------------------------------------------------------
 App:             com.example.app
 Device:          emulator-5554
 Android:         13
 Frida:           16.5.9
 Bypass attempts: 3
 Bypass success:  NO
 Frida detected:  NO
--------------------------------------------------------
 Report:  results/dynamic_report.json
--------------------------------------------------------
```

---

### `score` — Score from existing reports

Re-score and regenerate the HTML report from previously saved JSON reports.

```bash
# Static-only scoring
poetry run tls-pineval -o ./results score \
    --static ./results/static_report.json

# Full scoring (static + dynamic)
poetry run tls-pineval -o ./results score \
    --static  ./results/static_report.json \
    --dynamic ./results/dynamic_report.json

# Custom output directory
poetry run tls-pineval -o ./new_results score \
    --static ./results/static_report.json \
    --dynamic ./results/dynamic_report.json
```

**Options:**

| Option | Required | Description |
|--------|----------|-------------|
| `--static PATH` | Yes | Path to `static_report.json` |
| `--dynamic PATH` | No | Path to `dynamic_report.json` (omit for static-only scoring) |

**Output files:**
- `<output-dir>/report.html`

---

## Configuration

Default values are in [config/default.yaml](config/default.yaml).
Override any value with a custom YAML file:

```bash
poetry run tls-pineval -c my_config.yaml analyze app.apk
```

**Configurable parameters:**

```yaml
scoring:
  confidence_factors:
    HIGH:   1.0    # full points
    MEDIUM: 0.7    # 30% penalty
    LOW:    0.4    # 60% penalty
  weights:
    c1: 0.30
    c2: 0.25
    c3: 0.30
    c4: 0.15

analysis:
  bypass_timeout: 15      # seconds per bypass attempt
  detection_timeout: 10   # seconds for detection tests
  skip_jadx: false
  skip_dynamic: false
```

---

## Output Files

| File | Description |
|------|-------------|
| `static_report.json` | Full static analysis output (AppInfo, findings, hookable targets, protection profile) |
| `dynamic_report.json` | Full dynamic analysis output (bypass attempts, verification results, detection results) |
| `report.html` | Self-contained HTML report (open in any browser) |

---

## Validation / Smoke Tests

### Static-only smoke test (no device needed)

```bash
poetry run tls-pineval static app.apk -o ./smoke_results
```

**Success indicators:**
- Exit code 0
- `smoke_results/static_report.json` created and valid JSON
- Stdout shows app name, package name, findings count
- No `ToolError` about apktool or jadx

**Common failure:**
- `ToolError: 'apktool' not found on PATH` → install APKTool, restart terminal
- `ToolError: 'jadx' not found on PATH` → install Jadx or use `--skip-jadx`

---

### Full pipeline smoke test (device required)

```bash
# Start frida-server on device first (see docs/environment_setup.md)
poetry run tls-pineval analyze app.apk -o ./smoke_results -v
```

**Success indicators:**
- Exit code 0
- `smoke_results/static_report.json`, `dynamic_report.json`, `report.html` all created
- Stdout shows final score and security level
- Dynamic section shows "Bypass success: YES/NO" (not an error)

**Common failures:**

| Error message | Fix |
|--------------|-----|
| `No ADB device found in 'device' state` | Start emulator or connect device; run `adb devices` |
| `Frida cannot connect to device` | Start frida-server: `adb shell "/data/local/tmp/frida-server &"` |
| `frida-server not responding` | Version mismatch — reinstall Python frida package to match server |
| `APK installation failed` | Check device has enough storage; try `adb install -r app.apk` manually |

---

### Score-only smoke test (no APK, no device needed)

The test suite includes fixture reports. To validate scoring and reporting:

```bash
poetry run tls-pineval -o ./smoke_results score \
    --static  tests/fixtures/example_static_report.json \
    --dynamic tests/fixtures/example_dynamic_report.json
```

**Success indicators:**
- Exit code 0
- `smoke_results/report.html` created
- Open `report.html` in browser — all sections populated, no broken layout

---

### Unit tests

```bash
# Run all unit tests
poetry run pytest tests/ -v

# Run only scoring tests (no device, no APK needed)
poetry run pytest tests/test_scoring.py -v

# Run model serialization tests
poetry run pytest tests/test_models_serialization.py -v
```

---

## Project Structure

```
tls_pineval/
├── cli.py                 # Click commands (analyze, static, dynamic, score)
├── orchestrator.py        # Pipeline coordination
├── config.py              # YAML config loader
├── tools.py               # Subprocess wrappers: apktool, jadx, adb
├── models/                # Pydantic v2 data models
├── static/                # Static analysis modules
├── dynamic/               # Frida-based dynamic analysis
│   └── scripts/           # Frida JS scripts
├── scoring/               # Scoring engine + HTML reporter
└── templates/             # Jinja2 HTML template + CSS

config/default.yaml        # Default configuration
docs/environment_setup.md  # Full setup guide
tests/                     # Unit tests + fixture reports
```

---

## Full Environment Setup

See [docs/environment_setup.md](docs/environment_setup.md) for:
- APKTool and Jadx installation
- ADB and Android device setup
- Frida version matching and frida-server deployment
- Pre-flight checklist
- Troubleshooting
