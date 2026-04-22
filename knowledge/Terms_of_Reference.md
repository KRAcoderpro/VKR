**Terms of Reference**
for the development of an algorithm for assessing the security of Android applications against TLS pinning attacks

**Algorithm Name:**
**TLS-PinEval** — An Algorithm for the Comprehensive Quantitative Assessment of Android Application Security Against TLS Pinning Attacks

### 1. Development Goal
To develop an automated algorithm that enables an **accurate, comprehensive, and quantitative** assessment of Android application security against TLS pinning attacks based on the four criteria defined in Chapter 1.

### 2. Algorithm Objectives
1. Automatically perform static analysis of the APK and identify TLS pinning implementations.
2. Perform dynamic analysis on an emulator/device and verify the actual resistance of pinning to bypass.
3. Calculate a quantitative score (points/percentage) for each of the four criteria.
4. Generate a comprehensive final assessment of the application's security.
5. Generate a clear report for the developer/information security specialist.

### 3. Assessment Criteria (from Chapter 1)
The algorithm must evaluate the application based on the following four criteria:

1. **Correctness of TLS pinning implementation**
2. **Resistance to static bypass**
3. **Resistance to dynamic bypass**
4. **Comprehensive protection** (anti-analysis, runtime protection, native code, etc.)

Each criterion will be assessed on a point scale (0–100 points), with the final score being a weighted average.

### 4. Algorithm Architecture
The algorithm consists of three main modules:

- **Module 1.** Static Analyzer
- **Module 2.** Dynamic Analyzer
- **Module 3.** Score Calculation and Report Generation Module

The modules operate sequentially, with the static analysis results being passed to the dynamic module for test optimization.

### 5. Static Analysis Module
**Input:** APK file
**Output:** JSON report with found patterns

What it checks:
- Presence and contents of `network_security_config.xml` (pin-set, SHA-256, backup-pin, pin-expiry)
- Use of `CertificatePinner` (OkHttp)
- Custom `TrustManager` and `checkServerTrusted` implementation
- `HostnameVerifier`
- Handling of `onReceivedSslError` in WebViewClient
- Presence of obfuscation (ProGuard/R8), native libraries (.so), APK integrity checks (SafetyNet / Play Integrity)
- Hardcoded secrets related to pinning

**Search patterns:**
- Smali / Java / Kotlin code (Jadx / APKTool)
- XML ​​resources
- String constants (pin, certificate, trust, verify, etc.)

### 6. Dynamic Analysis Module
**Input:** APK + static analysis results
**Output:** JSON report of bypass test results

Implementation:
- Launching the app on an Android 11-15 emulator (Genymotion / Android Studio) or on a physical device (if possible).
- Automatic Frida instrumentation.
- Using static analysis results to generate target Frida scripts (hooks only on found classes/methods).
- Test launch:
- Standard bypass scripts (Android-unpinner + custom ones)
- Testing the app's response to interference (Frida detection, debugging, root)
- MITM traffic interception after successful/unsuccessful bypass
- Recording the time and number of bypass attempts

### 7. Complex quantitative assessment calculation module (main part)
Each criterion receives a score from 0 to 100. The final score is a weighted sum.

**Example scoring formula (subject to adjustment):**

- Criterion 1 (Implementation Correctness) — 30%
- Criterion 2 (Static Resilience) — 25%
- Criterion 3 (Dynamic Resilience) — 30%
- Criterion 4 (Comprehensive Protection) — 15%

**Scoring examples:**
- Correctness: +25 for backup PIN, +20 for PIN expiry, +20 for SHA-256, +15 for hostname verification, etc.
- Static Resilience: +40 for strong obfuscation, +30 for native code, +20 for APK integrity verification.
- Dynamic Resilience: +50 for "bypass failure," +30 for Frida detection, +20 for blocking in a non-standard environment.
- Comprehensive protection: additional points for runtime detection, anti-debugging, etc.

**Final scale:**
- 85–100 — High security
- 60–84 — Average security
- 30–59 — Low security
- 0–29 — Critically low security

### 8. Final report
The algorithm should generate a report in the following formats:
- HTML + PDF (with tables and graphs)
- Report structure:
1. Overall score (numeric score + color indicator)
2. Score for each of the 4 criteria (scores + explanations)
3. Pinning implementations found
4. Bypass test results (with Frida logs)
5. Recommendations for improvement
6. Comparison with MobSF (where our algorithm is more accurate)

### 9. Technical requirements
- Implementation language: Python 3.11+
- Libraries: Jadx, APKTool, Frida, mitmproxy, BeautifulSoup, Pandas
- Support for Android 8.0–15
- Ability to work both in the CLI and with a simple web interface (Flask / Streamlit)

### 10. Implementation Stages (Approximate)
1. Development and testing of the static analysis module
2. Development of the dynamic analysis module + Frida integration
3. Creation of the scoring system