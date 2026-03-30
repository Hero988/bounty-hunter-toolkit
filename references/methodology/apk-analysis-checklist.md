# APK Analysis Checklist for Bug Bounty

Practical, actionable checklist. No theory -- just steps that find bugs.

---

## Quick Start

### 1. Obtain the APK

```bash
# From Google Play (requires auth token)
gplaydl -d com.target.app -o target.apk

# From APKPure (no auth needed)
curl -o target.apk "https://d.apkpure.com/b/APK/com.target.app"

# apkeep (bulk download, handles split APKs)
apkeep -a com.target.app .

# From device via ADB
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk target.apk
```

Always grab multiple versions (current + older) -- older versions often have weaker security.

### 2. Decompile

```bash
# Java source (readable, best for analysis)
jadx -d target-src/ target.apk

# Smali + resources (preserves AndroidManifest.xml accurately)
apktool d target.apk -o target-smali/

# Run both -- jadx for reading code, apktool for manifest and resources
```

### 3. What to Look for First (highest ROI)

1. Hardcoded secrets in source (grep patterns below)
2. AndroidManifest.xml exported components
3. API endpoint URLs and base URLs
4. Network security config (cleartext, pinning)
5. WebView with JS interface bridges

---

## Secret Scanning Patterns

Run these from the decompiled source root. Every match is a potential finding.

```bash
# ============================================================
# API Keys & Tokens
# ============================================================

# Generic secrets -- broad net, review manually
grep -rn "Authorization\|Bearer\|api_key\|apiKey\|secret\|password" .

# Google API keys (starts with AIza, 35 chars after)
grep -rn "AIza[0-9A-Za-z_-]\{35\}" .

# Firebase Cloud Messaging server keys
grep -rn "AAAA[A-Za-z0-9_-]\{7\}:[A-Za-z0-9_-]\{140\}" .

# Stripe live keys (sk_live = secret, pk_live = publishable)
grep -rn "sk_live_\|pk_live_" .

# Sentry DSNs -- leak internal stack traces and error data
grep -rn "@sentry\|sentry\.io\|dsn.*sentry" .

# AWS keys
grep -rn "AKIA[0-9A-Z]\{16\}" .

# Slack tokens
grep -rn "xoxb-\|xoxp-\|xoxs-" .

# ============================================================
# Debug / Backdoor Indicators
# ============================================================

# Backdoor and god-mode flags
grep -rn "backdoor\|godmode\|god_mode\|debug_menu\|developer_menu" .

# Debug/test mode toggles
grep -rn "isDebug\|debugMode\|testMode\|staging\|qa\.\|dev\." .

# ============================================================
# Internal URLs
# ============================================================

# Internal/staging/dev subdomains that may lack WAF or auth
grep -rn "\.int\b\|\.internal\|\.local\|\.test\b\|-int\.\|-dev\.\|-qa\.\|-staging\." .

# ============================================================
# Exported Components
# ============================================================

# Components accessible to any app on the device
grep "exported=\"true\"" AndroidManifest.xml

# ============================================================
# WebView JavaScript Interfaces
# ============================================================

# JS bridge methods -- XSS in WebView can call these native methods
grep -rn "@JavascriptInterface" .

# ============================================================
# Network Security
# ============================================================

# Cleartext traffic allowed, certificate pinning config
grep -rn "cleartextTrafficPermitted\|certificatePinner\|CertificatePinner" .
```

**Tip:** Pipe any grep through `| grep -v "\.smali:"` to filter out smali noise if you decompiled with both jadx and apktool in the same tree.

---

## Endpoint Extraction

### Find Retrofit Interfaces

```bash
# Retrofit annotation patterns
grep -rn "@GET\|@POST\|@PUT\|@DELETE\|@PATCH\|@HEAD" .

# Typical pattern in decompiled code:
#   @GET("api/v1/users/{id}")
#   Call<UserResponse> getUser(@Path("id") String id);
```

Collect every annotated path. These are your target endpoints.

### Find OkHttp Base URLs

```bash
# Base URL assignments
grep -rn "baseUrl\|BASE_URL\|base_url\|ApiUrl\|API_URL" .

# Retrofit builder pattern
grep -rn "Retrofit.Builder\|new Retrofit" .
```

### Reconstruct Full API List

1. Extract all base URLs found above
2. Extract all Retrofit path annotations
3. Combine: `base_url + endpoint_path`
4. Check for versioning patterns (v1, v2, v3)
5. Look for path parameters (`{id}`, `{userId}`) and test with real values
6. Feed the full list into Burp or your proxy for further testing

```bash
# Quick one-liner to extract URL-like strings
grep -rnoE "https?://[a-zA-Z0-9./?=_-]*" . | sort -u
```

---

## Token Validation

This is where the big bounties live. For every hardcoded token or key you find:

### Step-by-Step Validation

1. **Test against discovered API endpoints**
   - Use the token as Bearer auth against every endpoint you extracted
   - Try both GET and POST methods
   - `curl -H "Authorization: Bearer <token>" https://api.target.com/v1/users`

2. **Replicate mobile app context**
   - Set User-Agent to match the app (find it in the decompiled source)
   - Include app-specific headers: `X-App-Version`, `X-Device-Id`, `X-Platform: android`
   - Some APIs reject requests without these headers

3. **Check WAF/geo-restriction bypass**
   - Some mobile API tokens bypass WAF rules that block browser traffic
   - Test from different regions if the app is geo-restricted
   - The token itself may grant access that normal auth flows do not

4. **Document data access scope**
   - What data does the token return? PII, internal configs, admin panels?
   - Can you access other users' data with the token?
   - Does it expose endpoints not visible in the public API docs?

5. **Determine token permissions**
   - Read-only vs read-write: try creating/modifying resources
   - Admin vs user scope: try admin-only endpoints
   - Rate limits: are they enforced on this token?

6. **Check token lifecycle**
   - Is the token still active? Test a simple GET
   - Does it rotate between app versions? Compare old vs new APKs
   - Is it a long-lived service key or a short-lived session token?

---

## AndroidManifest.xml Checklist

Open `AndroidManifest.xml` (use the apktool-decompiled version for accuracy).

### Exported Components

```bash
# Activities -- can be launched by any app
grep -A2 "exported=\"true\"" AndroidManifest.xml | grep "activity"

# Services -- can be bound/started by any app
grep -A2 "exported=\"true\"" AndroidManifest.xml | grep "service"

# Broadcast receivers -- can receive broadcasts from any app
grep -A2 "exported=\"true\"" AndroidManifest.xml | grep "receiver"

# Content providers -- can be queried by any app
grep -A2 "exported=\"true\"" AndroidManifest.xml | grep "provider"
```

Test each exported component with `adb`:
```bash
adb shell am start -n com.target.app/.ExportedActivity
adb shell am startservice -n com.target.app/.ExportedService
adb shell content query --uri content://com.target.app.provider/users
```

### Deep Link Handlers

```bash
grep -B5 -A5 "android:scheme\|android:host\|android:pathPrefix" AndroidManifest.xml
```

Test deep links for open redirect or auth bypass:
```bash
adb shell am start -a android.intent.action.VIEW -d "targetapp://callback?url=https://evil.com"
```

### Dangerous Permissions

Look for: `CAMERA`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `READ_SMS`, `RECORD_AUDIO`, `READ_CALL_LOG`. Cross-reference with what the app actually needs.

### Security Flags

```bash
# Backup allowed -- data extractable via adb backup
grep "allowBackup=\"true\"" AndroidManifest.xml

# Debuggable -- attach debugger, bypass checks
grep "debuggable=\"true\"" AndroidManifest.xml

# Network security config reference
grep "networkSecurityConfig" AndroidManifest.xml
```

---

## Network Security Config

Located at `res/xml/network_security_config.xml` (apktool output).

### What to Check

```xml
<!-- Cleartext (HTTP) traffic allowed globally -->
<base-config cleartextTrafficPermitted="true" />

<!-- Cleartext allowed for specific domains -->
<domain-config cleartextTrafficPermitted="true">
    <domain>api.target.com</domain>
</domain-config>

<!-- Custom trust anchors -- may trust user-installed CAs -->
<trust-anchors>
    <certificates src="user" />
</trust-anchors>
```

- `cleartextTrafficPermitted="true"` = MitM possible on that domain
- User trust anchors = easier to proxy with Burp (no Frida/objection needed)
- No pinning config at all = default Android trust store only

---

## Common High-Value Findings

| Finding | Impact | Typical Severity |
|---|---|---|
| Hardcoded API token with data access | Unauthorized access to user data or internal systems | High - Critical |
| Debug/staging endpoints in production | Info disclosure, potential RCE via debug features | Medium - Critical |
| Exported activity bypassing login | Authentication bypass | High |
| @JavascriptInterface in WebView loading external URLs | XSS escalates to native code execution | High - Critical |
| Cleartext traffic on auth endpoints | Credential theft via MitM | Medium - High |
| Sentry/crash reporter DSN exposed | Internal stack traces, source paths, environment variables | Medium |
| Firebase Cloud Messaging server key | Push notifications to all app users | High |
| allowBackup="true" with sensitive local data | Data extraction from device | Low - Medium |
| Stripe secret key (sk_live_) | Direct financial access | Critical |

---

## Report Snippets

Copy, adapt, and use these for your submissions.

### Hardcoded API Key with Data Access

> **Title:** Hardcoded [SERVICE] API Key in Android APK Exposes [DATA TYPE]
>
> **Impact:** The Android application (version X.Y.Z) contains a hardcoded API key for [SERVICE] embedded in [CLASS/FILE]. This key provides unauthenticated access to [DESCRIBE DATA: user PII, internal configurations, etc.]. Any user can extract this key by decompiling the publicly available APK. The key grants [read/read-write] access to [N records / sensitive endpoints]. An attacker requires no authentication or special privileges to exploit this -- only a copy of the APK from the Play Store.

### Exported Activity Auth Bypass

> **Title:** Exported Activity [ACTIVITY NAME] Bypasses Authentication
>
> **Impact:** The activity `com.target.app.[ActivityName]` is exported in AndroidManifest.xml without permission restrictions. Any application on the same device can launch this activity directly via an intent, bypassing the login flow entirely. This grants access to [DESCRIBE WHAT THE ACTIVITY SHOWS/DOES]. Exploitation requires only a malicious app installed on the same device -- no user interaction beyond installing the attacker's app.

### JavaScript Interface Bridge Vulnerability

> **Title:** WebView JavaScript Interface Exposes Native Methods via [INTERFACE NAME]
>
> **Impact:** The application registers a JavaScript interface (`@JavascriptInterface`) on a WebView that loads content from [URL/source]. If an attacker can inject JavaScript into this WebView (via XSS on the loaded domain, MitM if cleartext, or deep link manipulation), they can invoke native Android methods including [LIST METHODS]. This could allow [file access, token theft, arbitrary intent launching, etc.] on the victim's device.

### Cleartext Traffic on Sensitive Endpoints

> **Title:** Cleartext HTTP Traffic Enabled for [DOMAIN]
>
> **Impact:** The network security configuration permits unencrypted HTTP traffic to `[DOMAIN]`, which handles [authentication / user data / payment info]. An attacker on the same network (public Wi-Fi, compromised router) can intercept and modify this traffic in real time. Credentials and session tokens transmitted over this connection are exposed to passive eavesdropping.

### Sentry DSN Exposure

> **Title:** Sentry DSN Hardcoded in APK Leaks Internal Error Data
>
> **Impact:** The Sentry DSN `[DSN URL]` is embedded in the application source. Using this DSN, an attacker can query the Sentry API to retrieve crash reports containing internal stack traces, file paths, server environment variables, and potentially user data included in error context. This provides an attacker with detailed knowledge of the application's internal architecture, dependency versions, and server-side file structure, significantly lowering the barrier for further attacks.

---

## Flutter App Analysis

Flutter apps compile Dart code into native binaries (`libapp.so`), making traditional decompilation harder. The business logic is NOT in the Java/Kotlin DEX files.

### Identification
- Check for `io.flutter` in decompiled Java imports
- Look for `assets/flutter_assets/` in the APK
- Check for `libflutter.so` and `libapp.so` in `lib/` directory
- `MethodChannel` usage indicates Flutter-to-native communication

### Split APKs (AAB-Based)
Modern Flutter apps distributed via App Bundle may not include `libapp.so` in the base APK:
- The base APK contains Java/Kotlin native plugins and assets
- Native libraries are in separate config split APKs
- APKPure/APKCombo may only provide the base APK
- **Workaround**: Use `bundletool` to extract all splits, or analyze the base APK for native plugin code

### What You CAN Find in Java/Kotlin Layer
Even without Dart source, the native plugin layer reveals:
- **Third-party SDK configurations**: Braze API keys, Sentry DSNs, Firebase config, Amplitude keys
- **MethodChannel handlers**: Bridge between Dart and native — shows what native capabilities the app uses
- **Network security config**: Certificate pinning, trusted CAs
- **AndroidManifest.xml**: Exported components, deep link schemes, permissions
- **Encrypted SharedPreferences**: Flutter secure storage uses AES256-SIV + AES256-GCM

### Common Flutter SDKs to Check
| SDK | What to Search | Security Relevance |
|-----|---------------|-------------------|
| Braze/Appboy | `BrazeConfig`, `setApiKey`, `setCustomEndpoint` | Push notification config, SDK auth |
| Sentry | `setDsn`, `SentryEvent` | Error reporting DSN (client-side by design) |
| Firebase | `FirebaseRemoteConfig`, `Crashlytics` | Project config, FCM sender ID |
| Onfido | `OnfidoFactory`, `LivenessFragment` | KYC verification flow |
| Amplitude | `api2.amplitude.com` | Analytics tracking |

### Deep Link / App Link Analysis
Check `assetlinks.json` and `apple-app-site-association` for:
- **Staging/debug apps** listed in production config (e.g., `com.company.staging`, `com.company.debug`)
- **`get_login_creds` permission** — allows the app to receive autofill credentials for the domain
- **Certificate fingerprints** — exposure of signing cert hashes
- Multiple app IDs sharing the same domain's credential access

### Flutter Secure Storage
The `flutter_secure_storage` library uses standard base64 strings as identifiers (NOT encryption keys):
- `"This is the key for a secure storage AES Key"` — standard library constant, NOT a vulnerability
- Actual encryption uses Android Keystore — keys are hardware-backed
- The plaintext base64 strings are expected and not a finding
