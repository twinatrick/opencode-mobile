# Security review: private OpenCode Mobile fork

Review date: 2026-11-02. Upstream baseline: ba8a45937128c94c9dd29f41f127004a15b46a75.

## Decision

**Hold installation approval.** Source hardening is ready for review, but the APK,
merged manifest, network behavior and device UI have not yet been verified.
Do not treat passing unit tests as a security certification.

## Verified findings and changes

| Area | Evidence | Result |
| --- | --- | --- |
| Credentials | src/stores/connections.ts uses expo-secure-store | Preserved; credentials are also present in app memory while connected |
| Multiple remotes | connections store has saved connections and one active client | Preserved, no changes to switching behavior |
| Optional hosted integrations | telemetry.ts, analytics.ts, sentry.ts, chatwoot.ts | Hard-disabled even when upstream environment variables or prior consent exist |
| Other outbound requests | update-check.ts, diagnostics.ts, waitlist queue and connection UI | Automatic update discovery, public Google probe, waitlist retry and signup UI disabled |
| Android permissions | app.json, withPrivateBuildHardening.js, and native AndroidManifest.xml | Overlay, legacy shared-storage, camera, boot-completed, c2dm/finsky, and 15 OEM badge permissions blocked; backups disabled |
| Android exported & native telemetry components | withPrivateBuildHardening.js and native AndroidManifest.xml | ClipboardFileProvider & CropImageActivity forced to exported=false; SentryInitProvider, SentryPerformanceProvider, FirebaseInitProvider, FirebaseMessagingService & Datatransport services removed via tools:node="remove" |
| Voice | speech.ts | On-device recognition required; real-device support unverified |
| Build pipeline | build.yml and private-build.yml | Test gate added; separate manual unsigned inspection build; no automatic installation |

The support upload regression test deliberately supplies configured service values
and asserts that neither network nor saved support identity is accessed. Old tests
for enabled Chatwoot behavior were replaced because this fork disables the feature.
Hosted SDK packages remain in dependencies; static import/native initialization and
transitive SDK behavior still need APK and traffic inspection. User-requested
external browser links and local diagnostic sharing are not blocked.

## Local validation

- npm ci --ignore-scripts --legacy-peer-deps completed before review.
- npm run typecheck passed after the dependency refresh.
- npm run check:versions passed: version 0.4.16 / Android code 43.
- npm test passed: 373 tests, zero failures.
- git diff --check passed.
- No Android SDK/emulator is available here; Android compilation and device/CUA
  smoke tests have not run. No merge or release is authorized by this review.

## Dependency scan

npm audit --omit=dev originally reported 49 affected package entries:
2 critical, 16 high, 29 moderate and 2 low. A compatible npm audit fix (without
--force or lifecycle scripts) refreshed the lockfile. The subsequent scan reports
32 entries: **0 critical, 5 high, 26 moderate, 1 low**. Entries include transitive
and build-tool dependencies; the count is not a count of exploitable APK flaws.

Remaining high entries:

| Package | Concern | Scope still requiring verification |
| --- | --- | --- |
| decode-uri-component | malformed percent-encoding can cause denial of service | Route/query decoding in expo-router dependency chain |
| query-string | inherited finding from decoding dependency | Route input exposure |
| expo-router | inherited finding from query-string chain | Mobile deep links and route handling |
| image-size | malformed image parsers can loop | Metro/build-time image processing reachability |
| postcss | CSS/source-map handling findings | Web/build-tool use; not proven reachable in Android runtime |

Advisories: [decode-uri-component](https://github.com/advisories/GHSA-vcc3-ghjq-m6fr),
[image-size](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq),
[PostCSS](https://github.com/advisories/GHSA-6g55-p6wh-862q).

Do not use npm audit fix --force blindly: the suggested dependency resolution
includes incompatible Expo/React Native/router changes. Resolve the remaining
findings in a separately tested framework update or assess exact runtime
reachability before approving installation.

## Remaining verification

Run the private workflow manually on the reviewed branch, inspect the final APK,
then sign it with a retained personal key only after review. Use a disposable
server/project for multi-remote switching, permission-denial, biometric re-lock,
attachments and background tests. Observe all traffic before entering valuable
server credentials. Tailscale does not sandbox the client or the OpenCode agent.
See PRIVATE_BUILD.md for connection instructions and signing limitations.

### Phase 2 Code, Deep-Link, Markdown & Transport Hardening

- **Cleartext HTTP Lockdown**: Replaced global `android:usesCleartextTraffic="true"` with `android:usesCleartextTraffic="false"` and `@xml/network_security_config` (`<base-config cleartextTrafficPermitted="false">`).
- **Deep-Link Path Traversal & Query DoS Verification**: Added strict ID validation (`encodePathSegment` / `isSafeRouteId`) and verified in KVM Android 35 Emulator against path traversal (`opencode://session/..%2F..%2Fadmin`) and malformed percent-encoded query strings (`%25` x 300).
- **Markdown Tracking Pixel & SSRF Prevention**: Overrode `image()`, `linkImage()`, and `link()` in `CustomRenderer` (`src/components/markdown/Markdown.tsx`) and guarded `MessageBubble.tsx` attachments so remote `http://`/`https://` images never auto-fetch.
- **Logcat & Share Sheet Credential Scrubbing**: Enhanced `scrubString()` in `src/lib/scrub.ts` to redact `Basic`/`Bearer` headers and `opencode://` pairing secrets (`enc=`, `pin=`, `payload=`, `pw=`), applied it in `src/lib/logbuffer.ts`, and updated `shareReport()` in `src/lib/diagnostics.ts` to always export `formatReportForSupport()`.

### Phase 3 Native/JS Footprint Elimination, Biometric Default & Encrypted QR Pairing

- **Eliminated Sentry/PostHog Native & JS Bundle Footprint**: Disabled `@sentry/react-native` autolinking in `react-native.config.js`, excluded `libsentry.so`/`libsentry-android.so` in `withPrivateBuildHardening.js` (`0` native Sentry `.so` libraries in the final APK), and removed runtime imports of `@sentry/react-native` and `posthog-react-native` from `src/lib/sentry.ts` and `src/lib/analytics.ts`.
- **Eliminated `decode-uri-component` Runtime Advisory (`0/32` Bundled)**: Redirected `decode-uri-component` in `metro.config.js` to `src/lib/safe-decode-uri-component.js` (linear-time single-pass decoder).
- **Biometric Lock Default ON & Connection Security Warnings**: Enabled `requireBiometric: true` and `requireBiometricForMessages: true` by default in `src/stores/auth.ts`, and added Tailscale/HTTPS transport and empty-password warnings in `src/lib/connection-security.ts` and `app/connection/add.tsx`.
- **One-Time Token QR Code Pairing (256-bit CSPRNG Token + Single-Use + 5m TTL + 5-Attempt Rate Limit + Clipboard Auto-Wipe)**: Replaced low-entropy PIN encryption with `scripts/opencode-qr.mjs` and `src/lib/qr-pairing.ts` using a 256-bit CSPRNG one-time token (`crypto.randomBytes(32)`) redeemed via `POST /__opencode_pairing/redeem` (5-minute TTL, single-use invalidation, 5-attempt rate limit, zero long-term server password in QR payload, default `127.0.0.1` bind host, redacted terminal/JSON logs, automatic clipboard clearing `Clipboard.setStringAsync("")`, and fixed `.MainActivity` `<category android:name="android.intent.category.DEFAULT" />` without requiring `android.permission.CAMERA`).
  - Verified Unsigned Release APK SHA-256: `fc3589bda2f057f85b8db520025a066753724bb7f85bb817c919f3db5d5f4717` (`395/395` unit tests passed, KVM Android 35 Emulator verified).
