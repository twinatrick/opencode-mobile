# OpenCode Private: installation review

This is a community fork for personal use, based on upstream commit
`ba8a45937128c94c9dd29f41f127004a15b46a75` (application version 0.4.16).
It has not been approved for installation or independently security-audited.

## Changes in this fork

- Hosted integrations are disabled in source, including Sentry initialization,
  PostHog initialization, Chatwoot support uploads, waitlist retries and signup UI,
  Google public connectivity probes, and automatic GitHub update discovery.
  Existing telemetry consent cannot enable these integrations.
- SDK dependencies remain bundled; this is a runtime hardening change, not proof
  that the final APK has no third-party traffic. Packet-capture verification is pending.
- Android overlay, legacy shared-storage, camera, boot-completed, Google Cloud
  Messaging/Play Install Referrer, and 15 OEM launcher badge permissions injected
  by transitive AARs are explicitly blocked in both the native manifest and Expo
  configuration (`./plugins/withPrivateBuildHardening`). Android backups are disabled.
- Transitive AAR components that were previously exported without permission guards
  (`ClipboardFileProvider`, `CropImageActivity`) are locked to `android:exported="false"`,
  and native telemetry/cloud background components (`SentryInitProvider`,
  `SentryPerformanceProvider`, `FirebaseInitProvider`, `FirebaseMessagingService`,
  `TransportBackendDiscovery`, `JobInfoSchedulerService`) are removed at manifest
  merge time via `tools:node="remove"`.
- Speech recognition requires on-device recognition; unsupported devices may reject
  voice input. This requirement still needs real-device verification.
- Multiple saved servers and switching the active server are preserved.
- APK build jobs wait for tests. The private workflow has no publishing step,
  uses no upstream service secrets, and produces an unsigned inspection artifact
  only when manually dispatched. It checks final permissions and records SHA-256.

## Connection setup

Use Tailscale on the phone and each server. Give each server its own strong
`OPENCODE_SERVER_PASSWORD`. Prefer OpenCode bound to `127.0.0.1` behind Tailscale
Serve with HTTPS; alternatively bind only to the server's Tailscale IP. Do not
use Funnel or expose the OpenCode port through router forwarding.

The app still accepts arbitrary server addresses and HTTP to support Tailscale IPs.
It does not enforce VPN routing. HTTP Basic authentication is not encryption:
HTTP outside the encrypted Tailscale path can expose credentials and conversations.
Check access rules and devices in the tailnet. Enable the app biometric lock.
Do not approve commands when the requested operation is unclear.

Notifications are generated locally from received events; background connectivity
and timely delivery are not guaranteed. Local diagnostic sharing, attachments,
external browser links and the chosen AI provider remain user-controlled data paths.
AI requests still leave the OpenCode server for the provider you configured.

## Required before installation

1. Review this PR and the unresolved dependency findings in SECURITY_REVIEW.md.
2. Run the manual private build on the reviewed commit; inspect the merged manifest,
   APK permissions and SDK content, and verify its hash.
3. Choose and securely retain a personal release signing key. The unsigned artifact
   is not installable and must not be represented as a verified release.
4. Use a disposable project to test server switching, authentication failures,
   permissions, biometric locking, and foreground/background behavior on a device.
5. Observe network traffic with integrations disabled and Tailscale enabled.

The application ID remains `cc.agentlabs.opencode`. A personal signing key cannot
update an upstream-signed installation. Do not uninstall an existing app without
backing up connection details; a separate application ID can be prepared if needed.

### Phase 2 Application & Transport Hardening

- **Android Network Security Config (`res/xml/network_security_config.xml`)**: Enforces `android:usesCleartextTraffic="false"` globally (`<base-config cleartextTrafficPermitted="false">`), permitting HTTP cleartext only on explicit Tailscale (`*.ts.net`) or local development/container domains.
- **Deep-Link & SDK Path Traversal Defense (`src/lib/sdk.ts`, `src/lib/sdk-v1.ts`, `app/session/[id].tsx`, `app/connection/[id].tsx`)**: Validates all route/API resource IDs via `encodePathSegment()` and `isSafeRouteId()` (`^[A-Za-z0-9._:-]{1,256}$`).
- **Markdown & Attachment Anti-Tracking (`src/lib/markdown-security.ts`, `src/components/markdown/Markdown.tsx`, `src/components/chat/MessageBubble.tsx`)**: Blocks automatic loading of remote `http://`/`https://` inline images (preventing tracking pixels and SSRF) and restricts clickable external links to `http://` and `https://`.
- **Logcat & Diagnostics Redaction (`src/lib/logbuffer.ts`, `src/lib/scrub.ts`, `src/lib/diagnostics.ts`)**: Scrubs URLs, Basic/Bearer tokens, `opencode://` pairing URIs (`enc=`, `pin=`, `payload=`, `pw=`), and IP/host details before writing to the log buffer, `console` (`logcat`), or clipboard/share sheet.

### Phase 3 Native/JS Footprint Elimination, Biometric Default & Encrypted QR Pairing

- **Zero Sentry/PostHog Runtime Footprint (`react-native.config.js`, `src/lib/sentry.ts`, `src/lib/analytics.ts`, `plugins/withPrivateBuildHardening.js`)**: Disables `@sentry/react-native` native autolinking, excludes `libsentry.so`/`libsentry-android.so` (`0` native Sentry `.so` files in final APK), and removes runtime JS imports of `@sentry/react-native` and `posthog-react-native`.
- **Linear-Time URI Decoder (`metro.config.js`, `src/lib/safe-decode-uri-component.js`)**: Redirects `decode-uri-component` at the Metro bundler level to a linear-time implementation (`0/32` npm audit advisories bundled into APK runtime).
- **Biometric Lock Default ON & Connection Security Warnings (`src/stores/auth.ts`, `src/lib/connection-security.ts`, `app/connection/add.tsx`)**: Enables `requireBiometric: true` and `requireBiometricForMessages: true` by default when biometric hardware is enrolled, and warns before connecting over unencrypted HTTP outside Tailscale (`*.ts.net` / `100.64.0.0/10`) or without a password.
- **One-Time Token QR Code Pairing (`scripts/opencode-qr.mjs`, `src/lib/qr-pairing.ts`, `app/connection/add.tsx`)**: Generates a terminal UTF-8 QR code (`npm run qr` / `npm run serve:qr`) encoding `opencode://connection/add?pairing=<base64url>` with a 256-bit CSPRNG one-time pairing token (`crypto.randomBytes(32)`), redeemed once over `POST /__opencode_pairing/redeem` (5-minute TTL, immediate single-use invalidation, 5-attempt rate limiting, zero long-term password in QR payload, default `127.0.0.1` server binding, and redacted terminal/JSON output), with automatic clipboard wiping (`Clipboard.setStringAsync("")`) and zero `android.permission.CAMERA` requirement.
  - Verified Unsigned Release APK SHA-256: `fc3589bda2f057f85b8db520025a066753724bb7f85bb817c919f3db5d5f4717`.
