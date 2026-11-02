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
- Android overlay and legacy shared-storage permissions are explicitly blocked,
  both in the native manifest and Expo configuration. Android backups are disabled.
  Microphone and image attachment permissions remain for optional features.
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
