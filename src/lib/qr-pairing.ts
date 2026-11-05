import { assessConnectionSecurity, type ConnectionSecurityAssessment } from "./connection-security.ts"

export const DEFAULT_QR_TTL_MS = 5 * 60 * 1000 // 5 minutes
export const MIN_TOKEN_LENGTH = 32 // 32 base64url chars = 192+ bits entropy (default generated: 43 chars = 256 bits)
const SAFE_TOKEN_RE = /^[A-Za-z0-9_-]{32,128}$/

export interface QrPairingInvitationEnvelope {
  v: 2
  url: string
  name?: string
  /** High-entropy (256-bit) server-generated one-time pairing token. Never a long-term password. */
  token: string
  iat: number
  exp: number
}

export interface PendingQrPairingInvitation {
  url: string
  name: string
  token: string
  iat: number
  exp: number
  security: ConnectionSecurityAssessment
  securityLabel: string
}

export interface RedeemedPairingPayload {
  url: string
  name: string
  username: string
  password?: string
  security: ConnectionSecurityAssessment
  securityLabel: string
}

export interface ParsedQrPairing {
  ok: true
  state: "redeemed"
  payload: RedeemedPairingPayload
}

export interface PendingRedeemQrPairing {
  ok: true
  state: "pending_redeem"
  invitation: PendingQrPairingInvitation
}

export interface FailedQrPairing {
  ok: false
  code:
    | "EMPTY"
    | "INVALID_SCHEME"
    | "INVALID_PAYLOAD"
    | "INVALID_URL"
    | "INSECURE_LEGACY_PAYLOAD"
    | "LOW_ENTROPY_TOKEN"
    | "EXPIRED_QR"
    | "TOKEN_ALREADY_USED"
    | "RATE_LIMITED"
    | "REDEEM_FAILED"
  error: string
}

export type QrPairingResult = ParsedQrPairing | PendingRedeemQrPairing | FailedQrPairing

const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

export function bytesToBase64Url(bytes: Uint8Array): string {
  let base64 = ""
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0
    const triple = (a << 16) | (b << 8) | c
    base64 += B64_CHARS[(triple >> 18) & 0x3f]
    base64 += B64_CHARS[(triple >> 12) & 0x3f]
    base64 += i + 1 < bytes.length ? B64_CHARS[(triple >> 6) & 0x3f] : ""
    base64 += i + 2 < bytes.length ? B64_CHARS[triple & 0x3f] : ""
  }
  return base64.replace(/\+/g, "-").replace(/\//g, "_")
}

export function base64UrlToBytes(input: string): Uint8Array {
  const normalized = input.trim().replace(/-/g, "+").replace(/_/g, "/")
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error("Invalid base64url character")
  }
  const clean = normalized.replace(/=+$/, "")
  const out: number[] = []
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = B64_CHARS.indexOf(clean[i])
    const c1 = i + 1 < clean.length ? B64_CHARS.indexOf(clean[i + 1]) : -1
    const c2 = i + 2 < clean.length ? B64_CHARS.indexOf(clean[i + 2]) : -1
    const c3 = i + 3 < clean.length ? B64_CHARS.indexOf(clean[i + 3]) : -1
    if (c0 < 0 || c1 < 0) throw new Error("Truncated base64url")
    const triple = (c0 << 18) | (c1 << 12) | ((c2 > -1 ? c2 : 0) << 6) | (c3 > -1 ? c3 : 0)
    out.push((triple >> 16) & 0xff)
    if (c2 > -1) out.push((triple >> 8) & 0xff)
    if (c3 > -1) out.push(triple & 0xff)
  }
  return new Uint8Array(out)
}

export function encodeBase64UrlUtf8(input: string): string {
  return bytesToBase64Url(new TextEncoder().encode(input))
}

export function decodeBase64UrlUtf8(input: string): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(base64UrlToBytes(input))
}

export function isHighEntropyPairingToken(token: unknown): token is string {
  return typeof token === "string" && SAFE_TOKEN_RE.test(token.trim())
}

export function normalizePairingServerUrl(rawUrl: string): string | null {
  const trimmed = rawUrl.trim()
  if (!trimmed || trimmed.length > 512) return null
  try {
    const parsed = new URL(trimmed)
    const protocol = parsed.protocol.toLowerCase()
    if (protocol !== "http:" && protocol !== "https:") return null
    if (!parsed.hostname) return null
    if (parsed.username || parsed.password) return null
    const pathPart = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "")
    return `${protocol}//${parsed.host}${pathPart}`
  } catch {
    return null
  }
}

function buildPendingInvitation(
  raw: {
    url?: unknown
    name?: unknown
    token?: unknown
    iat?: unknown
    exp?: unknown
  },
  nowMs: number = Date.now(),
): QrPairingResult {
  if (typeof raw.url !== "string" || !raw.url.trim()) {
    return { ok: false, code: "INVALID_URL", error: "QR pairing payload is missing server URL." }
  }
  const normalizedUrl = normalizePairingServerUrl(raw.url)
  if (!normalizedUrl) {
    return {
      ok: false,
      code: "INVALID_URL",
      error: "QR pairing URL must be a valid http:// or https:// address without embedded credentials.",
    }
  }
  if (!isHighEntropyPairingToken(raw.token)) {
    return {
      ok: false,
      code: "LOW_ENTROPY_TOKEN",
      error: "QR pairing token does not meet minimum 192-bit/256-bit entropy requirements.",
    }
  }

  const iat = typeof raw.iat === "number" && Number.isFinite(raw.iat) ? raw.iat : nowMs
  const exp = typeof raw.exp === "number" && Number.isFinite(raw.exp) ? raw.exp : iat + DEFAULT_QR_TTL_MS
  if (nowMs > exp) {
    return {
      ok: false,
      code: "EXPIRED_QR",
      error: "This QR code has expired (5-minute validity window). Generate a new QR code on your OpenCode server.",
    }
  }

  const parsedHost = new URL(normalizedUrl).hostname
  const cleanName =
    typeof raw.name === "string" && raw.name.trim().length > 0
      ? raw.name.trim().slice(0, 80)
      : `OpenCode (${parsedHost})`

  const security = assessConnectionSecurity(normalizedUrl, "pending-token-auth")
  return {
    ok: true,
    state: "pending_redeem",
    invitation: {
      url: normalizedUrl,
      name: cleanName,
      token: raw.token.trim(),
      iat,
      exp,
      security,
      securityLabel: security.transportLabel,
    },
  }
}

/**
 * Builds an `opencode://connection/add?pairing=<base64url>` URI containing ONLY
 * the server URL, display name, expiration timestamp, and a high-entropy one-time
 * pairing token. Never embeds the server password or an offline-verifiable PIN ([HIGH-01]).
 */
export function buildPairingUri(
  input: {
    url: string
    name?: string
    token: string
    ttlMs?: number
  },
  nowMs: number = Date.now(),
): string {
  const normalizedUrl = normalizePairingServerUrl(input.url)
  if (!normalizedUrl) {
    throw new Error("Invalid server URL for QR pairing")
  }
  if (!isHighEntropyPairingToken(input.token)) {
    throw new Error("Pairing token must be at least 32 Base64URL characters of random entropy")
  }
  const ttl = input.ttlMs ?? DEFAULT_QR_TTL_MS
  const envelope: QrPairingInvitationEnvelope = {
    v: 2,
    url: normalizedUrl,
    ...(input.name?.trim() ? { name: input.name.trim() } : {}),
    token: input.token.trim(),
    iat: nowMs,
    exp: nowMs + ttl,
  }
  const encoded = encodeBase64UrlUtf8(JSON.stringify(envelope))
  return `opencode://connection/add?pairing=${encoded}`
}

export function parsePairingSearchParams(
  params: {
    pairing?: string | string[]
    token?: string | string[]
    url?: string | string[]
    name?: string | string[]
    exp?: string | string[]
    iat?: string | string[]
    enc?: string | string[]
    pin?: string | string[]
    payload?: string | string[]
    pw?: string | string[]
    password?: string | string[]
  },
  nowMs: number = Date.now(),
): QrPairingResult | null {
  const first = (v?: string | string[]) => (Array.isArray(v) ? v[0] : v)
  const enc = first(params.enc)
  const pw = first(params.pw) ?? first(params.password)
  const legacyPayload = first(params.payload)

  // Block legacy offline PIN-encrypted or plaintext-password QR payloads ([HIGH-01])
  if ((enc && enc.trim()) || (pw && pw.trim()) || (legacyPayload && legacyPayload.trim())) {
    return {
      ok: false,
      code: "INSECURE_LEGACY_PAYLOAD",
      error:
        "Legacy QR payloads containing passwords or offline PIN encryption are disabled ([HIGH-01]). Generate a v2 one-time token QR code on your server.",
    }
  }

  const pairingParam = first(params.pairing)
  if (pairingParam && pairingParam.trim()) {
    try {
      const jsonStr = decodeBase64UrlUtf8(pairingParam.trim())
      const parsed = JSON.parse(jsonStr) as Record<string, unknown>
      if (!parsed || typeof parsed !== "object") {
        return { ok: false, code: "INVALID_PAYLOAD", error: "QR pairing payload is not a JSON object." }
      }
      if ("pw" in parsed || "password" in parsed) {
        return {
          ok: false,
          code: "INSECURE_LEGACY_PAYLOAD",
          error: "QR pairing payload must not contain a direct server password ([HIGH-01]).",
        }
      }
      return buildPendingInvitation(
        {
          url: parsed.url,
          name: parsed.name,
          token: parsed.token,
          iat: parsed.iat,
          exp: parsed.exp,
        },
        nowMs,
      )
    } catch {
      return {
        ok: false,
        code: "INVALID_PAYLOAD",
        error: "Could not decode QR pairing invitation.",
      }
    }
  }

  const url = first(params.url)
  const token = first(params.token)
  if (url || token) {
    const expNum = first(params.exp) ? Number(first(params.exp)) : undefined
    const iatNum = first(params.iat) ? Number(first(params.iat)) : undefined
    return buildPendingInvitation(
      {
        url,
        name: first(params.name),
        token,
        iat: iatNum,
        exp: expNum,
      },
      nowMs,
    )
  }

  return null
}

export function parsePairingInput(rawInput: string, nowMs: number = Date.now()): QrPairingResult {
  const trimmed = rawInput.trim()
  if (!trimmed) {
    return { ok: false, code: "EMPTY", error: "Pairing link is empty." }
  }
  if (!/^opencode:\/\//i.test(trimmed)) {
    return {
      ok: false,
      code: "INVALID_SCHEME",
      error: "Only opencode://connection/add pairing links are accepted.",
    }
  }

  const withoutScheme = trimmed.replace(/^opencode:\/\//i, "")
  const qIndex = withoutScheme.indexOf("?")
  const pathPart = (qIndex >= 0 ? withoutScheme.slice(0, qIndex) : withoutScheme).replace(/\/+$/, "")
  if (pathPart.toLowerCase() !== "connection/add") {
    return {
      ok: false,
      code: "INVALID_SCHEME",
      error: "Only opencode://connection/add pairing links are accepted.",
    }
  }

  const queryString = qIndex >= 0 ? withoutScheme.slice(qIndex + 1) : ""
  const searchParams = new URLSearchParams(queryString)
  const result = parsePairingSearchParams(
    {
      pairing: searchParams.get("pairing") ?? undefined,
      token: searchParams.get("token") ?? undefined,
      url: searchParams.get("url") ?? undefined,
      name: searchParams.get("name") ?? undefined,
      exp: searchParams.get("exp") ?? undefined,
      iat: searchParams.get("iat") ?? undefined,
      enc: searchParams.get("enc") ?? undefined,
      pin: searchParams.get("pin") ?? undefined,
      payload: searchParams.get("payload") ?? undefined,
      pw: searchParams.get("pw") ?? undefined,
      password: searchParams.get("password") ?? undefined,
    },
    nowMs,
  )

  return (
    result ?? {
      ok: false,
      code: "INVALID_PAYLOAD",
      error: "No pairing parameters found in opencode://connection/add link.",
    }
  )
}

/**
 * Redeems a one-time pairing token against the OpenCode server's pairing endpoint
 * (`POST /__opencode_pairing/redeem`). The server validates token entropy, TTL expiration,
 * single-use state, and rate limits before returning session credentials.
 */
export async function redeemPairingToken(
  invitation: PendingQrPairingInvitation,
  fetchImpl: typeof fetch = fetch,
  nowMs: number = Date.now(),
): Promise<QrPairingResult> {
  if (nowMs > invitation.exp) {
    return {
      ok: false,
      code: "EXPIRED_QR",
      error: "This QR pairing token has expired. Generate a new QR code on your server.",
    }
  }

  try {
    const endpoint = `${invitation.url.replace(/\/+$/, "")}/__opencode_pairing/redeem`
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ token: invitation.token }),
    })

    const body = (await response.json().catch(() => ({}))) as {
      ok?: boolean
      code?: string
      error?: string
      config?: {
        url?: string
        name?: string
        username?: string
        password?: string
      }
    }

    if (response.status === 429 || body.code === "RATE_LIMITED") {
      return {
        ok: false,
        code: "RATE_LIMITED",
        error: "Too many failed pairing attempts. The pairing token has been invalidated by the server.",
      }
    }

    if (response.status === 410 || body.code === "TOKEN_EXPIRED") {
      return {
        ok: false,
        code: "EXPIRED_QR",
        error: "This QR pairing token has expired on the server.",
      }
    }

    if (response.status === 409 || body.code === "TOKEN_ALREADY_USED") {
      return {
        ok: false,
        code: "TOKEN_ALREADY_USED",
        error: "This one-time QR pairing token has already been used.",
      }
    }

    if (!response.ok || !body.ok || !body.config) {
      return {
        ok: false,
        code: "REDEEM_FAILED",
        error: "Server rejected the one-time pairing token.",
      }
    }

    const finalUrl = normalizePairingServerUrl(body.config.url || invitation.url) || invitation.url
    const finalName = body.config.name?.trim() || invitation.name
    const finalUsername = body.config.username?.trim() || "opencode"
    const finalPassword = body.config.password
    const security = assessConnectionSecurity(finalUrl, finalPassword)

    return {
      ok: true,
      state: "redeemed",
      payload: {
        url: finalUrl,
        name: finalName,
        username: finalUsername,
        password: finalPassword,
        security,
        securityLabel: security.transportLabel,
      },
    }
  } catch {
    return {
      ok: false,
      code: "REDEEM_FAILED",
      error: "Could not reach server to redeem one-time pairing token.",
    }
  }
}
