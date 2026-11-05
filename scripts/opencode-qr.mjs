#!/usr/bin/env node
import crypto from "node:crypto"
import { execSync, spawn } from "node:child_process"
import os from "node:os"

/**
 * OpenCode Server Terminal QR Code Generator & One-Time Token Exchange ([HIGH-01], [MEDIUM-01], [MEDIUM-04])
 *
 * Security invariants:
 *  - [HIGH-01] Never embeds the long-term server password or an offline-verifiable low-entropy PIN in the QR code.
 *    Generates a 256-bit CSPRNG one-time pairing token (`crypto.randomBytes(32).toString("base64url")`),
 *    validated server-side with single-use invalidation, 5-minute TTL expiration, and 5-attempt rate limiting.
 *  - [MEDIUM-01] Defaults `--serve` binding to `127.0.0.1` (for use behind `tailscale serve --https=443 http://127.0.0.1:4096`)
 *    and refuses `0.0.0.0` wildcard exposure unless `--allow-lan-exposure` is explicitly passed.
 *  - [MEDIUM-04] Never prints long-term server passwords or raw tokens to terminal/CI logs by default.
 */

export const DEFAULT_QR_TTL_MS = 5 * 60 * 1000 // 5 minutes
export const DEFAULT_BIND_HOST = "127.0.0.1"
export const DEFAULT_MAX_FAILED_ATTEMPTS = 5

export function generatePairingToken() {
  return crypto.randomBytes(32).toString("base64url")
}

export function resolveBindHost(requestedHost = DEFAULT_BIND_HOST, allowLanExposure = false) {
  const host = String(requestedHost || DEFAULT_BIND_HOST).trim()
  if ((host === "0.0.0.0" || host === "::") && !allowLanExposure) {
    throw new Error(
      "Refusing to bind OpenCode Server to 0.0.0.0 by default ([MEDIUM-01]). Bind to 127.0.0.1 behind Tailscale Serve HTTPS, specify a dedicated interface IP, or pass --allow-lan-exposure explicitly.",
    )
  }
  return host
}

export function buildPairingUri(
  { url, name, token, ttlMs = DEFAULT_QR_TTL_MS },
  nowMs = Date.now(),
) {
  if (!token || typeof token !== "string" || token.trim().length < 32) {
    throw new Error("Pairing token must have at least 32 Base64URL characters of random entropy ([HIGH-01]).")
  }
  const envelope = {
    v: 2,
    url: String(url).replace(/\/+$/, ""),
    ...(name ? { name: String(name).trim() } : {}),
    token: token.trim(),
    iat: nowMs,
    exp: nowMs + ttlMs,
  }
  const encoded = Buffer.from(JSON.stringify(envelope), "utf8").toString("base64url")
  return `opencode://connection/add?pairing=${encoded}`
}

/**
 * Server-side one-time pairing token exchange store with:
 * - Constant-time token comparison (`crypto.timingSafeEqual`)
 * - Single-use invalidation (`consumed = true`)
 * - 5-minute TTL expiration (`exp`)
 * - Strict rate limiting (`maxFailedAttempts = 5`, invalidating the token upon threshold)
 */
export function createPairingExchangeStore({
  url,
  name = "OpenCode Server",
  username = "opencode",
  password,
  ttlMs = DEFAULT_QR_TTL_MS,
  maxFailedAttempts = DEFAULT_MAX_FAILED_ATTEMPTS,
  nowFn = () => Date.now(),
}) {
  const issuedAt = nowFn()
  let state = {
    token: generatePairingToken(),
    url: String(url).replace(/\/+$/, ""),
    name,
    username,
    password,
    iat: issuedAt,
    exp: issuedAt + ttlMs,
    consumed: false,
    invalidatedByRateLimit: false,
    failedAttempts: 0,
  }

  function rotateToken() {
    const now = nowFn()
    state = {
      ...state,
      token: generatePairingToken(),
      iat: now,
      exp: now + ttlMs,
      consumed: false,
      invalidatedByRateLimit: false,
      failedAttempts: 0,
    }
    return getPublicMetadata()
  }

  function getPublicMetadata() {
    const pairingUri = buildPairingUri(
      { url: state.url, name: state.name, token: state.token, ttlMs: state.exp - state.iat },
      state.iat,
    )
    return {
      url: state.url,
      name: state.name,
      username: state.username,
      iat: state.iat,
      exp: state.exp,
      consumed: state.consumed,
      invalidatedByRateLimit: state.invalidatedByRateLimit,
      failedAttempts: state.failedAttempts,
      pairingUri,
    }
  }

  function redeem(candidateToken) {
    const now = nowFn()
    if (state.invalidatedByRateLimit || state.failedAttempts >= maxFailedAttempts) {
      state.invalidatedByRateLimit = true
      return {
        status: 429,
        body: {
          ok: false,
          code: "RATE_LIMITED",
          error: "Too many failed pairing attempts. Active pairing token has been invalidated.",
        },
      }
    }

    if (now > state.exp) {
      return {
        status: 410,
        body: {
          ok: false,
          code: "TOKEN_EXPIRED",
          error: "Pairing token has expired.",
        },
      }
    }

    if (state.consumed) {
      return {
        status: 409,
        body: {
          ok: false,
          code: "TOKEN_ALREADY_USED",
          error: "Pairing token has already been used.",
        },
      }
    }

    const submitted = typeof candidateToken === "string" ? candidateToken.trim() : ""
    const expectedBuf = Buffer.from(state.token, "utf8")
    const submittedBuf = Buffer.from(submitted, "utf8")
    const matches =
      expectedBuf.length === submittedBuf.length &&
      crypto.timingSafeEqual(expectedBuf, submittedBuf)

    if (!matches) {
      state.failedAttempts += 1
      if (state.failedAttempts >= maxFailedAttempts) {
        state.invalidatedByRateLimit = true
        return {
          status: 429,
          body: {
            ok: false,
            code: "RATE_LIMITED",
            error: "Too many failed pairing attempts. Active pairing token has been invalidated.",
          },
        }
      }
      return {
        status: 401,
        body: {
          ok: false,
          code: "INVALID_TOKEN",
          error: "Invalid pairing token.",
        },
      }
    }

    state.consumed = true
    return {
      status: 200,
      body: {
        ok: true,
        config: {
          url: state.url,
          name: state.name,
          username: state.username,
          password: state.password,
        },
      },
    }
  }

  return {
    getPublicMetadata,
    redeem,
    rotateToken,
  }
}

export function formatTerminalSummary({
  url,
  name,
  username,
  exp,
  bindHost = DEFAULT_BIND_HOST,
  qrAscii,
  showSecrets = false,
  password = "",
}) {
  const lines = [
    "================================================================",
    "  OpenCode Mobile — One-Time Token QR Pairing (Zero Camera Perm)",
    "================================================================",
    `  Server Name : ${name}`,
    `  Connect URL : ${url}`,
    `  Bind Host   : ${bindHost} (Least-Privilege Local/Interface Binding)`,
    `  Username    : ${username}`,
    `  Password    : ${showSecrets ? password : "<redacted — exchanged via one-time server token>"}`,
    `  Expires At  : ${new Date(exp).toISOString()} (5-minute single-use window)`,
    "----------------------------------------------------------------",
    qrAscii,
    "----------------------------------------------------------------",
    "  1. Scan the QR code with your phone's system scanner.",
    "  2. Confirm the server URL in OpenCode Mobile to redeem the one-time token.",
    "================================================================",
  ]
  return lines.join("\n")
}

export function formatJsonSummary(metadata, includeSecrets = false, secrets = {}) {
  const safe = {
    url: metadata.url,
    name: metadata.name,
    username: metadata.username,
    iat: metadata.iat,
    exp: metadata.exp,
    consumed: metadata.consumed,
    pairingUri: metadata.pairingUri,
    passwordRedacted: !includeSecrets,
  }
  if (includeSecrets) {
    safe.password = secrets.password
  }
  return safe
}

// ============================================================================
// Minimal zero-dependency QR Code Encoder (ISO/IEC 18004, Byte Mode, ECC L, v1..14)
// ============================================================================

const CAPACITIES_L = [
  0,
  17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458,
]

const EC_BLOCKS_L = [
  null,
  { ecPerBlock: 7, groups: [[1, 19]] },
  { ecPerBlock: 10, groups: [[1, 34]] },
  { ecPerBlock: 15, groups: [[1, 55]] },
  { ecPerBlock: 20, groups: [[1, 80]] },
  { ecPerBlock: 26, groups: [[1, 108]] },
  { ecPerBlock: 18, groups: [[2, 68]] },
  { ecPerBlock: 20, groups: [[2, 78]] },
  { ecPerBlock: 24, groups: [[2, 97]] },
  { ecPerBlock: 30, groups: [[2, 116]] },
  { ecPerBlock: 18, groups: [[2, 68], [2, 69]] },
  { ecPerBlock: 20, groups: [[4, 81]] },
  { ecPerBlock: 24, groups: [[2, 92], [2, 93]] },
  { ecPerBlock: 26, groups: [[4, 107]] },
  { ecPerBlock: 30, groups: [[3, 115], [1, 116]] },
]

const ALIGNMENT_POS = [
  [],
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
]

const GF_EXP = new Uint8Array(512)
const GF_LOG = new Uint8Array(256)
;(() => {
  let x = 1
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x
    GF_LOG[x] = i
    x <<= 1
    if (x & 0x100) x ^= 0x11d
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255]
})()

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0
  return GF_EXP[GF_LOG[a] + GF_LOG[b]]
}

function rsGeneratorPoly(degree) {
  let poly = new Uint8Array([1])
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1)
    const root = GF_EXP[i]
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j]
      next[j + 1] ^= gfMul(poly[j], root)
    }
    poly = next
  }
  return poly
}

function rsEncode(data, ecLen) {
  const gen = rsGeneratorPoly(ecLen)
  const msg = new Uint8Array(data.length + ecLen)
  msg.set(data, 0)
  for (let i = 0; i < data.length; i++) {
    const coef = msg[i]
    if (coef !== 0) {
      for (let j = 0; j < gen.length; j++) {
        msg[i + j] ^= gfMul(gen[j], coef)
      }
    }
  }
  return msg.slice(data.length)
}

export function encodeQrMatrix(text) {
  const utf8 = Buffer.from(text, "utf8")
  let version = 1
  while (version <= 14 && CAPACITIES_L[version] < utf8.length) version++
  if (version > 14) {
    throw new Error(`Payload too long for terminal QR (${utf8.length} bytes)`)
  }

  const ecInfo = EC_BLOCKS_L[version]
  const totalDataBytes = ecInfo.groups.reduce((s, [c, k]) => s + c * k, 0)
  const bits = []
  const pushBits = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1)
  }

  pushBits(0b0100, 4)
  pushBits(utf8.length, version >= 10 ? 16 : 8)
  for (const b of utf8) pushBits(b, 8)

  const maxBits = totalDataBytes * 8
  for (let i = 0; i < 4 && bits.length < maxBits; i++) bits.push(0)
  while (bits.length % 8 !== 0) bits.push(0)

  const dataBytes = new Uint8Array(totalDataBytes)
  for (let i = 0; i < bits.length / 8; i++) {
    let byte = 0
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b]
    dataBytes[i] = byte
  }
  const padBytes = [0xec, 0x11]
  for (let i = bits.length / 8, p = 0; i < totalDataBytes; i++, p ^= 1) {
    dataBytes[i] = padBytes[p]
  }

  const dataBlocks = []
  const ecBlocks = []
  let offset = 0
  for (const [count, k] of ecInfo.groups) {
    for (let c = 0; c < count; c++) {
      const block = dataBytes.slice(offset, offset + k)
      offset += k
      dataBlocks.push(block)
      ecBlocks.push(rsEncode(block, ecInfo.ecPerBlock))
    }
  }

  const finalCodewords = []
  const maxDataLen = Math.max(...dataBlocks.map((b) => b.length))
  for (let i = 0; i < maxDataLen; i++) {
    for (const b of dataBlocks) if (i < b.length) finalCodewords.push(b[i])
  }
  for (let i = 0; i < ecInfo.ecPerBlock; i++) {
    for (const b of ecBlocks) finalCodewords.push(b[i])
  }

  const size = 17 + version * 4
  const modules = Array.from({ length: size }, () => new Int8Array(size).fill(-1))
  const isFunction = Array.from({ length: size }, () => new Uint8Array(size))

  const setModule = (r, c, val, func = true) => {
    if (r < 0 || r >= size || c < 0 || c >= size) return
    modules[r][c] = val ? 1 : 0
    if (func) isFunction[r][c] = 1
  }

  const placeFinder = (row, col) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const inOuter = r >= 0 && r <= 6 && c >= 0 && c <= 6
        const inBorder = r === 0 || r === 6 || c === 0 || c === 6
        const inInner = r >= 2 && r <= 4 && c >= 2 && c <= 4
        setModule(row + r, col + c, inOuter && (inBorder || inInner), true)
      }
    }
  }

  placeFinder(0, 0)
  placeFinder(0, size - 7)
  placeFinder(size - 7, 0)

  for (let i = 8; i < size - 8; i++) {
    setModule(6, i, i % 2 === 0, true)
    setModule(i, 6, i % 2 === 0, true)
  }

  const align = ALIGNMENT_POS[version]
  for (let i = 0; i < align.length; i++) {
    for (let j = 0; j < align.length; j++) {
      if (
        (i === 0 && j === 0) ||
        (i === 0 && j === align.length - 1) ||
        (i === align.length - 1 && j === 0)
      ) {
        continue
      }
      const cr = align[i]
      const cc = align[j]
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const val = Math.max(Math.abs(r), Math.abs(c)) !== 1
          setModule(cr + r, cc + c, val, true)
        }
      }
    }
  }

  setModule(size - 8, 8, true, true)
  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      if (modules[8][i] === -1) setModule(8, i, false, true)
      if (modules[i][8] === -1) setModule(i, 8, false, true)
    }
  }
  for (let i = 0; i < 8; i++) {
    if (modules[8][size - 1 - i] === -1) setModule(8, size - 1 - i, false, true)
    if (modules[size - 1 - i][8] === -1) setModule(size - 1 - i, 8, false, true)
  }

  const cwBits = []
  for (const cw of finalCodewords) {
    for (let b = 7; b >= 0; b--) cwBits.push((cw >> b) & 1)
  }

  let bitIdx = 0
  let upward = true
  for (let col = size - 1; col >= 1; col -= 2) {
    if (col === 6) col--
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step
      for (let dc = 0; dc < 2; dc++) {
        const c = col - dc
        if (!isFunction[row][c]) {
          const bit = bitIdx < cwBits.length ? cwBits[bitIdx++] : 0
          const mask = (row + c) % 2 === 0 ? 1 : 0
          modules[row][c] = bit ^ mask
        }
      }
    }
    upward = !upward
  }

  const formatBits = 0x77c4
  for (let i = 0; i <= 5; i++) setModule(8, i, ((formatBits >> i) & 1) === 1, true)
  setModule(8, 7, ((formatBits >> 6) & 1) === 1, true)
  setModule(8, 8, ((formatBits >> 7) & 1) === 1, true)
  setModule(7, 8, ((formatBits >> 8) & 1) === 1, true)
  for (let i = 9; i < 15; i++) setModule(14 - i, 8, ((formatBits >> i) & 1) === 1, true)
  for (let i = 0; i < 8; i++) setModule(size - 1 - i, 8, ((formatBits >> i) & 1) === 1, true)
  for (let i = 8; i < 15; i++) setModule(8, size - 15 + i, ((formatBits >> i) & 1) === 1, true)

  return modules
}

export function renderQrTerminal(text, quietZone = 2) {
  const matrix = encodeQrMatrix(text)
  const size = matrix.length
  const total = size + quietZone * 2
  const get = (r, c) => {
    const mr = r - quietZone
    const mc = c - quietZone
    if (mr < 0 || mr >= size || mc < 0 || mc >= size) return 0
    return matrix[mr][mc]
  }
  const lines = []
  for (let r = 0; r < total; r += 2) {
    let line = "  "
    for (let c = 0; c < total; c++) {
      const top = get(r, c)
      const bottom = r + 1 < total ? get(r + 1, c) : 0
      if (top && bottom) line += "█"
      else if (top && !bottom) line += "▀"
      else if (!top && bottom) line += "▄"
      else line += " "
    }
    lines.push(line)
  }
  return lines.join("\n")
}

export function renderQrSvg(text, quietZone = 2) {
  const matrix = encodeQrMatrix(text)
  const size = matrix.length
  const total = size + quietZone * 2
  let rects = ""
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) {
        rects += `<rect x="${c + quietZone}" y="${r + quietZone}" width="1" height="1" fill="#000"/>`
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" shape-rendering="crispEdges"><rect width="${total}" height="${total}" fill="#fff"/>${rects}</svg>`
}

export function detectTailscaleHost(port = "4096") {
  try {
    const raw = execSync("tailscale status --json", {
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 2500,
    }).toString("utf8")
    const status = JSON.parse(raw)
    const dnsName = status?.Self?.DNSName?.replace(/\.$/, "")
    if (dnsName) {
      // [MEDIUM-01] & [MEDIUM-02]: Prefer Tailscale Serve HTTPS (`https://<magicdns>`)
      return { url: `https://${dnsName}`, source: "Tailscale Serve HTTPS (MagicDNS)" }
    }
  } catch {
    // Fallback to local loopback
  }
  return {
    url: `http://${DEFAULT_BIND_HOST}:${port}`,
    source: "Local Loopback (Configure `tailscale serve --https=443 http://127.0.0.1:4096` for remote access)",
  }
}

function parseCliArgs(argv) {
  const opts = {
    url: process.env.OPENCODE_PUBLIC_URL || "",
    port: process.env.OPENCODE_PORT || "4096",
    bindHost: process.env.OPENCODE_BIND_HOST || DEFAULT_BIND_HOST,
    allowLanExposure: false,
    name: process.env.OPENCODE_SERVER_NAME || os.hostname() || "OpenCode Server",
    user: process.env.OPENCODE_SERVER_USERNAME || "opencode",
    password:
      process.env.OPENCODE_SERVER_PASSWORD || crypto.randomBytes(24).toString("base64url"),
    serve: false,
    json: false,
    showSecrets: false,
    includeSecrets: false,
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === "--url" && argv[i + 1]) opts.url = argv[++i]
    else if (arg === "--port" && argv[i + 1]) opts.port = argv[++i]
    else if ((arg === "--bind" || arg === "--hostname") && argv[i + 1]) opts.bindHost = argv[++i]
    else if (arg === "--allow-lan-exposure") opts.allowLanExposure = true
    else if (arg === "--name" && argv[i + 1]) opts.name = argv[++i]
    else if (arg === "--user" && argv[i + 1]) opts.user = argv[++i]
    else if (arg === "--password" && argv[i + 1]) opts.password = argv[++i]
    else if (arg === "--serve") opts.serve = true
    else if (arg === "--json") opts.json = true
    else if (arg === "--show-secrets") opts.showSecrets = true
    else if (arg === "--include-secrets") opts.includeSecrets = true
  }
  return opts
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const opts = parseCliArgs(process.argv.slice(2))
  const safeBindHost = resolveBindHost(opts.bindHost, opts.allowLanExposure)
  const detected = opts.url
    ? { url: opts.url, source: "CLI --url" }
    : detectTailscaleHost(opts.port)

  const store = createPairingExchangeStore({
    url: detected.url,
    name: opts.name,
    username: opts.user,
    password: opts.password,
  })
  const metadata = store.getPublicMetadata()
  const qrAscii = renderQrTerminal(metadata.pairingUri)

  if (opts.json) {
    console.log(
      JSON.stringify(
        formatJsonSummary(metadata, opts.includeSecrets, { password: opts.password }),
        null,
        2,
      ),
    )
  } else {
    console.log(
      formatTerminalSummary({
        url: metadata.url,
        name: metadata.name,
        username: metadata.username,
        exp: metadata.exp,
        bindHost: safeBindHost,
        qrAscii,
        showSecrets: opts.showSecrets,
        password: opts.password,
      }),
    )
  }

  if (opts.serve) {
    const env = {
      ...process.env,
      OPENCODE_SERVER_USERNAME: opts.user,
      OPENCODE_SERVER_PASSWORD: opts.password,
    }
    const child = spawn(
      "opencode",
      ["serve", "--hostname", safeBindHost, "--port", opts.port],
      { stdio: "inherit", env },
    )
    child.on("exit", (code) => process.exit(code ?? 0))
  }
}
