import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  DEFAULT_BIND_HOST,
  buildPairingUri,
  createPairingExchangeStore,
  formatJsonSummary,
  formatTerminalSummary,
  generatePairingToken,
  renderQrSvg,
  renderQrTerminal,
  resolveBindHost,
} from "./opencode-qr.mjs"

describe("opencode-qr.mjs remediation verification ([HIGH-01], [MEDIUM-01], [MEDIUM-04])", () => {
  it("generates 256-bit one-time tokens, enforces single-use & rate limiting, and never puts password in QR ([HIGH-01])", () => {
    let now = 1_762_000_000_000
    const store = createPairingExchangeStore({
      url: "https://workstation.tailnet.ts.net",
      name: "Workstation",
      username: "opencode",
      password: "super-secret-long-term-password",
      maxFailedAttempts: 3,
      nowFn: () => now,
    })

    const meta = store.getPublicMetadata()
    assert.equal(meta.pairingUri.includes("super-secret-long-term-password"), false)

    // Wrong token attempts -> 401
    const bad1 = store.redeem(generatePairingToken())
    assert.equal(bad1.status, 401)
    assert.equal(bad1.body.code, "INVALID_TOKEN")

    // Valid token redemption -> 200 once
    const decoded = JSON.parse(
      Buffer.from(meta.pairingUri.split("pairing=")[1], "base64url").toString("utf8"),
    )
    assert.equal("password" in decoded, false)
    assert.equal("pw" in decoded, false)
    assert.ok(decoded.token.length >= 43)

    const okRedeem = store.redeem(decoded.token)
    assert.equal(okRedeem.status, 200)
    assert.equal(okRedeem.body.ok, true)
    assert.equal(okRedeem.body.config.password, "super-secret-long-term-password")

    // Second redemption with same token -> 409 TOKEN_ALREADY_USED
    const replay = store.redeem(decoded.token)
    assert.equal(replay.status, 409)
    assert.equal(replay.body.code, "TOKEN_ALREADY_USED")

    // Rotate and test rate-limit lockout
    const rotated = store.rotateToken()
    const rotatedToken = JSON.parse(
      Buffer.from(rotated.pairingUri.split("pairing=")[1], "base64url").toString("utf8"),
    ).token
    assert.equal(store.redeem("wrong-1").status, 401)
    assert.equal(store.redeem("wrong-2").status, 401)
    const rateLimited = store.redeem("wrong-3")
    assert.equal(rateLimited.status, 429)
    assert.equal(rateLimited.body.code, "RATE_LIMITED")

    // Even valid token is rejected once rate-limited
    const afterLockout = store.redeem(rotatedToken)
    assert.equal(afterLockout.status, 429)
    assert.equal(afterLockout.body.code, "RATE_LIMITED")
  })

  it("defaults bind host to 127.0.0.1 and rejects 0.0.0.0 wildcard exposure ([MEDIUM-01])", () => {
    assert.equal( DEFAULT_BIND_HOST, "127.0.0.1")
    assert.equal(resolveBindHost(), "127.0.0.1")
    assert.throws(() => resolveBindHost("0.0.0.0", false), /MEDIUM-01/)
    assert.throws(() => resolveBindHost("::", false), /MEDIUM-01/)
    assert.equal(resolveBindHost("0.0.0.0", true), "0.0.0.0")
  })

  it("redacts server password and raw secrets from terminal and JSON output by default ([MEDIUM-04])", () => {
    const token = generatePairingToken()
    const uri = buildPairingUri({
      url: "https://workstation.tailnet.ts.net",
      name: "Workstation",
      token,
    })
    const qrAscii = renderQrTerminal(uri)
    const qrSvg = renderQrSvg(uri)
    assert.ok(qrAscii.includes("█"))
    assert.ok(qrSvg.startsWith("<svg"))

    const termOut = formatTerminalSummary({
      url: "https://workstation.tailnet.ts.net",
      name: "Workstation",
      username: "opencode",
      exp: Date.now() + 300_000,
      qrAscii,
      showSecrets: false,
      password: "DO-NOT-PRINT-THIS-PASSWORD",
    })
    assert.equal(termOut.includes("DO-NOT-PRINT-THIS-PASSWORD"), false)
    assert.ok(termOut.includes("<redacted"))

    const jsonOut = formatJsonSummary(
      {
        url: "https://workstation.tailnet.ts.net",
        name: "Workstation",
        username: "opencode",
        iat: 1000,
        exp: 2000,
        consumed: false,
        pairingUri: uri,
      },
      false,
      { password: "DO-NOT-PRINT-THIS-PASSWORD" },
    )
    assert.equal("password" in jsonOut, false)
    assert.equal(jsonOut.passwordRedacted, true)
  })
})
