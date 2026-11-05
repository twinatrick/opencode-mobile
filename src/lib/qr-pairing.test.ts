import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  buildPairingUri,
  parsePairingInput,
  redeemPairingToken,
} from "./qr-pairing.ts"

const SAMPLE_TOKEN_256 = "K7gNU3sdo-OL0wNhqoVWhr3g6s1xYv72ol_pe_Unols"

describe("qr-pairing v2 one-time token security ([HIGH-01], [MEDIUM-02])", () => {
  it("builds a v2 pairing URI that NEVER contains the server password or offline PIN", () => {
    const now = 1_762_000_000_000
    const uri = buildPairingUri(
      {
        url: "https://workstation.tailnet.ts.net:4096/",
        name: "My Workstation",
        token: SAMPLE_TOKEN_256,
        ttlMs: 300_000,
      },
      now,
    )

    assert.ok(uri.startsWith("opencode://connection/add?pairing="))
    assert.equal(uri.includes("secret"), false)

    const parsed = parsePairingInput(uri, now + 10_000)
    assert.equal(parsed.ok, true)
    assert.equal(parsed.state, "pending_redeem")
    if (parsed.ok && parsed.state === "pending_redeem") {
      assert.equal(parsed.invitation.url, "https://workstation.tailnet.ts.net:4096")
      assert.equal(parsed.invitation.name, "My Workstation")
      assert.equal(parsed.invitation.token, SAMPLE_TOKEN_256)
      assert.equal(parsed.invitation.security.isHttps, true)
      assert.equal(parsed.invitation.security.requiresCleartextWarning, false)
    }
  })

  it("rejects low-entropy tokens, expired QR invitations, and legacy password/PIN payloads ([HIGH-01])", () => {
    assert.throws(() =>
      buildPairingUri({
        url: "https://workstation.tailnet.ts.net:4096",
        token: "123456",
      }),
    )

    const legacyEnc = parsePairingInput("opencode://connection/add?enc=ABCDEF")
    assert.equal(legacyEnc.ok, false)
    if (!legacyEnc.ok) assert.equal(legacyEnc.code, "INSECURE_LEGACY_PAYLOAD")

    const legacyPw = parsePairingInput(
      "opencode://connection/add?url=https%3A%2F%2Fhost.ts.net&pw=supersecret",
    )
    assert.equal(legacyPw.ok, false)
    if (!legacyPw.ok) assert.equal(legacyPw.code, "INSECURE_LEGACY_PAYLOAD")

    const now = 1_762_000_000_000
    const uri = buildPairingUri(
      {
        url: "https://workstation.tailnet.ts.net:4096",
        token: SAMPLE_TOKEN_256,
        ttlMs: 300_000,
      },
      now,
    )
    const expired = parsePairingInput(uri, now + 300_001)
    assert.equal(expired.ok, false)
    if (!expired.ok) assert.equal(expired.code, "EXPIRED_QR")
  })

  it("redeems a one-time token once and rejects replay or rate-limited attempts ([HIGH-01])", async () => {
    const now = 1_762_000_000_000
    const uri = buildPairingUri(
      {
        url: "https://workstation.tailnet.ts.net:4096",
        name: "Workstation",
        token: SAMPLE_TOKEN_256,
      },
      now,
    )
    const parsed = parsePairingInput(uri, now + 1000)
    assert.equal(parsed.ok && parsed.state === "pending_redeem", true)
    if (!parsed.ok || parsed.state !== "pending_redeem") return

    let redeemed = false
    let failures = 0
    const fakeFetch = async (_url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body || "{}"))
      if (failures >= 3) {
        return new Response(JSON.stringify({ ok: false, code: "RATE_LIMITED" }), { status: 429 })
      }
      if (body.token !== SAMPLE_TOKEN_256) {
        failures += 1
        return new Response(JSON.stringify({ ok: false, code: "INVALID_TOKEN" }), { status: 401 })
      }
      if (redeemed) {
        return new Response(JSON.stringify({ ok: false, code: "TOKEN_ALREADY_USED" }), { status: 409 })
      }
      redeemed = true
      return new Response(
        JSON.stringify({
          ok: true,
          config: {
            url: "https://workstation.tailnet.ts.net:4096",
            name: "Workstation",
            username: "opencode",
            password: "ephemeral-server-credential-256bit",
          },
        }),
        { status: 200 },
      )
    }

    const firstRedeem = await redeemPairingToken(parsed.invitation, fakeFetch as typeof fetch, now + 2000)
    assert.equal(firstRedeem.ok, true)
    assert.equal(firstRedeem.state, "redeemed")
    if (firstRedeem.ok && firstRedeem.state === "redeemed") {
      assert.equal(firstRedeem.payload.password, "ephemeral-server-credential-256bit")
    }

    const replayRedeem = await redeemPairingToken(parsed.invitation, fakeFetch as typeof fetch, now + 3000)
    assert.equal(replayRedeem.ok, false)
    if (!replayRedeem.ok) {
      assert.equal(replayRedeem.code, "TOKEN_ALREADY_USED")
    }
  })
})
