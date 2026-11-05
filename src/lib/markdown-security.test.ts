import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  isSafeExternalLinkUrl,
  isAllowedInlineImageUri,
  formatBlockedMarkdownImagePlaceholder,
} from "./markdown-security.ts"

describe("markdown-security", () => {
  it("allows only http and https external links", () => {
    assert.equal(isSafeExternalLinkUrl("https://tailscale.com/kb"), true)
    assert.equal(isSafeExternalLinkUrl("http://peer.tailnet.ts.net:4096"), true)
    assert.equal(isSafeExternalLinkUrl("javascript:alert(1)"), false)
    assert.equal(isSafeExternalLinkUrl("opencode://session/123"), false)
    assert.equal(isSafeExternalLinkUrl("intent://scan/#Intent;end"), false)
    assert.equal(isSafeExternalLinkUrl(""), false)
  })

  it("blocks remote http/https tracking pixels from inline auto-loading", () => {
    assert.equal(isAllowedInlineImageUri("https://attacker.example.com/pixel.png"), false)
    assert.equal(isAllowedInlineImageUri("http://100.64.0.1:4096/internal.png"), false)
    assert.equal(isAllowedInlineImageUri("data:image/png;base64,iVBORw0KGgo="), true)
    assert.equal(isAllowedInlineImageUri("file:///data/user/0/cc.agentlabs.opencode/cache/img.jpg"), true)
    assert.equal(isAllowedInlineImageUri("content://media/external/images/media/1"), true)
  })

  it("formats blocked remote image placeholders with host information", () => {
    assert.equal(
      formatBlockedMarkdownImagePlaceholder("tracker", "https://evil.example.com/p.gif"),
      "[Image blocked (https://evil.example.com): tracker]",
    )
  })
})
