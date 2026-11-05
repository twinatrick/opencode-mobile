import { describe, it } from "node:test"
import assert from "node:assert/strict"
import safeDecodeURIComponent from "./safe-decode-uri-component.js"

describe("safe-decode-uri-component", () => {
  it("decodes normal percent-encoded strings and pluses", () => {
    assert.equal(safeDecodeURIComponent("hello+world%21"), "hello world!")
    assert.equal(safeDecodeURIComponent("%E4%BD%A0%E5%A5%BD"), "你好")
  })

  it("gracefully handles malformed percent sequences in linear time without throwing", () => {
    assert.equal(safeDecodeURIComponent("%E0%A4%A"), "%E0%A4%A")
    assert.equal(safeDecodeURIComponent("test%2"), "test%2")
    const malicious = "%25".repeat(5000) + "%E0%A4%A"
    const start = Date.now()
    const out = safeDecodeURIComponent(malicious)
    const elapsedMs = Date.now() - start
    assert.ok(out.startsWith("%".repeat(5000)))
    assert.ok(elapsedMs < 200, `Expected linear-time execution < 200ms, took ${elapsedMs}ms`)
  })

  it("throws TypeError on non-string inputs", () => {
    assert.throws(() => safeDecodeURIComponent(null as unknown as string), TypeError)
  })
})
