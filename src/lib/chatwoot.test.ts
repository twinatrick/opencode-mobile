import { test } from "node:test"
import assert from "node:assert/strict"
import { chatwootConfigured, sendSupportReport } from "./chatwoot.ts"

test("private build never uploads support data even with upstream credentials", async () => {
  process.env.EXPO_PUBLIC_CHATWOOT_INBOX_IDENTIFIER = "configured-by-mistake"
  process.env.EXPO_PUBLIC_CHATWOOT_BASE_URL = "https://support.example.com"
  let called = false
  assert.equal(chatwootConfigured(), false)
  assert.equal(await sendSupportReport("sensitive diagnostic", {
    fetchFn: async () => { called = true; throw new Error("unexpected network") },
    loadSourceId: async () => { throw new Error("must not read support identity") },
  }), false)
  assert.equal(called, false)
})
