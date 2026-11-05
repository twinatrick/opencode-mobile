const assert = require("node:assert/strict")
const test = require("node:test")
const {
  BLOCKED_PERMISSIONS,
  UNEXPORTED_COMPONENTS,
  REMOVED_COMPONENTS,
  NETWORK_SECURITY_CONFIG_XML,
  hardenAndroidManifest,
} = require("./withPrivateBuildHardening")

test("hardens AndroidManifest permissions, exported components, deep-link categories, and network security config idempotently", () => {
  const input = {
    manifest: {
      $: { "xmlns:android": "http://schemas.android.com/apk/res/android" },
      "uses-permission": [{ $: { "android:name": "android.permission.INTERNET" } }],
      application: [
        {
          $: { "android:name": ".MainApplication" },
          activity: [
            {
              $: { "android:name": ".MainActivity", "android:exported": "true" },
              "intent-filter": [
                {
                  action: [{ $: { "android:name": "android.intent.action.VIEW" } }],
                  category: [
                    { $: { "android:name": "android.intent.category.BROWSABLE" } },
                    { $: { "android:name": "android.intent.action.DEFAULT" } },
                  ],
                  data: [{ $: { "android:scheme": "opencode" } }],
                },
              ],
            },
          ],
        },
      ],
    },
  }

  const hardened = hardenAndroidManifest(input)
  assert.equal(hardened.manifest.$["xmlns:tools"], "http://schemas.android.com/tools")
  assert.equal(hardened.manifest.application[0].$["android:allowBackup"], "false")
  assert.equal(hardened.manifest.application[0].$["android:usesCleartextTraffic"], "false")
  assert.equal(hardened.manifest.application[0].$["android:networkSecurityConfig"], "@xml/network_security_config")

  // Verify [FUNCTIONAL BLOCKER-01]: `android.intent.action.DEFAULT` corrected to `android.intent.category.DEFAULT`
  const mainActivity = hardened.manifest.application[0].activity.find(
    (a) => a.$["android:name"] === ".MainActivity",
  )
  const categories = mainActivity["intent-filter"][0].category.map((c) => c.$["android:name"])
  assert.ok(categories.includes("android.intent.category.DEFAULT"))
  assert.ok(categories.includes("android.intent.category.BROWSABLE"))
  assert.equal(categories.includes("android.intent.action.DEFAULT"), false)

  // Verify [MEDIUM-03]: Global cleartext forbidden; no blanket ts.net or 100.x cleartext exception
  assert.ok(NETWORK_SECURITY_CONFIG_XML.includes('<base-config cleartextTrafficPermitted="false">'))
  assert.equal(NETWORK_SECURITY_CONFIG_XML.includes("ts.net"), false)
  assert.equal(NETWORK_SECURITY_CONFIG_XML.includes("100.100.100.100"), false)

  for (const perm of BLOCKED_PERMISSIONS) {
    const entry = hardened.manifest["uses-permission"].find((p) => p.$["android:name"] === perm)
    assert.ok(entry, `Expected blocked permission ${perm}`)
    assert.equal(entry.$["tools:node"], "remove")
  }

  for (const comp of UNEXPORTED_COMPONENTS) {
    const list = hardened.manifest.application[0][comp.tag]
    const entry = list.find((c) => c.$["android:name"] === comp.name)
    assert.ok(entry, `Expected unexported component ${comp.name}`)
    assert.equal(entry.$["android:exported"], "false")
    assert.equal(entry.$["tools:replace"], "android:exported")
  }

  for (const comp of REMOVED_COMPONENTS) {
    const list = hardened.manifest.application[0][comp.tag]
    const entry = list.find((c) => c.$["android:name"] === comp.name)
    assert.ok(entry, `Expected removed component ${comp.name}`)
    assert.equal(entry.$["tools:node"], "remove")
  }

  const countBefore = hardened.manifest["uses-permission"].length
  const secondPass = hardenAndroidManifest(hardened)
  assert.equal(secondPass.manifest["uses-permission"].length, countBefore)
})
