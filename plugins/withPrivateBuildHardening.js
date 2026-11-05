const fs = require("fs")
const path = require("path")
const { withAndroidManifest, withDangerousMod } = require("@expo/config-plugins")

const BLOCKED_PERMISSIONS = [
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.CAMERA",
  "android.permission.RECEIVE_BOOT_COMPLETED",
  "com.google.android.c2dm.permission.RECEIVE",
  "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE",
  "com.sec.android.provider.badge.permission.READ",
  "com.sec.android.provider.badge.permission.WRITE",
  "com.htc.launcher.permission.READ_SETTINGS",
  "com.htc.launcher.permission.UPDATE_SHORTCUT",
  "com.sonyericsson.home.permission.BROADCAST_BADGE",
  "com.sonymobile.home.permission.PROVIDER_INSERT_BADGE",
  "com.anddoes.launcher.permission.UPDATE_COUNT",
  "com.majeur.launcher.permission.UPDATE_BADGE",
  "com.huawei.android.launcher.permission.CHANGE_BADGE",
  "com.huawei.android.launcher.permission.READ_SETTINGS",
  "com.huawei.android.launcher.permission.WRITE_SETTINGS",
  "android.permission.READ_APP_BADGE",
  "com.oppo.launcher.permission.READ_SETTINGS",
  "com.oppo.launcher.permission.WRITE_SETTINGS",
  "me.everything.badger.permission.BADGE_COUNT_READ",
  "me.everything.badger.permission.BADGE_COUNT_WRITE",
]

const UNEXPORTED_COMPONENTS = [
  { tag: "activity", name: "com.canhub.cropper.CropImageActivity" },
]

const REMOVED_COMPONENTS = [
  { tag: "provider", name: "expo.modules.clipboard.ClipboardFileProvider" },
  { tag: "provider", name: "io.sentry.android.core.SentryInitProvider" },
  { tag: "provider", name: "io.sentry.android.core.SentryPerformanceProvider" },
  { tag: "provider", name: "com.google.firebase.provider.FirebaseInitProvider" },
  { tag: "service", name: "expo.modules.notifications.service.ExpoFirebaseMessagingService" },
  { tag: "service", name: "com.google.firebase.messaging.FirebaseMessagingService" },
  { tag: "service", name: "com.google.firebase.components.ComponentDiscoveryService" },
  { tag: "service", name: "com.google.android.datatransport.runtime.backends.TransportBackendDiscovery" },
  { tag: "service", name: "com.google.android.datatransport.runtime.scheduling.jobscheduling.JobInfoSchedulerService" },
  { tag: "receiver", name: "com.google.firebase.iid.FirebaseInstanceIdReceiver" },
  {
    tag: "receiver",
    name: "com.google.android.datatransport.runtime.scheduling.jobscheduling.AlarmManagerSchedulerBroadcastReceiver",
  },
]

const NETWORK_SECURITY_CONFIG_XML = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <!-- [MEDIUM-03] Global policy: forbid cleartext HTTP across all remote, CGNAT, and public networks. -->
  <!-- Remote/Tailscale servers should use HTTPS (e.g. tailscale serve --https=443 http://127.0.0.1:4096). -->
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors>
      <certificates src="system" />
    </trust-anchors>
  </base-config>
  <!-- Strictly scoped cleartext exceptions ONLY for local loopback and isolated container/emulator test hosts -->
  <domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">127.0.0.1</domain>
    <domain includeSubdomains="false">localhost</domain>
    <domain includeSubdomains="false">10.0.2.2</domain>
    <domain includeSubdomains="false">mock-opencode-primary</domain>
    <domain includeSubdomains="false">mock-opencode-secondary</domain>
  </domain-config>
</network-security-config>
`

function upsertComponentRule(appNode, tag, name, attrs) {
  if (!Array.isArray(appNode[tag])) {
    appNode[tag] = []
  }
  const existing = appNode[tag].find((item) => item?.$?.["android:name"] === name)
  if (existing) {
    existing.$ = { "android:name": name, ...attrs }
  } else {
    appNode[tag].push({
      $: {
        "android:name": name,
        ...attrs,
      },
    })
  }
}

function normalizeDeepLinkIntentFilters(appNode) {
  if (!Array.isArray(appNode.activity)) return
  for (const activity of appNode.activity) {
    if (!Array.isArray(activity["intent-filter"])) continue
    for (const filter of activity["intent-filter"]) {
      const actions = Array.isArray(filter.action) ? filter.action : []
      const isViewAction = actions.some(
        (a) => a?.$?.["android:name"] === "android.intent.action.VIEW",
      )
      if (!isViewAction) continue
      if (!Array.isArray(filter.category)) {
        filter.category = []
      }
      // [FUNCTIONAL BLOCKER-01]: Fix any upstream `android.intent.action.DEFAULT` typo
      // to `android.intent.category.DEFAULT` and ensure BROWSABLE + DEFAULT exist.
      for (const cat of filter.category) {
        if (cat?.$?.["android:name"] === "android.intent.action.DEFAULT") {
          cat.$["android:name"] = "android.intent.category.DEFAULT"
        }
      }
      const hasDefault = filter.category.some(
        (c) => c?.$?.["android:name"] === "android.intent.category.DEFAULT",
      )
      if (!hasDefault) {
        filter.category.push({ $: { "android:name": "android.intent.category.DEFAULT" } })
      }
      const hasBrowsable = filter.category.some(
        (c) => c?.$?.["android:name"] === "android.intent.category.BROWSABLE",
      )
      if (!hasBrowsable) {
        filter.category.push({ $: { "android:name": "android.intent.category.BROWSABLE" } })
      }
    }
  }
}

function hardenAndroidManifest(androidManifest) {
  const manifest = androidManifest.manifest
  if (!manifest) {
    throw new Error("Invalid AndroidManifest object: missing manifest root")
  }

  manifest.$ = manifest.$ || {}
  manifest.$["xmlns:android"] = manifest.$["xmlns:android"] || "http://schemas.android.com/apk/res/android"
  manifest.$["xmlns:tools"] = "http://schemas.android.com/tools"

  if (!Array.isArray(manifest["uses-permission"])) {
    manifest["uses-permission"] = []
  }

  for (const permission of BLOCKED_PERMISSIONS) {
    const existing = manifest["uses-permission"].find((item) => item?.$?.["android:name"] === permission)
    if (existing) {
      existing.$["tools:node"] = "remove"
    } else {
      manifest["uses-permission"].push({
        $: {
          "android:name": permission,
          "tools:node": "remove",
        },
      })
    }
  }

  if (!Array.isArray(manifest.application) || manifest.application.length === 0) {
    manifest.application = [{ $: {} }]
  }
  const appNode = manifest.application[0]
  appNode.$ = appNode.$ || {}
  appNode.$["android:allowBackup"] = "false"
  appNode.$["android:usesCleartextTraffic"] = "false"
  appNode.$["android:networkSecurityConfig"] = "@xml/network_security_config"

  normalizeDeepLinkIntentFilters(appNode)

  for (const comp of UNEXPORTED_COMPONENTS) {
    upsertComponentRule(appNode, comp.tag, comp.name, {
      "android:exported": "false",
      "tools:replace": "android:exported",
    })
  }

  for (const comp of REMOVED_COMPONENTS) {
    upsertComponentRule(appNode, comp.tag, comp.name, {
      "tools:node": "remove",
    })
  }

  return androidManifest
}

module.exports = (config) => {
  config = withAndroidManifest(config, (modConfig) => {
    modConfig.modResults = hardenAndroidManifest(modConfig.modResults)
    return modConfig
  })
  config = withDangerousMod(config, [
    "android",
    async (modConfig) => {
      const xmlDir = path.join(modConfig.modRequest.platformProjectRoot, "app/src/main/res/xml")
      fs.mkdirSync(xmlDir, { recursive: true })
      fs.writeFileSync(path.join(xmlDir, "network_security_config.xml"), NETWORK_SECURITY_CONFIG_XML, "utf8")
      const gradlePath = path.join(modConfig.modRequest.platformProjectRoot, "app/build.gradle")
      if (fs.existsSync(gradlePath)) {
        let gradle = fs.readFileSync(gradlePath, "utf8")
        gradle = gradle.replace(/^.*apply from:.*sentry\.gradle.*$/gm, "")
        if (!gradle.includes("libsentry.so")) {
          gradle = gradle.replace(
            /android\s*\{/,
            "android {\n    packagingOptions {\n        jniLibs {\n            excludes += [\"**/libsentry.so\", \"**/libsentry-android.so\"]\n        }\n    }"
          )
        }
        fs.writeFileSync(gradlePath, gradle, "utf8")
      }
      return modConfig
    },
  ])
  return config
}

module.exports.BLOCKED_PERMISSIONS = BLOCKED_PERMISSIONS
module.exports.UNEXPORTED_COMPONENTS = UNEXPORTED_COMPONENTS
module.exports.REMOVED_COMPONENTS = REMOVED_COMPONENTS
module.exports.NETWORK_SECURITY_CONFIG_XML = NETWORK_SECURITY_CONFIG_XML
module.exports.hardenAndroidManifest = hardenAndroidManifest
