const path = require("path")
const { getDefaultConfig } = require("expo/metro-config")

/**
 * Private Build Metro Configuration
 *
 * 1. Uses Expo standard Metro config instead of `@sentry/react-native/metro` so
 *    Sentry debug-ID injection and telemetry polyfills are excluded from the
 *    compiled Hermes bundle (`index.android.bundle`).
 * 2. Redirects `decode-uri-component` to `src/lib/safe-decode-uri-component.js`
 *    so the vulnerable `node_modules/decode-uri-component@0.2.2` package is
 *    never bundled into the Android APK.
 */
const config = getDefaultConfig(__dirname)

const SAFE_DECODE_PATH = path.resolve(__dirname, "src/lib/safe-decode-uri-component.js")
const upstreamResolveRequest = config.resolver?.resolveRequest

config.resolver = {
  ...config.resolver,
  resolveRequest(context, moduleName, platform) {
    if (moduleName === "decode-uri-component") {
      return {
        filePath: SAFE_DECODE_PATH,
        type: "sourceFile",
      }
    }
    if (upstreamResolveRequest) {
      return upstreamResolveRequest(context, moduleName, platform)
    }
    return context.resolveRequest(context, moduleName, platform)
  },
}

module.exports = config
