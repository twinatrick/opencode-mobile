/**
 * Safe linear-time replacement for `decode-uri-component@0.2.2`.
 *
 * Eliminates GHSA-vcc3-ghjq-m6fr and GHSA-qr28-fpjm-wq7f (exponential/quadratic
 * backtracking on malformed percent-encoded sequences) while preserving the
 * CommonJS `decodeComponent(encodedURI)` contract expected by `query-string`.
 */
const TOKEN_RE = /%[a-fA-F0-9]{2}/g

function safeDecodeURIComponent(encodedURI) {
  if (typeof encodedURI !== "string") {
    throw new TypeError("Expected `encodedURI` to be of type `string`, got `" + typeof encodedURI + "`")
  }
  if (encodedURI.length === 0) return ""

  // Convert `+` to space per application/x-www-form-urlencoded convention used by decode-uri-component
  const input = encodedURI.replace(/\+/g, " ")

  try {
    return decodeURIComponent(input)
  } catch {
    // Linear single-pass fallback: decode valid UTF-8 percent-encoded sequences
    // byte-by-byte without recursive multi-pass regex replacement.
    return input.replace(/(?:%[a-fA-F0-9]{2})+/g, (match) => {
      try {
        return decodeURIComponent(match)
      } catch {
        // Decode individual single-byte hex tokens that are valid ASCII, keep invalid ones literal
        return match.replace(TOKEN_RE, (byteToken) => {
          try {
            return decodeURIComponent(byteToken)
          } catch {
            return byteToken
          }
        })
      }
    })
  }
}

module.exports = safeDecodeURIComponent
module.exports.default = safeDecodeURIComponent
