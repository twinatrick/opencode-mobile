// Security helpers for Markdown and inline attachment rendering.
// Prevents remote tracking pixels / SSRF from auto-loading in chat bubbles
// and restricts external link openings to safe http/https schemes.

const SAFE_EXTERNAL_SCHEMES = new Set(["http:", "https:"])
const SAFE_INLINE_IMAGE_PREFIXES = ["data:image/", "file://", "content://"]

export function isSafeExternalLinkUrl(href: string | undefined | null): boolean {
  if (!href || typeof href !== "string") return false
  const trimmed = href.trim()
  if (!trimmed || trimmed.length > 2048) return false
  try {
    const parsed = new URL(trimmed)
    return SAFE_EXTERNAL_SCHEMES.has(parsed.protocol.toLowerCase())
  } catch {
    return false
  }
}

export function isAllowedInlineImageUri(uri: string | undefined | null): boolean {
  if (!uri || typeof uri !== "string") return false
  const trimmed = uri.trim().toLowerCase()
  if (!trimmed || trimmed.length > 10_000_000) return false
  return SAFE_INLINE_IMAGE_PREFIXES.some((prefix) => trimmed.startsWith(prefix))
}

export function formatBlockedMarkdownImagePlaceholder(alt?: string, uri?: string): string {
  const label = (alt || "").trim() || "remote image"
  if (!uri || typeof uri !== "string") {
    return `[Image blocked: ${label}]`
  }
  try {
    const parsed = new URL(uri.trim())
    return `[Image blocked (${parsed.protocol}//${parsed.host}): ${label}]`
  } catch {
    return `[Image blocked: ${label}]`
  }
}
