const SECRET_QUERY_KEYS =
  /([?&](?:token|access_token|api_key|key|password|pass|pwd|pw|auth|payload|enc|pin)=)[^&#\s"']*/gi;
const URL_IN_TEXT = /https?:\/\/[^\s)\]}"']+/gi;
const OPENCODE_DEEP_LINK_IN_TEXT = /opencode:\/\/[^\s)\]}"']+/gi;
const IPV4_IN_TEXT = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;

export function scrubUrl(raw: string): string {
  try {
    const u = new URL(raw);
    let out = raw;
    if (u.username || u.password) {
      out = out.replace(/\/\/[^/@]+@/, "//<redacted>@");
    }
    out = out.replace(SECRET_QUERY_KEYS, "$1<redacted>");
    return out;
  } catch {
    return raw
      .replace(/\/\/[^/@\s]+@/, "//<redacted>@")
      .replace(SECRET_QUERY_KEYS, "$1<redacted>");
  }
}

export function scrubString(s: string): string {
  return s
    .replace(OPENCODE_DEEP_LINK_IN_TEXT, "<redacted-url>")
    .replace(/https?:\/\/\S+/g, (m) => scrubUrl(m))
    .replace(SECRET_QUERY_KEYS, "$1<redacted>")
    .replace(/\b(Basic|Bearer)\s+[A-Za-z0-9._~+/=-]{4,}/gi, "$1 <redacted>");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function redactHostAndUrls(
  text: string,
  hosts?: Array<string | undefined>
): string {
  let out = scrubString(text).replace(URL_IN_TEXT, "<redacted-url>");
  for (const host of hosts || []) {
    const trimmed = host?.trim();
    if (!trimmed) continue;
    out = out.replace(new RegExp(escapeRegExp(trimmed), "gi"), "<redacted-host>");
  }
  return out.replace(IPV4_IN_TEXT, "<redacted-ip>");
}

export function scrubObject<T>(val: T): T {
  if (typeof val === "string") return scrubString(val) as unknown as T;
  if (Array.isArray(val)) return val.map((v) => scrubObject(v)) as unknown as T;
  if (val && typeof val === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (/^(password|pass|pwd|pw|token|authorization|auth|secret|api_key|apikey|payload|enc|pin)$/i.test(k)) {
        out[k] = "<redacted>";
      } else {
        out[k] = scrubObject(v);
      }
    }
    return out as T;
  }
  return val;
}
