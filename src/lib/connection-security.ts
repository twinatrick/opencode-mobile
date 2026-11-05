export interface ConnectionSecurityAssessment {
  isHttps: boolean;
  isTailscaleDomain: boolean;
  /** RFC 6598 Shared CGNAT range (100.64.0.0/10). Not proof of Tailscale identity. */
  isCgnatIp: boolean;
  /** Backwards-compatible alias for CGNAT IP range check; never used to bypass HTTP warnings. */
  isTailscaleCgnatIp: boolean;
  isLoopback: boolean;
  isLoopbackOrEmulator: boolean;
  isAuthenticatedTransport: boolean;
  hasPassword: boolean;
  requiresCleartextWarning: boolean;
  requiresEmptyPasswordWarning: boolean;
  transportLabel: string;
}

/**
 * Checks whether an IPv4 address falls within RFC 6598 Shared Address Space (100.64.0.0/10).
 * NOTE: 100.64.0.0/10 is used by both Tailscale and carrier-grade NAT (CGNAT) ISPs.
 * An IP in this range does NOT authenticate the server or prove traffic is inside Tailscale.
 */
export function isCgnatIpv4(hostname: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!m) return false;
  const octets = m.slice(1).map((x) => Number(x));
  if (octets.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  return octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127;
}

export const isTailscaleIpv4 = isCgnatIpv4;

export function assessConnectionSecurity(
  rawUrl: string,
  password?: string
): ConnectionSecurityAssessment {
  let protocol = "http:";
  let hostname = "";
  try {
    const trimmed = rawUrl.trim();
    const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`;
    const parsed = new URL(withProto);
    protocol = parsed.protocol.toLowerCase();
    hostname = parsed.hostname.toLowerCase();
  } catch {
    hostname = "";
  }

  const isHttps = protocol === "https:";
  const isTailscaleDomain = hostname === "ts.net" || hostname.endsWith(".ts.net");
  const isCgnatIp = isCgnatIpv4(hostname);
  const isLoopback = hostname === "localhost" || hostname === "127.0.0.1";
  const isLoopbackOrEmulator =
    isLoopback ||
    hostname === "10.0.2.2" ||
    hostname === "mock-opencode-primary" ||
    hostname === "mock-opencode-secondary";

  const hasPassword = Boolean(password && password.trim().length > 0);

  // Security Policy ([MEDIUM-02]):
  // 1. CGNAT IPs (100.64.0.0/10) and *.ts.net over plain HTTP are NOT treated as verified/trusted.
  // 2. Only HTTPS (e.g. Tailscale Serve HTTPS with TLS certificate verification) or local loopback
  //    is exempt from cleartext HTTP warnings.
  const isAuthenticatedTransport = isHttps;
  const requiresCleartextWarning = !isHttps && !isLoopback;
  const requiresEmptyPasswordWarning = !hasPassword;

  let transportLabel = "Cleartext HTTP (Unverified — Use HTTPS)";
  if (isHttps && isTailscaleDomain) {
    transportLabel = "Tailscale HTTPS (*.ts.net TLS Verified)";
  } else if (isHttps) {
    transportLabel = "HTTPS (TLS Encrypted)";
  } else if (isLoopback) {
    transportLabel = "Local Loopback (127.0.0.1 / localhost)";
  } else if (isCgnatIp) {
    transportLabel = "Cleartext HTTP over CGNAT IP (Unverified — Prefer Tailscale HTTPS)";
  } else if (isTailscaleDomain) {
    transportLabel = "Cleartext HTTP on *.ts.net (Unencrypted — Prefer Tailscale HTTPS)";
  }

  return {
    isHttps,
    isTailscaleDomain,
    isCgnatIp,
    isTailscaleCgnatIp: isCgnatIp,
    isLoopback,
    isLoopbackOrEmulator,
    isAuthenticatedTransport,
    hasPassword,
    requiresCleartextWarning,
    requiresEmptyPasswordWarning,
    transportLabel,
  };
}
