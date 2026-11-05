import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { assessConnectionSecurity, isCgnatIpv4, isTailscaleIpv4 } from "./connection-security.ts";

describe("connection-security assessment & biometric default", () => {
  it("enables requireBiometric and requireBiometricForMessages by default in auth.ts without hardcoded absolute paths", () => {
    const authFile = fileURLToPath(new URL("../stores/auth.ts", import.meta.url));
    const authSrc = fs.readFileSync(authFile, "utf8");
    assert.ok(authSrc.includes("requireBiometric: true"));
    assert.ok(authSrc.includes("requireBiometricForMessages: true"));
  });

  it("identifies RFC 6598 Shared CGNAT 100.64.0.0/10 IPv4 addresses", () => {
    assert.equal(isCgnatIpv4("100.64.0.1"), true);
    assert.equal(isTailscaleIpv4("100.101.202.3"), true);
    assert.equal(isCgnatIpv4("100.127.255.254"), true);
    assert.equal(isCgnatIpv4("100.63.255.255"), false);
    assert.equal(isCgnatIpv4("100.128.0.1"), false);
    assert.equal(isCgnatIpv4("192.168.1.50"), false);
  });

  it("does NOT trust CGNAT 100.64.0.0/10 or plain HTTP *.ts.net without HTTPS ([MEDIUM-02])", () => {
    const cgnatHttp = assessConnectionSecurity("http://100.101.102.103:4096", "secret");
    assert.equal(cgnatHttp.isCgnatIp, true);
    assert.equal(cgnatHttp.isHttps, false);
    assert.equal(cgnatHttp.isAuthenticatedTransport, false);
    assert.equal(cgnatHttp.requiresCleartextWarning, true);
    assert.equal(cgnatHttp.requiresEmptyPasswordWarning, false);

    const tsHttp = assessConnectionSecurity("http://workstation.tailnet.ts.net:4096", "secret");
    assert.equal(tsHttp.isTailscaleDomain, true);
    assert.equal(tsHttp.isHttps, false);
    assert.equal(tsHttp.requiresCleartextWarning, true);
  });

  it("trusts HTTPS connections (e.g. Tailscale Serve https://*.ts.net) and requires password", () => {
    const tsHttpsWithPw = assessConnectionSecurity("https://workstation.tailnet.ts.net:4096", "secret");
    assert.equal(tsHttpsWithPw.isHttps, true);
    assert.equal(tsHttpsWithPw.isTailscaleDomain, true);
    assert.equal(tsHttpsWithPw.isAuthenticatedTransport, true);
    assert.equal(tsHttpsWithPw.requiresCleartextWarning, false);
    assert.equal(tsHttpsWithPw.requiresEmptyPasswordWarning, false);

    const tsHttpsNoPw = assessConnectionSecurity("https://workstation.tailnet.ts.net:4096", "");
    assert.equal(tsHttpsNoPw.isHttps, true);
    assert.equal(tsHttpsNoPw.requiresCleartextWarning, false);
    assert.equal(tsHttpsNoPw.requiresEmptyPasswordWarning, true);
  });
});
