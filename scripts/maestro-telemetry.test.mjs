import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const flowsDir = path.resolve(__dirname, "../.maestro/flows");

test("Maestro flows handle telemetry-consent-card conditionally for private build ([CI-03])", () => {
  const files = fs.readdirSync(flowsDir).filter((f) => f.endsWith(".yaml"));
  assert.ok(files.length >= 7);
  for (const file of files) {
    const content = fs.readFileSync(path.join(flowsDir, file), "utf8");
    assert.equal(
      content.includes('- assertVisible:\n    id: "telemetry-consent-card"'),
      false,
      `${file} must not unconditionally assert telemetry-consent-card`,
    );
    assert.equal(
      content.includes('id: "telemetry-decline-button"\n    optional: true'),
      true,
      `${file} must mark telemetry-decline-button as optional: true`,
    );
  }
});
