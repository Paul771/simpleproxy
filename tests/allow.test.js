// FILE: tests/allow.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-ALLOW parsing and allowlist checks
//   SCOPE: normalizeTarget edge cases, isAllowed rule matching
//   DEPENDS: M-ALLOW
//   LINKS: V-M-ALLOW
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeTarget, isAllowed } from "../src/allow.js";

const RULES = [
  { type: "exact", host: "api.telegram.org" },
  { type: "suffix", host: ".telegram.org" },
];

test("normalizeTarget: valid authority", () => {
  assert.deepEqual(normalizeTarget("api.telegram.org:443"), { host: "api.telegram.org", port: 443 });
  assert.deepEqual(normalizeTarget("core.telegram.org:443"), { host: "core.telegram.org", port: 443 });
});

test("normalizeTarget: rejects malformed authorities", () => {
  assert.equal(normalizeTarget(""), null);
  assert.equal(normalizeTarget("user@host:443"), null);
  assert.equal(normalizeTarget("host:443:5"), null);
  assert.equal(normalizeTarget("[::1]:443"), null);
  assert.equal(normalizeTarget("host:abc"), null);
  assert.equal(normalizeTarget("host:"), null);
  assert.equal(normalizeTarget(":443"), null);
  assert.equal(normalizeTarget(null), null);
  assert.equal(normalizeTarget(undefined), null);
});

test("isAllowed: telegram hosts pass on 443", () => {
  assert.equal(isAllowed(normalizeTarget("api.telegram.org:443"), RULES), true);
  assert.equal(isAllowed(normalizeTarget("core.telegram.org:443"), RULES), true);
  assert.equal(isAllowed(normalizeTarget("updates.telegram.org:443"), RULES), true);
});

test("isAllowed: non-telegram and wrong-port rejected", () => {
  assert.equal(isAllowed(normalizeTarget("example.com:443"), RULES), false);
  assert.equal(isAllowed(normalizeTarget("api.telegram.org:80"), RULES), false);
  assert.equal(isAllowed(normalizeTarget("telegram.org:443"), RULES), false); // bare domain not covered by suffix
  assert.equal(isAllowed(null, RULES), false);
});

test("isAllowed: trailing-dot and casing cannot bypass", () => {
  // Trailing dot is stripped during normalization, so it resolves to the exact host.
  assert.deepEqual(normalizeTarget("api.telegram.org.:443"), { host: "api.telegram.org", port: 443 });
  // Uppercase is normalized to lowercase during parsing.
  assert.deepEqual(normalizeTarget("API.TELEGRAM.ORG:443"), { host: "api.telegram.org", port: 443 });
  // Normalization does not let a non-telegram host through.
  assert.equal(isAllowed(normalizeTarget("example.com:443"), RULES), false);
});
