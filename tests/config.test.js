// FILE: tests/config.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-CONFIG env parsing and validation
//   SCOPE: defaults, PORT parsing, auth credentials, invalid env
//   DEPENDS: M-CONFIG
//   LINKS: V-M-CONFIG
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { loadConfig } from "../src/config.js";

test("defaults: port 8080, host 0.0.0.0, maxTunnels 32, idle 120000", () => {
  const cfg = loadConfig({});
  assert.equal(cfg.port, 8080);
  assert.equal(cfg.host, "0.0.0.0");
  assert.equal(cfg.maxTunnels, 32);
  assert.equal(cfg.idleTimeoutMs, 120_000);
  assert.equal(cfg.creds, null);
});

test("PORT is picked up from env", () => {
  const cfg = loadConfig({ PORT: "9000" });
  assert.equal(cfg.port, 9000);
});

test("MAX_TUNNELS and IDLE_TIMEOUT_MS are picked up", () => {
  const cfg = loadConfig({ MAX_TUNNELS: "4", IDLE_TIMEOUT_MS: "5000" });
  assert.equal(cfg.maxTunnels, 4);
  assert.equal(cfg.idleTimeoutMs, 5000);
});

test("allowlist rules default to exact api.telegram.org + suffix .telegram.org", () => {
  const cfg = loadConfig({});
  const types = cfg.rules.map((r) => r.type).sort();
  assert.deepEqual(types, ["exact", "suffix"]);
  assert.ok(cfg.rules.some((r) => r.type === "exact" && r.host === "api.telegram.org"));
  assert.ok(cfg.rules.some((r) => r.type === "suffix" && r.host === ".telegram.org"));
});

test("auth enabled only when BOTH PROXY_USER and PROXY_PASS are set", () => {
  const both = loadConfig({ PROXY_USER: "u", PROXY_PASS: "p" });
  assert.deepEqual(both.creds, { user: "u", pass: "p" });

  const userOnly = loadConfig({ PROXY_USER: "u" });
  assert.equal(userOnly.creds, null);

  const passOnly = loadConfig({ PROXY_PASS: "p" });
  assert.equal(passOnly.creds, null);

  const empty = loadConfig({ PROXY_USER: "", PROXY_PASS: "" });
  assert.equal(empty.creds, null);
});

test("invalid PORT throws INVALID_ENV", () => {
  assert.throws(() => loadConfig({ PORT: "abc" }), /INVALID_ENV/);
  assert.throws(() => loadConfig({ PORT: "0" }), /INVALID_ENV/);
  assert.throws(() => loadConfig({ PORT: "-5" }), /INVALID_ENV/);
  assert.throws(() => loadConfig({ PORT: "80.5" }), /INVALID_ENV/);
});

test("invalid MAX_TUNNELS throws INVALID_ENV", () => {
  assert.throws(() => loadConfig({ MAX_TUNNELS: "x" }), /INVALID_ENV/);
});
