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

test("MTProto: MTPROTO_SECRET parses into lowercase hex secrets; unset disables", () => {
  const disabled = loadConfig({});
  assert.deepEqual(disabled.mtprotoSecrets, []);
  assert.equal(disabled.mtprotoPort, 0);
  assert.equal(disabled.mtprotoMaxConnections, 64);

  const cfg = loadConfig({
    MTPROTO_SECRET: "ABCDEF0123456789ABCDEF0123456789,00112233445566778899aabbccddeeff",
    MTPROTO_PORT: "9443",
    MTPROTO_MAX_CONNECTIONS: "8",
  });
  assert.deepEqual(cfg.mtprotoSecrets, [
    "abcdef0123456789abcdef0123456789",
    "00112233445566778899aabbccddeeff",
  ]);
  assert.equal(cfg.mtprotoPort, 9443);
  assert.equal(cfg.mtprotoMaxConnections, 8);
  assert.equal(cfg.mtprotoHost, "YOUR_HOST_OR_IP");

  const withHost = loadConfig({
    MTPROTO_SECRET: "abcdef0123456789abcdef0123456789",
    MTPROTO_HOST: "  example.wispbyte.com  ",
  });
  assert.equal(withHost.mtprotoHost, "example.wispbyte.com");
});

test("MTProto: invalid MTPROTO_SECRET entries throw INVALID_ENV", () => {
  assert.throws(() => loadConfig({ MTPROTO_SECRET: "zz" }), /INVALID_ENV/);
  assert.throws(() => loadConfig({ MTPROTO_SECRET: "abcdef" }), /INVALID_ENV/); // too short
});

test("MTProto: whitespace and empties in MTPROTO_SECRET are trimmed away", () => {
  const cfg = loadConfig({
    MTPROTO_SECRET: " 00112233445566778899aabbccddeeff , , abcdef0123456789abcdef0123456789 ",
  });
  assert.deepEqual(cfg.mtprotoSecrets, [
    "00112233445566778899aabbccddeeff",
    "abcdef0123456789abcdef0123456789",
  ]);
});

test("invalid MAX_TUNNELS throws INVALID_ENV", () => {
  assert.throws(() => loadConfig({ MAX_TUNNELS: "x" }), /INVALID_ENV/);
});
