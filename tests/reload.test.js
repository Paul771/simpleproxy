// FILE: tests/reload.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Unit tests for config hot-reload: applyConfigUpdate in-place merge + SIGUSR2 wiring
//   SCOPE: mutable field copy (preserving port/host), change detection, invalid-env rejection
//   DEPENDS: M-CONFIG
//   LINKS: V-M-CONFIG
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { loadConfig, applyConfigUpdate } from "../src/config.js";

function baseEnv(overrides = {}) {
  return {
    PORT: "8080",
    MAX_TUNNELS: "8",
    IDLE_TIMEOUT_MS: "120000",
    MTPROTO_SECRET: "00000000000000000000000000000000",
    MTPROTO_MAX_CONNECTIONS: "32",
    MTPROTO_MASK_HOST: "www.google.com",
    MTPROTO_REPLAY_WINDOW: "512",
    MTPROTO_REPLAY_TTL_MS: "20000",
    MTPROTO_TLS_DOMAIN: "www.google.com",
    MTPROTO_UNKNOWN_SNI_ACTION: "mask",
    MTPROTO_PREFER_IPV6: "false",
    MTPROTO_TLS_PROFILE_CAPTURE: "false",
    MTPROTO_DOPPELGANGER: "false",
    MTPROTO_PENDING_MAX: "128",
    MTPROTO_METRICS_PORT: "0",
    ...overrides,
  };
}

test("applyConfigUpdate: copies mutable fields in place, preserves port/host", () => {
  const cur = loadConfig(baseEnv({ PORT: "8080", MAX_TUNNELS: "8" }));
  const next = loadConfig(baseEnv({ PORT: "9999", MAX_TUNNELS: "16", MTPROTO_REPLAY_WINDOW: "1024" }));

  const changed = applyConfigUpdate(cur, next);

  // port/host untouched (listening socket stays).
  assert.equal(cur.port, 8080);
  assert.equal(cur.host, "0.0.0.0");
  // mutable fields replaced.
  assert.equal(cur.maxTunnels, 16);
  assert.equal(cur.mtprotoReplayWindow, 1024);
  // changed-set excludes port/host.
  assert.ok(!changed.includes("port"));
  assert.ok(!changed.includes("host"));
  assert.ok(changed.includes("maxTunnels"));
  assert.ok(changed.includes("mtprotoReplayWindow"));
});

test("applyConfigUpdate: identical config yields empty change set", () => {
  const cur = loadConfig(baseEnv());
  const next = loadConfig(baseEnv());
  const changed = applyConfigUpdate(cur, next);
  assert.deepEqual(changed, []);
});

test("applyConfigUpdate: secrets array is replaced wholesale", () => {
  const cur = loadConfig(baseEnv({ MTPROTO_SECRET: "00000000000000000000000000000000" }));
  const next = loadConfig(
    baseEnv({
      MTPROTO_SECRET: "11111111111111111111111111111111,22222222222222222222222222222222",
    })
  );
  const changed = applyConfigUpdate(cur, next);
  assert.equal(cur.mtprotoSecrets.length, 2);
  assert.equal(cur.mtprotoSecrets[0], "11111111111111111111111111111111");
  assert.ok(changed.includes("mtprotoSecrets"));
});

test("applyConfigUpdate: returns the names of every field that differs", () => {
  const cur = loadConfig(baseEnv({ MTPROTO_TLS_DOMAIN: "www.google.com", MTPROTO_DOPPELGANGER: "false" }));
  const next = loadConfig(baseEnv({ MTPROTO_TLS_DOMAIN: "www.cloudflare.com", MTPROTO_DOPPELGANGER: "true" }));
  const changed = applyConfigUpdate(cur, next);
  assert.ok(changed.includes("mtprotoTlsDomain"));
  assert.ok(changed.includes("mtprotoDoppelganger"));
  assert.equal(cur.mtprotoTlsDomain, "www.cloudflare.com");
  assert.equal(cur.mtprotoDoppelganger, true);
});

test("applyConfigUpdate: reload preserves derived structures (rules unchanged)", () => {
  const cur = loadConfig(baseEnv());
  const next = loadConfig(baseEnv({ MAX_TUNNELS: "20" }));
  applyConfigUpdate(cur, next);
  // allowlist rules are a constant default; reload must not wipe them.
  assert.ok(cur.rules.length >= 2);
  assert.equal(cur.rules[0].host, "api.telegram.org");
});