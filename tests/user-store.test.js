// FILE: tests/user-store.test.js
// VERSION: 1.1.0
// START_MODULE_CONTRACT
//   PURPOSE: Unit tests for per-user secret management (multi-tenant limits + expiry + quota)
//   SCOPE: resolve-by-secret, admit/release concurrent-cap, expiry, byte-quota,
//          update() runtime swap for hot-reload (counter preservation)
//   DEPENDS: M-USER-STORE, M-CONFIG
//   LINKS: V-M-USER-STORE
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT
//
// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.1.0 - update() swap tests (W2-1): counters preserved by username on
//                reload, removed users drop out, changed limits take effect immediately;
//                MTPROTO_USERS_STRICT config parsing
// END_CHANGE_SUMMARY

import { test } from "node:test";
import assert from "node:assert/strict";
import { createUserStore } from "../src/user-store.js";
import { loadConfig } from "../src/config.js";

const SEC_A = "0000000000000000000000000000000a";
const SEC_B = "11111111111111111111111111111111b".slice(0, 32);
const SEC_B_HEX = "11111111111111111111111111111111";

function users(overrides = {}) {
  return [
    { user: "alice", secretHex: SEC_A, maxConns: 2, expiresAt: null, byteQuota: null },
    { user: "bob", secretHex: SEC_B_HEX, maxConns: null, expiresAt: null, byteQuota: 100 },
    { user: "default", secretHex: "22222222222222222222222222222222", maxConns: null, expiresAt: null, byteQuota: null },
    ...overrides.extra || [],
  ];
}

test("resolve: known secret hex -> user record, unknown -> null", () => {
  const s = createUserStore(users());
  assert.equal(s.resolve(SEC_A)?.user, "alice");
  assert.equal(s.resolve("deadbeefdeadbeefdeadbeefdeadbeef"), null);
});

test("admit: default user with no limits always admitted", () => {
  const s = createUserStore(users());
  const u = s.resolve("22222222222222222222222222222222");
  assert.ok(s.admit(u));
  s.release(u);
});

test("admit: per-user concurrent cap rejects beyond maxConns", () => {
  const s = createUserStore(users());
  const alice = s.resolve(SEC_A);
  assert.ok(s.admit(alice)); // 1
  assert.ok(s.admit(alice)); // 2
  assert.equal(s.admit(alice), false); // 3 -> rejected
  s.release(alice);
  assert.ok(s.admit(alice)); // back to 2 -> ok
  s.release(alice);
  s.release(alice);
});

test("admit: expired user is rejected", () => {
  const s = createUserStore([
    { user: "expired", secretHex: SEC_A, maxConns: null, expiresAt: Date.now() - 1000, byteQuota: null },
  ]);
  const u = s.resolve(SEC_A);
  assert.equal(s.admit(u), false);
});

test("admit: future-expiry user is admitted", () => {
  const s = createUserStore([
    { user: "future", secretHex: SEC_A, maxConns: null, expiresAt: Date.now() + 60_000, byteQuota: null },
  ]);
  const u = s.resolve(SEC_A);
  assert.ok(s.admit(u));
  s.release(u);
});

test("addBytes + byteQuota: admit rejected once cumulative quota exceeded", () => {
  const s = createUserStore(users());
  const bob = s.resolve(SEC_B_HEX);
  assert.ok(s.admit(bob));
  assert.equal(s.addBytes(bob, 60), true); // 60/100, ok
  s.release(bob);
  assert.ok(s.admit(bob));
  assert.equal(s.addBytes(bob, 50), false); // 110/100, over -> signal
  s.release(bob);
  // quota exceeded -> new admit rejected
  assert.equal(s.admit(bob), false);
});

test("config: parses user:secret and bare secret into mtprotoUsers", () => {
  const cfg = loadConfig({
    MTPROTO_SECRET: `alice:${SEC_A},bob:${SEC_B_HEX},${"33333333333333333333333333333333"}`,
  });
  assert.equal(cfg.mtprotoUsers.length, 3);
  assert.equal(cfg.mtprotoUsers[0].user, "alice");
  assert.equal(cfg.mtprotoUsers[0].secretHex, SEC_A);
  assert.equal(cfg.mtprotoUsers[1].user, "bob");
  assert.equal(cfg.mtprotoUsers[2].user, "default");
  // backward-compat: mtprotoSecrets still the hex list.
  assert.equal(cfg.mtprotoSecrets.length, 3);
  assert.equal(cfg.mtprotoSecrets[0], SEC_A);
});

test("config: applies MTPROTO_USER_MAX_CONNS / EXPIRATIONS / QUOTAS JSON", () => {
  const cfg = loadConfig({
    MTPROTO_SECRET: `alice:${SEC_A}`,
    MTPROTO_USER_MAX_CONNS: JSON.stringify({ alice: 5 }),
    MTPROTO_USER_EXPIRATIONS: JSON.stringify({ alice: "2099-01-01T00:00:00Z" }),
    MTPROTO_USER_QUOTAS: JSON.stringify({ alice: 2048 }),
  });
  const alice = cfg.mtprotoUsers[0];
  assert.equal(alice.maxConns, 5);
  assert.equal(alice.byteQuota, 2048);
  assert.ok(alice.expiresAt > Date.now()); // 2099 is in the future
});

test("config: malformed MTPROTO_SECRET user:secret still validates hex", () => {
  assert.throws(
    () => loadConfig({ MTPROTO_SECRET: "alice:not_hex_at_all" }),
    /INVALID_ENV/,
  );
});

// --- W2-1: update() runtime swap for SIGUSR2 hot-reload ---
test("update: preserves active and byte counters for surviving usernames", () => {
  const s = createUserStore(users());
  const alice = s.resolve(SEC_A);
  const bob = s.resolve(SEC_B_HEX);
  assert.ok(s.admit(alice)); // alice.active = 1
  assert.equal(s.addBytes(bob, 40), true); // bob.bytes = 40

  // "Reload": same users, new objects (fresh config parse) — counters must survive.
  s.update([
    { user: "alice", secretHex: SEC_A, maxConns: 2, expiresAt: null, byteQuota: null },
    { user: "bob", secretHex: SEC_B_HEX, maxConns: null, expiresAt: null, byteQuota: 100 },
    { user: "default", secretHex: "22222222222222222222222222222222", maxConns: null, expiresAt: null, byteQuota: null },
  ]);

  const snap = s.snapshot();
  assert.equal(snap.alice.active, 1, "active count must survive the swap");
  assert.equal(snap.bob.bytes, 40, "byte counter must survive the swap (quota must not reset)");
  // And enforcement still works on preserved state:
  assert.equal(s.addBytes(bob, 61), false); // 101/100
});

test("update: removed user stops resolving; stale object releases harmlessly", () => {
  const s = createUserStore(users());
  const bob = s.resolve(SEC_B_HEX);
  assert.ok(s.admit(bob));

  s.update([
    { user: "alice", secretHex: SEC_A, maxConns: null, expiresAt: null, byteQuota: null },
    { user: "default", secretHex: "22222222222222222222222222222222", maxConns: null, expiresAt: null, byteQuota: null },
  ]);

  assert.equal(s.resolve(SEC_B_HEX), null, "removed user's secret must stop resolving");
  s.release(bob); // in-flight connection closes after reload -> must not throw
  const snap = s.snapshot();
  assert.ok(!("bob" in snap), "removed user must vanish from snapshot");
});

test("update: added user starts at zero state; changed limits apply immediately", () => {
  const s = createUserStore(users().filter((u) => u.user !== "bob"));
  s.update([
    ...users().filter((u) => u.user !== "bob"),
    { user: "carol", secretHex: "33333333333333333333333333333333", maxConns: 1, expiresAt: null, byteQuota: 10 },
  ]);
  const carol = s.resolve("33333333333333333333333333333333");
  assert.ok(carol, "newly added user must resolve right after the swap");
  assert.ok(s.admit(carol));
  assert.equal(s.admit(carol), false, "maxConns=1 must be enforced immediately");
  s.release(carol);

  // Tighten bob's quota via swap: previously unlimited -> now capped.
  s.update(users().map((u) => (u.user === "default"
    ? { ...u, byteQuota: 5 }
    : u)));
  const def = s.resolve("22222222222222222222222222222222");
  assert.equal(s.addBytes(def, 6), false, "changed quota from the swapped table must take effect");
});

test("config: MTPROTO_USERS_STRICT parses as boolean flag (default off)", () => {
  assert.equal(loadConfig({ MTPROTO_SECRET: SEC_A }).mtprotoUsersStrict, false);
  assert.equal(loadConfig({ MTPROTO_SECRET: SEC_A, MTPROTO_USERS_STRICT: "1" }).mtprotoUsersStrict, true);
  assert.equal(loadConfig({ MTPROTO_SECRET: SEC_A, MTPROTO_USERS_STRICT: "true" }).mtprotoUsersStrict, true);
  assert.equal(loadConfig({ MTPROTO_SECRET: SEC_A, MTPROTO_USERS_STRICT: "no" }).mtprotoUsersStrict, false);
});