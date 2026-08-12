// FILE: tests/replay-guard.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-REPLAY LRU+TTL admit/reject semantics and timestamp freshness
//   SCOPE: novel digest admitted, duplicate rejected, TTL eviction, FIFO overflow, freshness window
//   DEPENDS: M-REPLAY
//   LINKS: V-M-REPLAY
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { createReplayGuard } from "../src/replay-guard.js";

function makeDigest(tsSec) {
  // 28 zero bytes + 4-byte LE timestamp -> mimics a fake-TLS digest.
  const d = Buffer.alloc(32);
  if (tsSec !== undefined) d.writeUInt32LE(tsSec, 28);
  return d;
}

test("replay-guard: disabled (maxSize 0) admits everything including duplicates", () => {
  const g = createReplayGuard({ maxSize: 0, ttlMs: 1000 });
  const d = makeDigest(123);
  assert.equal(g.admit(d), true);
  assert.equal(g.admit(d), true);
  g.stop();
});

test("replay-guard: novel digest admitted, duplicate rejected", () => {
  const g = createReplayGuard({ maxSize: 8, ttlMs: 60_000 });
  const d = makeDigest(Math.floor(Date.now() / 1000));
  assert.equal(g.admit(d), true);
  assert.equal(g.admit(d), false);
  assert.equal(g.size, 1);
  g.stop();
});

test("replay-guard: freshness rejects stale and future timestamps", () => {
  const g = createReplayGuard({ maxSize: 8, ttlMs: 60_000, freshnessMs: 10_000 });
  const now = Math.floor(Date.now() / 1000);
  const stale = makeDigest(now - 100); // 100s old -> outside 10s window
  const future = makeDigest(now + 100); // 100s ahead -> outside window
  const fresh = makeDigest(now);
  assert.equal(g.admit(stale), false);
  assert.equal(g.admit(future), false);
  assert.equal(g.admit(fresh), true);
  assert.equal(g.size, 1);
  g.stop();
});

test("replay-guard: FIFO eviction on capacity overflow", () => {
  const g = createReplayGuard({ maxSize: 2, ttlMs: 60_000 });
  const a = makeDigest(1);
  const b = makeDigest(2);
  const c = makeDigest(3);
  assert.equal(g.admit(a), true);
  assert.equal(g.admit(b), true);
  assert.equal(g.admit(c), true); // evicts a
  // a was evicted -> re-admitting it counts as novel again.
  assert.equal(g.admit(a), true);
  assert.equal(g.size, 2);
  g.stop();
});

test("replay-guard: TTL cleanup removes expired entries", async () => {
  const g = createReplayGuard({ maxSize: 8, ttlMs: 50, freshnessMs: 0 });
  const d = makeDigest(1);
  assert.equal(g.admit(d), true);
  await new Promise((r) => setTimeout(r, 120));
  // After TTL, the digest is gone from the store -> re-admit succeeds.
  assert.equal(g.admit(d), true);
  g.stop();
});

test("replay-guard: non-Buffer / too-short key is admitted (defensive)", () => {
  const g = createReplayGuard({ maxSize: 8, ttlMs: 60_000 });
  assert.equal(g.admit(null), true);
  assert.equal(g.admit(Buffer.alloc(2)), true);
  g.stop();
});