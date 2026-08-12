// FILE: src/replay-guard.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Replay-attack protection: LRU+TTL of seen digests with timestamp-freshness check
//   SCOPE: admit-or-reject a client digest based on novelty, TTL and timestamp freshness
//   DEPENDS: none
//   LINKS: M-REPLAY
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createReplayGuard - build a stateful admit/reject guard over digests
// END_MODULE_MAP

// Timestamp occupies the last 4 bytes of a fake-TLS digest (little-endian, seconds since epoch).
const TS_OFFSET = 28;
const TS_LEN = 4;
const TS_FACTOR_MS = 1000;

// START_CONTRACT: createReplayGuard
//   PURPOSE: Build a stateful guard that admits fresh, novel digests and rejects replays / stale ones
//   INPUTS: { maxSize: number - LRU capacity (0 = disabled), ttlMs: number - max age of a seen entry,
//             freshnessMs: number - max |now - digest.timestamp| (0 = do not check) }
//   OUTPUTS: { admit(key: Buffer): boolean - true if fresh & novel (and added), false if replay/stale/disabled }
//   SIDE_EFFECTS: maintains an internal Map; schedules an unref'd cleanup interval
//   LINKS: M-REPLAY
// END_CONTRACT: createReplayGuard
export function createReplayGuard({ maxSize = 1024, ttlMs = 30_000, freshnessMs = 0 } = {}) {
  // START_BLOCK_GUARD
  const store = new Map(); // key: digestHex -> admittedAt(ms)
  let timer = null;

  const cleanup = () => {
    const now = Date.now();
    for (const [k, admittedAt] of store) {
      if (now - admittedAt > ttlMs) store.delete(k);
      else break; // Map keeps insertion order; once we hit a fresh entry, stop.
    }
  };

  if (maxSize > 0 && ttlMs > 0) {
    timer = setInterval(cleanup, Math.max(ttlMs, 1000));
    if (typeof timer.unref === "function") timer.unref();
  }

  const stop = () => {
    if (timer !== null) clearInterval(timer);
    timer = null;
  };

  const admit = (key) => {
    // START_BLOCK_ADMIT
    if (maxSize <= 0) return true; // disabled -> accept everything
    if (!Buffer.isBuffer(key) || key.length < TS_LEN) return true;

    // Freshness: reject digests whose embedded timestamp is out of window.
    if (freshnessMs > 0) {
      const ts = key.readUInt32LE(key.length - TS_LEN) * TS_FACTOR_MS;
      const skew = Math.abs(Date.now() - ts);
      if (skew > freshnessMs) return false;
    }

    const hex = key.toString("hex");
    const existing = store.get(hex);
    if (existing !== undefined) {
      // Lazy expiry: a digest seen past its TTL is treated as novel again.
      if (Date.now() - existing <= ttlMs) return false; // replay within window
      store.delete(hex);
    }

    // FIFO eviction on capacity overflow (Map preserves insertion order).
    if (store.size >= maxSize) {
      const oldest = store.keys().next().value;
      if (oldest !== undefined) store.delete(oldest);
    }
    store.set(hex, Date.now());
    return true;
    // END_BLOCK_ADMIT
  };

  return { admit, stop, get size() { return store.size; } };
  // END_BLOCK_GUARD
}