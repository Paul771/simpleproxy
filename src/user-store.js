// FILE: src/user-store.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Per-user secret management: resolve-by-secret, concurrent-conn cap, expiry, byte-quota
//   SCOPE: multi-tenant limits over a list of {user, secretHex, maxConns, expiresAt, byteQuota}
//   DEPENDS: none
//   LINKS: M-USER-STORE
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createUserStore - build a stateful per-user admit/release/addBytes guard
// END_MODULE_MAP

// START_CONTRACT: createUserStore
//   PURPOSE: Build a stateful store that resolves a secret to a user and enforces per-user limits
//   INPUTS: { users: Array<{ user, secretHex, maxConns: number|null, expiresAt: number|null,
//                          byteQuota: number|null }> }
//   OUTPUTS: { resolve(hex): User|null, admit(user): boolean, release(user): void,
//             addBytes(user, n): boolean, snapshot(): Record }
//   SIDE_EFFECTS: maintains per-user active-conn and byte counters (stateful)
//   LINKS: M-USER-STORE
// END_CONTRACT: createUserStore
export function createUserStore(users = []) {
  // START_BLOCK_STORE
  const bySecret = new Map(users.map((u) => [u.secretHex.toLowerCase(), u]));
  const active = new Map(); // user -> active connection count
  const bytes = new Map(); // user -> cumulative bytes

  const resolve = (hex) => {
    if (typeof hex !== "string") return null;
    return bySecret.get(hex.toLowerCase()) ?? null;
  };

  const admit = (user) => {
    if (!user) return true; // no user record -> legacy/unlimited path
    if (user.expiresAt !== null && Date.now() > user.expiresAt) return false;
    if (user.byteQuota !== null && (bytes.get(user.user) ?? 0) >= user.byteQuota) return false;
    if (user.maxConns !== null) {
      const cur = active.get(user.user) ?? 0;
      if (cur >= user.maxConns) return false;
    }
    if (user.maxConns !== null) active.set(user.user, (active.get(user.user) ?? 0) + 1);
    return true;
  };

  const release = (user) => {
    if (!user || user.maxConns === null) return;
    const cur = active.get(user.user) ?? 0;
    if (cur <= 1) active.delete(user.user);
    else active.set(user.user, cur - 1);
  };

  const addBytes = (user, n) => {
    if (!user) return true;
    const total = (bytes.get(user.user) ?? 0) + n;
    bytes.set(user.user, total);
    return user.byteQuota === null ? true : total <= user.byteQuota;
  };

  const snapshot = () => {
    const out = {};
    for (const u of users) {
      out[u.user] = {
        active: active.get(u.user) ?? 0,
        bytes: bytes.get(u.user) ?? 0,
        maxConns: u.maxConns,
        byteQuota: u.byteQuota,
        expiresAt: u.expiresAt,
      };
    }
    return out;
  };

  return { resolve, admit, release, addBytes, snapshot };
  // END_BLOCK_STORE
}