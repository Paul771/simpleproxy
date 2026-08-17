// FILE: src/config.js
// VERSION: 1.1.0
// START_MODULE_CONTRACT
//   PURPOSE: Read env and return a validated proxy configuration
//   SCOPE: env parsing, defaults, allowlist rule construction, auth credentials, MTProto settings
//   DEPENDS: M-BLOCKLIST
//   LINKS: M-CONFIG
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   loadConfig - load and validate config from env
// END_MODULE_MAP

import { createBlocklist } from "./blocklist.js";

// START_BLOCK_ALLOW_RULES
// Telegram Bot API endpoints and subdomains. Port is always 443.
const DEFAULT_RULES = [
  { type: "exact", host: "api.telegram.org" },
  { type: "suffix", host: ".telegram.org" },
];
// END_BLOCK_ALLOW_RULES

function parseIntEnv(value, fallback, name) {
  if (value === undefined || value === "") return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) {
    throw new Error(`INVALID_ENV: ${name} must be a positive integer, got "${value}"`);
  }
  return n;
}

// Port-style integer: 0 means "disabled" and is always allowed.
function parsePortEnv(value, fallback, name) {
  if (value === undefined || value === "") return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`INVALID_ENV: ${name} must be a non-negative integer, got "${value}"`);
  }
  return n;
}

// Parse a JSON object env var. Empty/absent -> fallback. Throws INVALID_ENV on bad JSON / non-object.
function parseJsonEnv(value, fallback, name) {
  if (value === undefined || value === "" || value == null) return fallback;
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`INVALID_ENV: ${name} must be valid JSON, got "${value}"`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`INVALID_ENV: ${name} must be a JSON object, got "${value}"`);
  }
  return parsed;
}

// Accept ISO-8601 string or epoch-ms number; null when absent. NaN -> throws.
function parseExpiry(value) {
  if (value == null || value === "") return null;
  const ms = typeof value === "number" ? value : Date.parse(value);
  if (!Number.isFinite(ms)) {
    throw new Error(`INVALID_ENV: MTPROTO_USER_EXPIRATIONS entry must be ISO-8601 or epoch-ms, got "${value}"`);
  }
  return ms;
}

// START_CONTRACT: loadConfig
//   PURPOSE: Read env and return validated config
//   INPUTS: { env: Record<string, string | undefined> - environment (default process.env) }
//   OUTPUTS: { Config - { port, host, maxTunnels, idleTimeoutMs, authUser, authPass, creds, rules,
//                          mtprotoSecrets, mtprotoPort, mtprotoMaxConnections, mtprotoHost,
//                          mtprotoTlsDomain, mtprotoTlsAlpn, mtprotoMaskHost, mtprotoMaskPort,
//                          mtprotoUnknownSniAction, mtprotoReplayWindow, mtprotoReplayTtlMs,
//                          mtprotoDigestFreshnessMs, mtprotoPreferIpv6,
//                          mtprotoTlsProfileCapture, mtprotoTlsProfileRefreshMs, mtprotoTlsProfileTimeoutMs,
//                          mtprotoDoppelganger, mtprotoDoppelgangerMaxDelayMs,
//                          mtprotoMetricsPort, mtprotoMetricsHost } }
//   SIDE_EFFECTS: none
//   LINKS: M-CONFIG
// END_CONTRACT: loadConfig
export function loadConfig(env = process.env) {
  const port = parseIntEnv(env.PORT, 8080, "PORT");
  const maxTunnels = parseIntEnv(env.MAX_TUNNELS, 32, "MAX_TUNNELS");
  const idleTimeoutMs = parseIntEnv(env.IDLE_TIMEOUT_MS, 120_000, "IDLE_TIMEOUT_MS");

  const authUser = env.PROXY_USER && env.PROXY_USER !== "" ? env.PROXY_USER : null;
  const authPass = env.PROXY_PASS && env.PROXY_PASS !== "" ? env.PROXY_PASS : null;
  // Auth is enabled only when BOTH user and pass are provided.
  const creds = authUser !== null && authPass !== null ? { user: authUser, pass: authPass } : null;

  // MTProto secrets: comma-separated entries, each "user:secret" or just "secret".
  // A bare secret maps to the "default" user. MTPROTO_SECRET unset/empty -> listener disabled.
  let mtprotoUsers = [];
  if (env.MTPROTO_SECRET && env.MTPROTO_SECRET.trim() !== "") {
    const rawEntries = env.MTPROTO_SECRET.split(",").map((s) => s.trim()).filter((s) => s !== "");
    mtprotoUsers = rawEntries.map((entry) => {
      const colon = entry.indexOf(":");
      let user, secretHex;
      if (colon > 0) {
        user = entry.slice(0, colon).trim();
        secretHex = entry.slice(colon + 1).trim().toLowerCase();
      } else {
        user = "default";
        secretHex = entry.toLowerCase();
      }
      if (!/^[0-9a-f]{32}$/.test(secretHex)) {
        throw new Error(`INVALID_ENV: MTPROTO_SECRET entries must be 32 hex chars, got "${secretHex}"`);
      }
      return { user, secretHex };
    });
  }
  const mtprotoSecrets = mtprotoUsers.map((u) => u.secretHex);

  // --- Per-user limits (multi-tenant): JSON maps keyed by user name. ---
  const userMaxConns = parseJsonEnv(env.MTPROTO_USER_MAX_CONNS, {}, "MTPROTO_USER_MAX_CONNS");
  const userExpirations = parseJsonEnv(env.MTPROTO_USER_EXPIRATIONS, {}, "MTPROTO_USER_EXPIRATIONS");
  const userQuotas = parseJsonEnv(env.MTPROTO_USER_QUOTAS, {}, "MTPROTO_USER_QUOTAS");
  mtprotoUsers = mtprotoUsers.map((u) => ({
    user: u.user,
    secretHex: u.secretHex,
    maxConns: userMaxConns[u.user] != null ? Number(userMaxConns[u.user]) : null,
    expiresAt: parseExpiry(userExpirations[u.user]),
    byteQuota: userQuotas[u.user] != null ? Number(userQuotas[u.user]) : null,
  }));

  const mtprotoPort = parseIntEnv(env.MTPROTO_PORT, 0, "MTPROTO_PORT");
  const mtprotoMaxConnections = parseIntEnv(
    env.MTPROTO_MAX_CONNECTIONS,
    64,
    "MTPROTO_MAX_CONNECTIONS"
  );
  // Slowloris guard: cap sockets still in the MTProto handshake phase (before relay).
  const mtprotoPendingMax = parseIntEnv(
    env.MTPROTO_PENDING_MAX,
    256,
    "MTPROTO_PENDING_MAX"
  );
  // Public host shown in tg://proxy links. Falls back to the listen port's hint.
  const mtprotoHost =
    env.MTPROTO_HOST && env.MTPROTO_HOST.trim() !== "" ? env.MTPROTO_HOST.trim() : "YOUR_HOST_OR_IP";
  // Domain used for fake-TLS (ee-secret) SNI masking. Picked to look plausible from the host IP.
  const mtprotoTlsDomain =
    env.MTPROTO_TLS_DOMAIN && env.MTPROTO_TLS_DOMAIN.trim() !== ""
      ? env.MTPROTO_TLS_DOMAIN.trim()
      : "www.google.com";

  // --- Anti-DPI settings (see docs/Architecture, telemt-inspired) ---
  // ALPN advertised in the fake ServerHello. First entry = negotiated protocol.
  const mtprotoTlsAlpn =
    env.MTPROTO_TLS_ALPN && env.MTPROTO_TLS_ALPN.trim() !== ""
      ? env.MTPROTO_TLS_ALPN.split(",")
          .map((s) => s.trim())
          .filter((s) => s !== "")
      : ["h2", "http/1.1"];
  // Real upstream a non-keyed / unknown-SNI client is transparently spliced to (traffic masking).
  const mtprotoMaskHost =
    env.MTPROTO_MASK_HOST && env.MTPROTO_MASK_HOST.trim() !== ""
      ? env.MTPROTO_MASK_HOST.trim()
      : mtprotoTlsDomain;
  const mtprotoMaskPort = parseIntEnv(env.MTPROTO_MASK_PORT, 443, "MTPROTO_MASK_PORT");
  // Behaviour on unknown SNI / failed fake-TLS auth: "mask" (splice to mask_host, default),
  // "reject" (emit TLS unrecognized_name alert + close), "drop" (destroy, legacy behaviour).
  const mtprotoUnknownSniAction = parseActionEnv(env.MTPROTO_UNKNOWN_SNI_ACTION, "mask");
  // Replay protection: LRU capacity (0 = disabled) and TTL of seen digests.
  const mtprotoReplayWindow = parseIntEnv(env.MTPROTO_REPLAY_WINDOW, 1024, "MTPROTO_REPLAY_WINDOW");
  const mtprotoReplayTtlMs = parseIntEnv(env.MTPROTO_REPLAY_TTL_MS, 30_000, "MTPROTO_REPLAY_TTL_MS");
  // Max skew between now and the digest-embedded timestamp (0 = lenient, accept any).
  const mtprotoDigestFreshnessMs = parseIntEnv(
    env.MTPROTO_DIGEST_FRESHNESS_MS,
    0,
    "MTPROTO_DIGEST_FRESHNESS_MS"
  );
  // Prefer IPv6 Telegram DC addresses when resolving dc_idx.
  const mtprotoPreferIpv6 = parseBoolEnv(env.MTPROTO_PREFER_IPV6, false);

  // --- TLS profile capture & replay (Phase 2 anti-DPI, telemt-inspired) ---
  // When enabled, the fake ServerHello replays the record structure captured from mtprotoTlsDomain.
  const mtprotoTlsProfileCapture = parseBoolEnv(env.MTPROTO_TLS_PROFILE_CAPTURE, false);
  const mtprotoTlsProfileRefreshMs = parseIntEnv(
    env.MTPROTO_TLS_PROFILE_REFRESH_MS,
    600_000,
    "MTPROTO_TLS_PROFILE_REFRESH_MS"
  );
  const mtprotoTlsProfileTimeoutMs = parseIntEnv(
    env.MTPROTO_TLS_PROFILE_TIMEOUT_MS,
    5000,
    "MTPROTO_TLS_PROFILE_TIMEOUT_MS"
  );
  // Doppelganger: replay captured inter-arrival delays of the server flight when sending the
  // fake ServerHello (statistical indistinguishability). Requires a captured profile.
  const mtprotoDoppelganger = parseBoolEnv(env.MTPROTO_DOPPELGANGER, false);
  const mtprotoDoppelgangerMaxDelayMs = parseIntEnv(
    env.MTPROTO_DOPPELGANGER_MAX_DELAY_MS,
    500,
    "MTPROTO_DOPPELGANGER_MAX_DELAY_MS"
  );

  // --- Observability: Prometheus metrics side-port (off by default = 0). ---
  const mtprotoMetricsPort = parsePortEnv(env.MTPROTO_METRICS_PORT, 0, "MTPROTO_METRICS_PORT");
  const mtprotoMetricsHost =
    env.MTPROTO_METRICS_HOST && env.MTPROTO_METRICS_HOST.trim() !== ""
      ? env.MTPROTO_METRICS_HOST.trim()
      : "0.0.0.0";

  // --- Client-IP blocklist (edge reject). Comma-separated CIDRs or bare IPs (IPv4/IPv6).
  // Validated eagerly via createBlocklist so an invalid entry fails at load (INVALID_ENV).
  // We store the raw validated strings (not the runtime object) so hot-reload deep-equality
  // works and index.js owns runtime-object construction (same pattern as replay/profile/metrics).
  let mtprotoBlocklist = [];
  if (env.MTPROTO_BLOCKLIST && env.MTPROTO_BLOCKLIST.trim() !== "") {
    const entries = env.MTPROTO_BLOCKLIST.split(",").map((s) => s.trim()).filter((s) => s !== "");
    if (entries.length > 0) {
      try {
        createBlocklist(entries); // validate (throws on bad entry)
      } catch (err) {
        throw new Error(err.message);
      }
      mtprotoBlocklist = entries;
    }
  }

  return {
    port,
    host: "0.0.0.0",
    maxTunnels,
    idleTimeoutMs,
    authUser,
    authPass,
    creds,
    rules: DEFAULT_RULES,
    mtprotoSecrets,
    mtprotoUsers,
    mtprotoPort,
    mtprotoMaxConnections,
    mtprotoPendingMax,
    mtprotoHost,
    mtprotoTlsDomain,
    mtprotoTlsAlpn,
    mtprotoMaskHost,
    mtprotoMaskPort,
    mtprotoUnknownSniAction,
    mtprotoReplayWindow,
    mtprotoReplayTtlMs,
    mtprotoDigestFreshnessMs,
    mtprotoPreferIpv6,
    mtprotoTlsProfileCapture,
    mtprotoTlsProfileRefreshMs,
    mtprotoTlsProfileTimeoutMs,
    mtprotoDoppelganger,
    mtprotoDoppelgangerMaxDelayMs,
    mtprotoMetricsPort,
    mtprotoMetricsHost,
    mtprotoBlocklist,
  };
}

function parseActionEnv(value, fallback) {
  if (value === undefined || value === "") return fallback;
  const v = value.trim().toLowerCase();
  if (v !== "mask" && v !== "reject" && v !== "drop") {
    throw new Error(`INVALID_ENV: MTPROTO_UNKNOWN_SNI_ACTION must be mask|reject|drop, got "${value}"`);
  }
  return v;
}

function parseBoolEnv(value, fallback) {
  if (value === undefined || value === "") return fallback;
  const v = value.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

// Fields that are bound to the listening socket and must NOT be reloaded in place.
const IMMUTABLE_FIELDS = new Set(["port", "host"]);

// START_CONTRACT: applyConfigUpdate
//   PURPOSE: Merge a freshly-loaded config into a live config object in place (hot-reload)
//   INPUTS: { target: Config - the live cfg mutated in place, source: Config - new loadConfig() result }
//   OUTPUTS: { string[] - names of fields whose value changed (port/host excluded) }
//   SIDE_EFFECTS: mutates `target` in place; never touches target.port / target.host
//   LINKS: M-CONFIG
// END_CONTRACT: applyConfigUpdate
// Deep equality that handles primitives, arrays, and plain objects (order-stable via JSON).
function deepEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return a == null && b == null;
  try {
    return JSON.stringify(a) === JSON.stringify(b);
  } catch {
    return false;
  }
}

export function applyConfigUpdate(target, source) {
  const changed = [];
  for (const key of Object.keys(source)) {
    if (IMMUTABLE_FIELDS.has(key)) continue;
    const a = target[key];
    const b = source[key];
    if (!deepEqual(a, b)) {
      target[key] = b;
      changed.push(key);
    }
  }
  return changed;
}
