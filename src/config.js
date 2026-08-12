// FILE: src/config.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Read env and return a validated proxy configuration
//   SCOPE: env parsing, defaults, allowlist rule construction, auth credentials, MTProto settings
//   DEPENDS: none
//   LINKS: M-CONFIG
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   loadConfig - load and validate config from env
// END_MODULE_MAP

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

// START_CONTRACT: loadConfig
//   PURPOSE: Read env and return validated config
//   INPUTS: { env: Record<string, string | undefined> - environment (default process.env) }
//   OUTPUTS: { Config - { port, host, maxTunnels, idleTimeoutMs, authUser, authPass, creds, rules,
//                          mtprotoSecrets, mtprotoPort, mtprotoMaxConnections, mtprotoHost,
//                          mtprotoTlsDomain, mtprotoTlsAlpn, mtprotoMaskHost, mtprotoMaskPort,
//                          mtprotoUnknownSniAction, mtprotoReplayWindow, mtprotoReplayTtlMs,
//                          mtprotoDigestFreshnessMs, mtprotoPreferIpv6 } }
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

  // MTProto secrets: comma-separated 32-hex (16-byte) values.
  // MTPROTO_SECRET unset or empty -> MTProto listener disabled.
  let mtprotoSecrets = [];
  if (env.MTPROTO_SECRET && env.MTPROTO_SECRET.trim() !== "") {
    mtprotoSecrets = env.MTPROTO_SECRET.split(",")
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s !== "");
    for (const s of mtprotoSecrets) {
      if (!/^[0-9a-f]{32}$/.test(s)) {
        throw new Error(`INVALID_ENV: MTPROTO_SECRET entries must be 32 hex chars, got "${s}"`);
      }
    }
  }

  const mtprotoPort = parseIntEnv(env.MTPROTO_PORT, 0, "MTPROTO_PORT");
  const mtprotoMaxConnections = parseIntEnv(
    env.MTPROTO_MAX_CONNECTIONS,
    64,
    "MTPROTO_MAX_CONNECTIONS"
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
    mtprotoPort,
    mtprotoMaxConnections,
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
