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
//                          mtprotoSecrets, mtprotoPort, mtprotoMaxConnections } }
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
  };
}
