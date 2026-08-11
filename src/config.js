// FILE: src/config.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Read env and return a validated proxy configuration
//   SCOPE: env parsing, defaults, allowlist rule construction, auth credentials
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
//   OUTPUTS: { Config - { port, host, maxTunnels, idleTimeoutMs, authUser, authPass, rules } }
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

  return {
    port,
    host: "0.0.0.0",
    maxTunnels,
    idleTimeoutMs,
    authUser,
    authPass,
    creds,
    rules: DEFAULT_RULES,
  };
}
