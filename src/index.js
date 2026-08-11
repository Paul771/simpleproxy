// FILE: src/index.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Entry point: loadConfig -> makeLog -> createProxy -> start
//   SCOPE: process bootstrap and dependency wiring
//   DEPENDS: M-CONFIG, M-LOG, M-ALLOW, M-AUTH, M-PROXY, M-TUNNEL
//   LINKS: M-PROXY
//   ROLE: ENTRY_POINT
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { loadConfig } from "./config.js";
import { makeLog } from "./log.js";
import { normalizeTarget, isAllowed } from "./allow.js";
import { checkAuth } from "./auth.js";
import { createProxy, start } from "./proxy.js";

// START_BLOCK_BOOT
let cfg;
try {
  cfg = loadConfig();
} catch (err) {
  console.error(`[config][load][env] ${err.message}`);
  process.exit(1);
}

const log = makeLog();
const allow = (raw) => isAllowed(normalizeTarget(raw), cfg.rules);
const auth = (header) => checkAuth(header, cfg.creds);

const server = createProxy(cfg, allow, auth, log);

start(server, cfg, log).catch((err) => {
  console.error(`[server][start][fatal] ${err.message}`);
  process.exit(1);
});
// END_BLOCK_BOOT
