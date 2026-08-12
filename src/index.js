// FILE: src/index.js
// VERSION: 1.1.0
// START_MODULE_CONTRACT
//   PURPOSE: Entry point: loadConfig -> makeLog -> mux(connect + mtproto) -> start
//   SCOPE: process bootstrap, dependency wiring, tg://proxy link generation
//   DEPENDS: M-CONFIG, M-LOG, M-ALLOW, M-AUTH, M-PROXY, M-MUX, M-MTPROTO
//   LINKS: M-PROXY
//   ROLE: ENTRY_POINT
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { loadConfig } from "./config.js";
import { makeLog } from "./log.js";
import { normalizeTarget, isAllowed } from "./allow.js";
import { checkAuth } from "./auth.js";
import { createConnectHandler, start } from "./proxy.js";
import { createMtprotoHandler } from "./mtproto-server.js";
import { createMuxServer } from "./mux.js";

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

const httpHandlers = createConnectHandler(cfg, allow, auth, log);
const handlers = {
  "http-connect": httpHandlers["http-connect"],
  "http-other": httpHandlers["http-other"],
  "mtproto": cfg.mtprotoSecrets.length > 0 ? createMtprotoHandler(cfg, log) : null,
};

const server = createMuxServer(handlers);

server.on("listening", () => {
  // START_BLOCK_PRINT_LINKS
  if (cfg.mtprotoSecrets.length > 0) {
    const host = cfg.mtprotoHost;
    const port = cfg.mtprotoPort > 0 ? cfg.mtprotoPort : cfg.port;
    for (const secret of cfg.mtprotoSecrets) {
      log("mtproto_link", "start", `simple:  tg://proxy?server=${host}&port=${port}&secret=${secret}`);
      log("mtproto_link", "start", `dd:     tg://proxy?server=${host}&port=${port}&secret=dd${secret}`);
      const tlsSecret = "ee" + secret + Buffer.from(cfg.mtprotoTlsDomain, "utf8").toString("hex");
      log(
        "mtproto_link",
        "start",
        `ee:     tg://proxy?server=${host}&port=${port}&secret=${tlsSecret}`
      );
    }
  }
  // END_BLOCK_PRINT_LINKS
});

start(server, cfg, log).catch((err) => {
  console.error(`[server][start][fatal] ${err.message}`);
  process.exit(1);
});
// END_BLOCK_BOOT
