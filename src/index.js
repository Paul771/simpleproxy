// FILE: src/index.js
// VERSION: 1.2.0
// START_MODULE_CONTRACT
//   PURPOSE: Entry point: loadConfig -> makeLog -> mux(connect + mtproto) -> start
//   SCOPE: process bootstrap, dependency wiring, tg://proxy link generation
//   DEPENDS: M-CONFIG, M-LOG, M-ALLOW, M-AUTH, M-PROXY, M-MUX, M-MTPROTO, M-FAKETLS, M-MASK, M-REPLAY, M-TLS-PROFILE, M-METRICS, M-USER-STORE
//   LINKS: M-PROXY
//   ROLE: ENTRY_POINT
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { loadConfig, applyConfigUpdate } from "./config.js";
import { makeLog } from "./log.js";
import { normalizeTarget, isAllowed } from "./allow.js";
import { checkAuth } from "./auth.js";
import { createConnectHandler, start } from "./proxy.js";
import { createMtprotoHandler } from "./mtproto-server.js";
import { createMuxServer } from "./mux.js";
import { createReplayGuard } from "./replay-guard.js";
import { createProfileManager } from "./tls-profile.js";
import { createMetrics, startMetricsServer } from "./metrics.js";
import { createUserStore } from "./user-store.js";

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

// Prometheus metrics registry. Always created; served on a side-port only when
// MTPROTO_METRICS_PORT > 0. Passed to handlers for counter/gauge instrumentation.
const metrics = createMetrics();

const httpHandlers = createConnectHandler(cfg, allow, auth, log, metrics);
// Replay guard is created only when MTProto is enabled and the window is non-zero.
const replayGuard = cfg.mtprotoSecrets.length > 0 && cfg.mtprotoReplayWindow > 0
  ? createReplayGuard({
      maxSize: cfg.mtprotoReplayWindow,
      ttlMs: cfg.mtprotoReplayTtlMs,
      freshnessMs: cfg.mtprotoDigestFreshnessMs,
    })
  : null;
// TLS profile capture & replay (Phase 2 anti-DPI): captures the real server-flight shape
// from MTPROTO_TLS_DOMAIN and replays it in buildServerHello. Off by default.
const profileManager = cfg.mtprotoSecrets.length > 0 && cfg.mtprotoTlsProfileCapture
  ? createProfileManager({
      host: cfg.mtprotoTlsDomain,
      port: 443,
      refreshMs: cfg.mtprotoTlsProfileRefreshMs,
      timeoutMs: cfg.mtprotoTlsProfileTimeoutMs,
      log,
    })
  : null;
if (profileManager) profileManager.start();
// Per-user secret limits (multi-tenant): built from cfg.mtprotoUsers. When no limits are
// configured, admit() always returns true -> behaviour is unchanged from the single-tenant case.
const userStore = cfg.mtprotoUsers.length > 0 ? createUserStore(cfg.mtprotoUsers) : null;
const handlers = {
  "http-connect": httpHandlers["http-connect"],
  "http-other": httpHandlers["http-other"],
  "mtproto": cfg.mtprotoSecrets.length > 0 ? createMtprotoHandler(cfg, log, undefined, replayGuard, undefined, profileManager, metrics, userStore) : null,
};

const server = createMuxServer(handlers);

// Side-port /metrics server (off when MTPROTO_METRICS_PORT is 0).
let metricsServer = null;
if (cfg.mtprotoMetricsPort > 0) {
  metricsServer = startMetricsServer({ port: cfg.mtprotoMetricsPort, host: cfg.mtprotoMetricsHost }, metrics, log);
  metricsServer.listen(cfg.mtprotoMetricsPort, cfg.mtprotoMetricsHost, () => {
    log("metrics_listen", "DF-METRICS", `http://${cfg.mtprotoMetricsHost}:${cfg.mtprotoMetricsPort}`);
  });
}

server.on("listening", () => {
  // START_BLOCK_PRINT_LINKS
  if (cfg.mtprotoSecrets.length > 0) {
    log("mask_config", "start", {
      action: cfg.mtprotoUnknownSniAction,
      mask_host: `${cfg.mtprotoMaskHost}:${cfg.mtprotoMaskPort}`,
      alpn: (cfg.mtprotoTlsAlpn || []).join(","),
      replay: replayGuard ? cfg.mtprotoReplayWindow : 0,
      ipv6: cfg.mtprotoPreferIpv6 ? 1 : 0,
      profile_capture: cfg.mtprotoTlsProfileCapture ? 1 : 0,
    });
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

// START_BLOCK_HOT_RELOAD
// SIGUSR2: re-read env and merge into the live cfg in place. Handlers read cfg.* fresh on
// each connection, so secret rotation, mask host, TLS domain, caps, doppelganger, etc. take
// effect immediately. Subsystems with boot-time state (replay guard, profile manager, metrics
// server, listening port) cannot be reconfigured live — those are flagged for a restart.
// On Windows SIGUSR2 is not delivered, so this is a no-op there (restart via panel instead).
const RESTART_FIELDS = new Set([
  "mtprotoMetricsPort",
  "mtprotoMetricsHost",
  "mtprotoReplayWindow",
  "mtprotoReplayTtlMs",
  "mtprotoDigestFreshnessMs",
  "mtprotoTlsProfileCapture",
  "mtprotoTlsProfileRefreshMs",
  "mtprotoTlsProfileTimeoutMs",
]);
process.on("SIGUSR2", () => {
  let next;
  try {
    next = loadConfig();
  } catch (err) {
    log("reload_fail", "DF-RELOAD", err.message);
    return;
  }
  const changed = applyConfigUpdate(cfg, next);
  const restartNeeded = changed.filter((k) => RESTART_FIELDS.has(k));
  log("reload", "DF-RELOAD", {
    changed: changed.length,
    fields: changed.join(",") || "none",
    restart_needed: restartNeeded.join(",") || "none",
  });
});
// END_BLOCK_HOT_RELOAD
// END_BLOCK_BOOT
