// FILE: src/mtproto-server.js
// VERSION: 1.2.0
// START_MODULE_CONTRACT
//   PURPOSE: MTProto connection handler: plain + fake-TLS handshake, DC connect, FAST_MODE relay
//   SCOPE: per-connection handshake validation (obfuscated2 / fake-TLS), DC upstream, bidirectional relay
//   DEPENDS: M-MTPROTO, M-FAKETLS, M-LOG
//   LINKS: M-MTPROTO
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createMtprotoHandler - build the mtproto handler for the mux server
// END_MODULE_MAP

import net from "node:net";
import {
  parseClientHandshake,
  buildUpstreamHandshake,
  getDcAddress,
  getDcAddressCandidates,
} from "./mtproto.js";
import {
  validateClientHello,
  buildServerHello,
  createTlsRecordReader,
  wrapTlsRecord,
  buildTlsAlert,
  extractSni,
  splitTlsRecords,
} from "./faketls.js";
import { maskConnection } from "./mask.js";

const HANDSHAKE_LEN = 64;
const HANDSHAKE_TIMEOUT_MS = 10_000;
const UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;
const TLS_START = [0x16, 0x03, 0x01];
const TLS_ALERT_UNRECOGNIZED_NAME = 112;

// START_CONTRACT: createMtprotoHandler
//   PURPOSE: Create the mtproto mux handler; validates handshake, connects to DC, relays
//   INPUTS: { cfg: Config, log: Log, resolveDc?: (dcIdx, opts) => Array<{host,port}> | {host,port} | null,
//             replayGuard?: { admit: (key: Buffer) => boolean } | null,
//             maskImpl?: (opts) => void - mask splice function (injectable for tests),
//             profileManager?: { get(): Profile | null } | null - TLS profile capture & replay,
//             metrics?: { inc(name, n?): void, set(name, v): void } | null - Prometheus registry,
//             userStore?: { resolve(hex): User|null, admit(user): boolean, release(user): void,
//                           addBytes(user, n): boolean } | null - per-user limits }
//   OUTPUTS: { (socket, head) => void }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO, M-TLS-PROFILE, M-USER-STORE
// END_CONTRACT: createMtprotoHandler
export function createMtprotoHandler(cfg, log, resolveDc = getDcAddressCandidates, replayGuard = null, maskImpl = maskConnection, profileManager = null, metrics = null, userStore = null) {
  let activeConnections = 0;
  let pendingHandshakes = 0; // sockets in handshake phase, before relay is established

  const syncPending = () => {
    if (metrics) metrics.set("simpleproxy_pending_mtproto", pendingHandshakes);
  };
  const syncActive = () => {
    if (metrics) metrics.set("simpleproxy_active_mtproto", activeConnections);
  };

  // START_BLOCK_ROUTE_UNKNOWN
  // Behaviour on unknown SNI / failed fake-TLS auth (telemt-inspired anti-DPI).
  // cfg.mtprotoUnknownSniAction: "mask" (splice to mask_host) | "reject" (TLS alert+close) | "drop".
  // Falls back to "drop" when unset so manually-built test configs keep legacy behaviour.
  const routeUnknown = (socket, head) => {
    const action = cfg.mtprotoUnknownSniAction || "drop";
    if (action === "mask") {
      if (metrics) metrics.inc("simpleproxy_mask_splices_total");
      maskImpl({ clientSocket: socket, head, cfg, log });
      return;
    }
    if (action === "reject") {
      socket.write(buildTlsAlert(TLS_ALERT_UNRECOGNIZED_NAME));
      socket.destroy();
      return;
    }
    socket.destroy();
  };
  // END_BLOCK_ROUTE_UNKNOWN

  const handle = (socket, head) => {
    // START_BLOCK_MT_HANDSHAKE
    if (activeConnections >= cfg.mtprotoMaxConnections) {
      log("mtproto_cap", "DF-4", socket.remoteAddress, { active: activeConnections });
      if (metrics) metrics.inc("simpleproxy_rejected_total");
      socket.destroy();
      return;
    }
    // Slowloris guard: cap the number of sockets still in the handshake phase.
    if (pendingHandshakes >= cfg.mtprotoPendingMax) {
      log("mtproto_pending_cap", "DF-4", socket.remoteAddress, { pending: pendingHandshakes });
      if (metrics) metrics.inc("simpleproxy_pending_caps_total");
      socket.destroy();
      return;
    }
    pendingHandshakes += 1;
    syncPending();

    const secrets = cfg.mtprotoSecrets.map((s) => Buffer.from(s, "hex"));
    const isTls =
      head.length >= 3 && head[0] === TLS_START[0] && head[1] === TLS_START[1] && head[2] === TLS_START[2];

    let buf = head;
    let phase = isTls ? "tls-hello" : "plain"; // tls-hello -> tls-app -> relay
    let completed = false;
    let tlsReader = null;
    let obfsHandshake = Buffer.alloc(0);
    let extraAppData = Buffer.alloc(0); // app bytes received beyond the 64-byte obfs handshake

    const finishHandshakeAndRelay = () => {
      const parsed = parseClientHandshake(obfsHandshake.subarray(0, HANDSHAKE_LEN), secrets);
      if (!parsed) {
        log("mtproto_auth_fail", "DF-1", socket.remoteAddress);
        socket.destroy();
        return;
      }
      // Per-user limits (multi-tenant): resolve the user by matched secret, enforce cap/expiry/quota.
      const user = userStore ? userStore.resolve(parsed.secret.toString("hex")) : null;
      if (userStore && !userStore.admit(user)) {
        log("mtproto_user_reject", "DF-4", socket.remoteAddress, { user: user ? user.user : "unknown" });
        socket.destroy();
        return;
      }
      // DC resolution with IPv4↔IPv6 fallback: resolveDc may return a single {host,port}
      // (legacy/test resolver) or an ordered candidate array (production). Normalise to a list.
      const resolved = resolveDc(parsed.dcIdx, { preferIpv6: cfg.mtprotoPreferIpv6 });
      const candidates = Array.isArray(resolved) ? resolved : resolved ? [resolved] : [];
      if (candidates.length === 0) {
        log("mtproto_bad_dc", "DF-1", socket.remoteAddress, parsed.dcIdx);
        socket.destroy();
        return;
      }
      const up = buildUpstreamHandshake(parsed);

      // START_BLOCK_MT_RELAY
      // Try each DC candidate in order; fall back to the next on TCP connect failure
      // (the failed candidate never received the upstream handshake, so reuse is safe).
      let attempt = 0;
      let relayDc = null;
      let relayUpstream = null;

      const startRelay = (dc, upstream) => {
        relayDc = dc;
        relayUpstream = upstream;
        pendingHandshakes -= 1; // left handshake phase
        activeConnections += 1;
        syncPending();
        syncActive();
        if (metrics) metrics.inc("simpleproxy_mtproto_connections_total");
        log("mtproto_connect", "DF-1", socket.remoteAddress, `${dc.host}:${dc.port}`, {
          dc: parsed.dcIdx,
          tls: isTls ? 1 : 0,
        });
        upstream.write(up.rndEnc);

        let bytesIn = 0;
        let bytesOut = 0;
        const startedAt = Date.now();
        let idleTimer = null;
        let tornDown = false;

        const armIdle = () => {
          clearTimeout(idleTimer);
          idleTimer = setTimeout(() => {
            log("mtproto_idle_timeout", "DF-3", dc.host, dc.port, cfg.idleTimeoutMs);
            socket.destroy();
            upstream.destroy();
          }, cfg.idleTimeoutMs);
          idleTimer.unref?.();
        };

        const teardown = () => {
          if (tornDown) return;
          tornDown = true;
          clearTimeout(idleTimer);
          activeConnections -= 1;
          syncActive();
          if (userStore && user) userStore.release(user);
          log("mtproto_close", "DF-2", dc.host, dc.port, {
            bytes_in: bytesIn,
            bytes_out: bytesOut,
            duration_ms: Date.now() - startedAt,
          });
          socket.destroy();
          upstream.destroy();
        };

        // client -> DC: decrypt client obfuscated2, re-encrypt upstream.
        const pushAppDataToDc = (appData) => {
          bytesIn += appData.length;
          if (metrics) metrics.inc("simpleproxy_bytes_in_total", appData.length);
          if (userStore && user) userStore.addBytes(user, appData.length);
          armIdle();
          const plain = parsed.decryptor.decrypt(appData);
          upstream.write(up.encryptorUp.encrypt(plain));
        };

        if (isTls) {
          // Feed leftover app bytes that arrived with the handshake.
          if (extraAppData.length > 0) {
            pushAppDataToDc(extraAppData);
            extraAppData = Buffer.alloc(0);
          }
          socket.on("data", (chunk) => {
            for (const appData of tlsReader.feed(chunk)) pushAppDataToDc(appData);
          });
          // DC -> client: wrap in fake-TLS application-data records.
          upstream.on("data", (chunk) => {
            bytesOut += chunk.length;
            if (metrics) metrics.inc("simpleproxy_bytes_out_total", chunk.length);
            if (userStore && user) userStore.addBytes(user, chunk.length);
            armIdle();
            socket.write(wrapTlsRecord(chunk));
          });
        } else {
          socket.on("data", pushAppDataToDc);
          upstream.on("data", (chunk) => {
            bytesOut += chunk.length;
            if (metrics) metrics.inc("simpleproxy_bytes_out_total", chunk.length);
            if (userStore && user) userStore.addBytes(user, chunk.length);
            armIdle();
            socket.write(chunk);
          });
          if (extraAppData.length > 0) {
            pushAppDataToDc(extraAppData);
            extraAppData = Buffer.alloc(0);
          }
        }

        socket.on("error", () => {});
        upstream.on("error", () => {});
        socket.on("close", teardown);
        upstream.on("close", teardown);
        armIdle();
      };

      const tryConnect = () => {
        const dc = candidates[attempt];
        const upstream = net.connect({ host: dc.host, port: dc.port });
        upstream.setTimeout(UPSTREAM_CONNECT_TIMEOUT_MS, () => {
          upstream.destroy(new Error("upstream connect timeout"));
        });
        let connected = false;

        upstream.once("connect", () => {
          connected = true;
          upstream.setTimeout(0);
          startRelay(dc, upstream);
        });

        upstream.once("error", (err) => {
          if (connected) return; // post-connect error: startRelay's teardown handles it
          // TCP connect failure on this candidate — try the next one.
          attempt += 1;
          if (attempt < candidates.length) {
            log("mtproto_dc_fallback", "DF-1", socket.remoteAddress, {
              failed: `${dc.host}:${dc.port}`,
              next: `${candidates[attempt].host}:${candidates[attempt].port}`,
            });
            tryConnect();
          } else {
            log("mtproto_upstream_error", "DF-1", `${dc.host}:${dc.port}`, err.code || err.message);
            socket.destroy();
          }
        });
      };
      tryConnect();
      socket.once("error", () => relayUpstream && relayUpstream.destroy());
      // END_BLOCK_MT_RELAY
    };

    const complete = () => {
      completed = true;
      socket.removeListener("data", onData);
      clearTimeout(timer);
      finishHandshakeAndRelay();
    };

    const processBuffer = (data) => {
      buf = data;
      if (completed) return;

      if (phase === "plain") {
        if (buf.length < HANDSHAKE_LEN) return;
        obfsHandshake = buf.subarray(0, HANDSHAKE_LEN);
        extraAppData = buf.subarray(HANDSHAKE_LEN);
        complete();
        return;
      }

      if (phase === "tls-hello") {
        if (buf.length < 5) return;
        const recordLen = buf.readUInt16BE(3);
        if (recordLen < 512) {
          log("faketls_reject", "DF-1", socket.remoteAddress, { recordLen });
          socket.destroy();
          return;
        }
        if (buf.length < 5 + recordLen) return;
        const clientHello = buf.subarray(0, 5 + recordLen);
        buf = buf.subarray(5 + recordLen);
        const validated = validateClientHello(clientHello, secrets);
        if (!validated) {
          // Non-keyed client (crawler / wrong secret): mask or reject instead of a bare RST,
          // so port 443 is wire-indistinguishable from a real web server.
          log("faketls_auth_fail", "DF-1", socket.remoteAddress);
          routeUnknown(socket, clientHello);
          return;
        }
        // SNI gate: a present SNI that does not match the configured front domain is treated as
        // unknown. Absent SNI stays lenient (legacy clients / test emulators without SNI).
        const sni = extractSni(clientHello);
        if (sni !== null && sni !== cfg.mtprotoTlsDomain.toLowerCase()) {
          log("faketls_unknown_sni", "DF-MASK", socket.remoteAddress, { sni });
          routeUnknown(socket, clientHello);
          return;
        }
        // Replay protection: admit each client digest at most once within the guard window.
        if (replayGuard && !replayGuard.admit(validated.digest)) {
          log("faketls_replay", "DF-MASK", socket.remoteAddress);
          if (metrics) metrics.inc("simpleproxy_replay_attacks_total");
          routeUnknown(socket, clientHello);
          return;
        }
        const alpn = Array.isArray(cfg.mtprotoTlsAlpn) && cfg.mtprotoTlsAlpn.length > 0
          ? cfg.mtprotoTlsAlpn[0]
          : null;
        const profile = profileManager ? profileManager.get() : null;
        const response = buildServerHello(validated.secret, validated.digest, validated.sessionId, alpn, profile);

        // Doppelganger: replay captured inter-arrival delays so the flight is timed like the
        // real origin, not bursty-instant. Only the handshake flight is shaped; steady-state
        // relay stays untouched. Falls back to a single write when disabled / no profile.
        if (cfg.mtprotoDoppelganger && profile && Array.isArray(profile.recordDelays) && profile.recordDelays.length > 0) {
          const records = splitTlsRecords(response);
          const delays = profile.recordDelays;
          let sent = 0;
          const sendNext = (idx) => {
            if (idx >= records.length || socket.destroyed) return;
            socket.write(records[idx]);
            const d = delays[Math.min(idx, delays.length - 1)];
            setTimeout(() => sendNext(idx + 1), Math.min(d, cfg.mtprotoDoppelgangerMaxDelayMs)).unref?.();
          };
          log("doppelganger", "DF-DOPPELGANGER", socket.remoteAddress, {
            records: records.length,
            delays: delays.length,
          });
          sendNext(0);
        } else {
          socket.write(response);
        }

        tlsReader = createTlsRecordReader();
        phase = "tls-app";
        // Fall through: feed remaining bytes to the TLS reader.
        const appDatas = tlsReader.feed(buf);
        obfsHandshake = Buffer.concat(appDatas);
        if (obfsHandshake.length >= HANDSHAKE_LEN) {
          extraAppData = obfsHandshake.subarray(HANDSHAKE_LEN);
          obfsHandshake = obfsHandshake.subarray(0, HANDSHAKE_LEN);
          complete();
        }
        return;
      }

      if (phase === "tls-app") {
        const appDatas = tlsReader.feed(buf);
        obfsHandshake = Buffer.concat([obfsHandshake, ...appDatas]);
        if (obfsHandshake.length >= HANDSHAKE_LEN) {
          extraAppData = obfsHandshake.subarray(HANDSHAKE_LEN);
          obfsHandshake = obfsHandshake.subarray(0, HANDSHAKE_LEN);
          complete();
        }
        return;
      }
    };

    const onData = (chunk) => processBuffer(Buffer.concat([buf, chunk]));

    const timer = setTimeout(() => {
      socket.removeListener("data", onData);
      socket.destroy();
    }, HANDSHAKE_TIMEOUT_MS);
    timer.unref?.();

    socket.on("data", onData);
    socket.on("error", () => socket.destroy());
    // Release the pending slot if the socket dies before entering relay.
    socket.once("close", () => {
      if (!completed) {
        pendingHandshakes -= 1;
        syncPending();
      }
    });
    processBuffer(buf);
    // END_BLOCK_MT_HANDSHAKE
  };

  return handle;
}