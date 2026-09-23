// FILE: src/mtproto-server.js
// VERSION: 1.9.0
// START_MODULE_CONTRACT
//   PURPOSE: MTProto connection handler: plain + fake-TLS handshake, DC connect, FAST_MODE relay,
//            periodic [proxy][heartbeat] liveness line
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
//
// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.9.0 - periodic [proxy][heartbeat] line (cfg.mtprotoHeartbeatMs, default 60s,
//                0 = off) reporting uptime_s + active/pending/total. Makes restarts, idle gaps
//                and pool pressure visible in a journal that replays stdout without timestamps.
//   PREVIOUS: v1.8.0 - client-abort guard during the DC connect window: a client that dies while
//                a DC connect is in flight now aborts that connect and is never handed a relay.
//                Pre-fix, startRelay() ran on the destroyed socket, leaking an active-connection
//                slot (reaped only by the idle timeout -> mtproto_cap exhaustion under a client
//                reconnect storm) and a failed candidate produced a spurious
//                mtproto_dc_fallback/retry + mtproto_upstream_error for a peer that was gone.
//                Mirrors M-MASK v1.0.1 (client_close aborts the pending splice). connectImpl is
//                injectable so the race is asserted deterministically.
//   PREVIOUS: v1.7.0 - IPv4 DC resilience: detectIpv6Availability() is passed to resolveDc so an
//                IPv4-only host never wastes a fallback on a guaranteed-ENETUNREACH IPv6 candidate;
//                and after the candidate list is exhausted the preferred candidate is retried once
//                (mtproto_dc_retry, 150ms delay, 3s timeout) before dropping the client.
//   PREVIOUS: v1.6.3 - mtproto_handshake_timeout now reports `phase`; a tls-app timeout
//                (ServerHello already sent, client silent) increments the dedicated
//                simpleproxy_faketls_post_hello_timeouts_total in addition to the total. The
//                post-restart console showed bytes:0 timeouts that were previously ambiguous.
//   PREVIOUS: v1.6.2 - observability: mtproto_close now carries dc/client/tls so a close can
//                be attributed to a client + DC (the console showed two interleaved clients whose
//                closes were previously indistinguishable); mtproto_idle_timeout logs the same
//                dc/client context plus idle_ms.
//   PREVIOUS: v1.6.1 - pass validated.ciphers into buildServerHello so a captured
//                profile.cipher is replayed only when the client offered it (fixes
//                dd/simple wrapped transports aborting after ServerHello under
//                MTPROTO_TLS_PROFILE_CAPTURE=1)
// END_CHANGE_SUMMARY

import net from "node:net";
import os from "node:os";
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
// Default period of the [proxy][heartbeat] liveness line (overridable via MTPROTO_HEARTBEAT_MS).
const HEARTBEAT_INTERVAL_MS = 60_000;
const UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;
// One retry of the preferred DC candidate after the list is exhausted (see START_BLOCK_MT_RELAY):
// a transient IPv4 failure or a wasted fallback would otherwise drop the client. The retry uses a
// shorter timeout and a small delay so the extra latency stays bounded.
const UPSTREAM_RETRY_TIMEOUT_MS = 3_000;
const DC_RETRY_DELAY_MS = 150;
// Memory bounds (512MB box): a valid ClientHello record is <= 16 KiB+5 (RFC 8446 §5.1)
// and the obfuscated2 handshake is 64 bytes, so 64 KiB of pre-handshake bytes is generous;
// anything beyond that is a probe or an attack, not a client.
const HANDSHAKE_BUF_MAX_BYTES = 64 * 1024;
// Bytes collectable while the DC connection is being established (up to 10s x candidates).
const PENDING_DATA_MAX_BYTES = 1024 * 1024;
const TLS_START = [0x16, 0x03, 0x01];
const TLS_ALERT_UNRECOGNIZED_NAME = 112;

// START_CONTRACT: detectIpv6Availability
//   PURPOSE: Report whether the host has a routable (non-internal, non-link-local) IPv6 address
//   INPUTS: { none }
//   OUTPUTS: { boolean - true when an IPv6 candidate is worth attempting }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO-SERVER, M-MTPROTO
// END_CONTRACT: detectIpv6Availability
function detectIpv6Availability() {
  try {
    const ifaces = os.networkInterfaces();
    for (const addrs of Object.values(ifaces)) {
      for (const addr of addrs || []) {
        const isV6 = addr.family === "IPv6" || addr.family === 6;
        // Skip loopback/link-local (fe80::/10): present on many hosts but never routable to a DC.
        if (isV6 && !addr.internal && !/^fe80:/i.test(addr.address)) return true;
      }
    }
  } catch {
    // Detection failure must not disable the fallback: assume IPv6 may be usable.
    return true;
  }
  return false;
}

// START_CONTRACT: createMtprotoHandler
//   PURPOSE: Create the mtproto mux handler; validates handshake, connects to DC, relays
//   INPUTS: { cfg: Config, log: Log, resolveDc?: (dcIdx, opts) => Array<{host,port}> | {host,port} | null,
//             replayGuard?: { admit: (key: Buffer) => boolean } | null,
//             maskImpl?: (opts) => void - mask splice function (injectable for tests),
//             profileManager?: { get(): Profile | null } | null - TLS profile capture & replay,
//             metrics?: { inc(name, n?): void, set(name, v): void } | null - Prometheus registry,
//             userStore?: { resolve(hex): User|null, admit(user): boolean, release(user): void,
//                           addBytes(user, n): boolean } | null - per-user limits,
//             connectImpl?: (opts: {host,port}) => net.Socket - DC connector (injectable for tests) }
//   OUTPUTS: { (socket, head) => void }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO, M-TLS-PROFILE, M-USER-STORE
// END_CONTRACT: createMtprotoHandler
export function createMtprotoHandler(cfg, log, resolveDc = getDcAddressCandidates, replayGuard = null, maskImpl = maskConnection, profileManager = null, metrics = null, userStore = null, connectImpl = net.connect) {
  let activeConnections = 0;
  let pendingHandshakes = 0; // sockets in handshake phase, before relay is established
  let totalConnections = 0; // cumulative connections that passed the cap checks

  // Detected once: whether this host can reach Telegram over IPv6. On an IPv4-only host the v6
  // candidate is skipped so a transient IPv4 failure is not masked by a guaranteed ENETUNREACH.
  const hasIpv6 = detectIpv6Availability();

  const syncPending = () => {
    if (metrics) metrics.set("simpleproxy_pending_mtproto", pendingHandshakes);
  };
  const syncActive = () => {
    if (metrics) metrics.set("simpleproxy_active_mtproto", activeConnections);
  };

  // START_BLOCK_MT_HEARTBEAT
  // Periodic liveness line: uptime + live counters. The Wispbyte journal only replays buffered
  // stdout and carries no timestamps, so a redeploy/restart, a silent idle gap, or pool pressure
  // (active approaching mtprotoMaxConnections) is otherwise invisible. 0 (or a negative override)
  // disables it. unref so a handler kept alive only by this timer never blocks process exit.
  const heartbeatMs = cfg.mtprotoHeartbeatMs ?? HEARTBEAT_INTERVAL_MS;
  if (heartbeatMs > 0) {
    const heartbeatTimer = setInterval(() => {
      log("heartbeat", "DF-HEARTBEAT", "mtproto", {
        uptime_s: Math.round(process.uptime()),
        active: activeConnections,
        pending: pendingHandshakes,
        total: totalConnections,
      });
    }, heartbeatMs);
    heartbeatTimer.unref?.();
  }
  // END_BLOCK_MT_HEARTBEAT

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
    totalConnections += 1; // counted once the caps admitted this socket
    pendingHandshakes += 1;
    syncPending();

    // Set-once release guard (telemt UserConnectionReservation pattern): exactly one
    // decrement per connection regardless of which exit path fires first — relay start,
    // post-handshake failure (auth fail / user reject / bad dc / exhausted candidates),
    // or an early close. Without this, failure paths after complete() leaked the slot
    // and 256 garbage probes could permanently brick the listener (mtproto_pending_cap).
    let pendingReleased = false;
    const releasePending = () => {
      if (pendingReleased) return;
      pendingReleased = true;
      pendingHandshakes -= 1;
      syncPending();
    };

    const secrets = cfg.mtprotoSecrets.map((s) => Buffer.from(s, "hex"));
    const isTls =
      head.length >= 3 && head[0] === TLS_START[0] && head[1] === TLS_START[1] && head[2] === TLS_START[2];

    let buf = head;
    let phase = isTls ? "tls-hello" : "plain"; // tls-hello -> tls-app -> relay
    let completed = false;
    let handedOff = false;
    let tlsReader = null;
    let obfsHandshake = Buffer.alloc(0);
    let extraAppData = Buffer.alloc(0); // app bytes received beyond the 64-byte obfs handshake
    let pendingData = Buffer.alloc(0); // client bytes arriving during the async DC connect

    const finishHandshakeAndRelay = () => {
      const parsed = parseClientHandshake(obfsHandshake.subarray(0, HANDSHAKE_LEN), secrets);
      if (!parsed) {
        releasePending();
        log("mtproto_auth_fail", "DF-1", socket.remoteAddress);
        socket.destroy();
        return;
      }
      // Per-user limits (multi-tenant): resolve the user by matched secret, enforce cap/expiry/quota.
      // Strict mode (W2-3): a valid-HMAC secret that resolves to no user record is denied
      // instead of silently taking the legacy unlimited path. Gated on size() > 0 so an
      // EMPTY tenant table under strict mode keeps serving single-tenant secrets.
      const user = userStore ? userStore.resolve(parsed.secret.toString("hex")) : null;
      if (userStore) {
        const unknownDenied =
          cfg.mtprotoUsersStrict === true && userStore.size() > 0 && user === null;
        if (unknownDenied || !userStore.admit(user)) {
          releasePending();
          if (unknownDenied && metrics) metrics.inc("simpleproxy_user_unknown_total");
          log(unknownDenied ? "mtproto_user_unknown" : "mtproto_user_reject", "DF-4", socket.remoteAddress, {
            user: user ? user.user : "unknown",
            strict: cfg.mtprotoUsersStrict === true,
          });
          socket.destroy();
          return;
        }
      }
      // DC resolution with IPv4↔IPv6 fallback: resolveDc may return a single {host,port}
      // (legacy/test resolver) or an ordered candidate array (production). Normalise to a list.
      const resolved = resolveDc(parsed.dcIdx, { preferIpv6: cfg.mtprotoPreferIpv6, hasIpv6 });
      const candidates = Array.isArray(resolved) ? resolved : resolved ? [resolved] : [];
      if (candidates.length === 0) {
        releasePending();
        log("mtproto_bad_dc", "DF-1", socket.remoteAddress, parsed.dcIdx);
        socket.destroy();
        return;
      }
      const up = buildUpstreamHandshake(parsed);

      // START_BLOCK_MT_RELAY
      // Try each DC candidate in order; fall back to the next on TCP connect failure
      // (the failed candidate never received the upstream handshake, so reuse is safe).
      let attempt = 0;
      let phase = "primary"; // "primary" = walk the candidate list; "retry" = one preferred retry
      let retriedPreferred = false;
      let relayDc = null;
      let relayUpstream = null;
      // In-flight DC connect during the candidate walk. A client that aborts while the connect is
      // pending must tear this down: otherwise startRelay() would run on a dead socket and hold an
      // active-connection slot until the idle timeout (mtproto_cap exhaustion under a reconnect
      // storm), and a failed candidate would trigger a pointless fallback/retry for a gone peer.
      // Mirrors M-MASK v1.0.1, where a client_close aborts the pending mask splice.
      let connecting = null;

      const startRelay = (dc, upstream) => {
        relayDc = dc;
        relayUpstream = upstream;
        releasePending(); // left handshake phase (idempotent)
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
        // MTProto-specific idle override (wave-A): during ISP drop windows a relay can sit
        // stalled far longer than the shared tunnel timeout is meant to tolerate; reaping
        // those pairs forces the client into a reconnect storm. Default: inherit.
        const idleMs = cfg.mtprotoIdleTimeoutMs ?? cfg.idleTimeoutMs;

        const armIdle = () => {
          clearTimeout(idleTimer);
          idleTimer = setTimeout(() => {
            log("mtproto_idle_timeout", "DF-3", dc.host, dc.port, {
              dc: parsed.dcIdx,
              client: socket.remoteAddress,
              idle_ms: idleMs,
            });
            socket.destroy();
            upstream.destroy();
          }, idleMs);
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
            dc: parsed.dcIdx,
            client: socket.remoteAddress,
            tls: isTls ? 1 : 0,
            bytes_in: bytesIn,
            bytes_out: bytesOut,
            duration_ms: Date.now() - startedAt,
          });
          socket.destroy();
          upstream.destroy();
        };

        // client -> DC: decrypt client obfuscated2, re-encrypt upstream.
        // Backpressure: when the DC socket's write buffer is full, pause the client
        // socket and resume it on the DC's 'drain' — prevents unbounded buffering
        // (and OOM on the 512MB box) during large media uploads.
        // dcPaused guard: a single 'data' chunk can fan out into many records, each
        // write failing while paused — without the guard every failure attached another
        // 'drain' listener (MaxListenersExceededWarning under 1 MiB payloads).
        let dcPaused = false;
        const pushAppDataToDc = (appData) => {
          if (tornDown) return;
          bytesIn += appData.length;
          if (metrics) metrics.inc("simpleproxy_bytes_in_total", appData.length);
          // Per-user byte quota, mid-stream enforcement (W2-2): addBytes charges first and
          // returns false once the quota is crossed -> tear the relay down immediately
          // instead of letting an exhausted user keep transferring until TCP EOF.
          if (userStore && user && !userStore.addBytes(user, appData.length)) {
            log("mtproto_quota_exceeded", "DF-USER", dc.host, dc.port, { user: user.user, bytes_in: bytesIn });
            if (metrics) metrics.inc("simpleproxy_quota_exceeded_total");
            teardown();
            return;
          }
          armIdle();
          const plain = parsed.decryptor.decrypt(appData);
          const ok = upstream.write(up.encryptorUp.encrypt(plain));
          if (!ok && !dcPaused) {
            dcPaused = true;
            socket.pause();
            upstream.once("drain", () => {
              dcPaused = false;
              socket.resume();
            });
          }
        };

        // Stop the handshake listener; the relay handlers below take over.
        socket.removeListener("data", onData);

        // DC -> client: same single-listener backpressure guard as above, mirrored.
        let clientPaused = false;
        if (isTls) {
          socket.on("data", (chunk) => {
            for (const appData of tlsReader.feed(chunk)) pushAppDataToDc(appData);
          });
          // DC -> client: wrap in fake-TLS application-data records.
          // Backpressure: pause the DC socket when the client's write buffer is full,
          // resume on the client's 'drain' — prevents unbounded buffering during
          // large media downloads.
          upstream.on("data", (chunk) => {
            if (tornDown) return;
            bytesOut += chunk.length;
            if (metrics) metrics.inc("simpleproxy_bytes_out_total", chunk.length);
            if (userStore && user && !userStore.addBytes(user, chunk.length)) {
              log("mtproto_quota_exceeded", "DF-USER", dc.host, dc.port, { user: user.user, bytes_out: bytesOut });
              if (metrics) metrics.inc("simpleproxy_quota_exceeded_total");
              teardown();
              return;
            }
            armIdle();
            const ok = socket.write(wrapTlsRecord(chunk));
            if (!ok && !clientPaused) {
              clientPaused = true;
              upstream.pause();
              socket.once("drain", () => {
                clientPaused = false;
                upstream.resume();
              });
            }
          });
        } else {
          socket.on("data", pushAppDataToDc);
          upstream.on("data", (chunk) => {
            if (tornDown) return;
            bytesOut += chunk.length;
            if (metrics) metrics.inc("simpleproxy_bytes_out_total", chunk.length);
            if (userStore && user && !userStore.addBytes(user, chunk.length)) {
              log("mtproto_quota_exceeded", "DF-USER", dc.host, dc.port, { user: user.user, bytes_out: bytesOut });
              if (metrics) metrics.inc("simpleproxy_quota_exceeded_total");
              teardown();
              return;
            }
            armIdle();
            const ok = socket.write(chunk);
            if (!ok && !clientPaused) {
              clientPaused = true;
              upstream.pause();
              socket.once("drain", () => {
                clientPaused = false;
                upstream.resume();
              });
            }
          });
        }

        // Flush buffered client bytes in arrival order. extraAppData is already app data
        // (TLS framing stripped during the handshake); pendingData is raw bytes that landed
        // during the async DC connect window and still needs TLS framing stripped for fake-TLS.
        if (extraAppData.length > 0) {
          pushAppDataToDc(extraAppData);
          extraAppData = Buffer.alloc(0);
        }
        if (pendingData.length > 0) {
          if (isTls) {
            for (const appData of tlsReader.feed(pendingData)) pushAppDataToDc(appData);
          } else {
            pushAppDataToDc(pendingData);
          }
          pendingData = Buffer.alloc(0);
        }

        socket.on("error", () => {});
        upstream.on("error", () => {});
        socket.on("close", teardown);
        upstream.on("close", teardown);
        armIdle();
      };

      const tryConnect = (timeoutMs = UPSTREAM_CONNECT_TIMEOUT_MS) => {
        if (socket.destroyed) return; // client gone during the retry delay: nothing to serve
        const dc = candidates[attempt];
        const upstream = connectImpl({ host: dc.host, port: dc.port });
        connecting = upstream;
        upstream.setTimeout(timeoutMs, () => {
          upstream.destroy(new Error("upstream connect timeout"));
        });
        let connected = false;

        upstream.once("connect", () => {
          connected = true;
          if (connecting === upstream) connecting = null;
          upstream.setTimeout(0);
          // Client vanished during the connect window (abort / reconnect storm): a relay on a
          // destroyed socket would leak an active slot + an idle DC socket. Skip it entirely.
          if (socket.destroyed) {
            releasePending();
            upstream.destroy();
            return;
          }
          startRelay(dc, upstream);
        });

        upstream.once("error", (err) => {
          if (connected) return; // post-connect error: startRelay's teardown handles it
          if (connecting === upstream) connecting = null;
          // Client gone: never chase fallback/retry for a peer that no longer exists — that would
          // walk and log the candidate list (dc_fallback / upstream_error) for a dead client.
          if (socket.destroyed) {
            releasePending();
            return;
          }
          // TCP connect failure on this candidate — try the next one (the failed candidate never
          // received the upstream handshake, so reuse across attempts is safe).
          if (phase === "primary") {
            attempt += 1;
            if (attempt < candidates.length) {
              log("mtproto_dc_fallback", "DF-1", socket.remoteAddress, {
                failed: `${dc.host}:${dc.port}`,
                next: `${candidates[attempt].host}:${candidates[attempt].port}`,
              });
              tryConnect();
              return;
            }
            // Candidate list exhausted. Give the preferred candidate one more shot: a transient
            // IPv4 failure (DPI blip / short stall) or a wasted fallback to an unreachable family
            // would otherwise drop the client and force a full TLS+obfs reconnect. Delay + shorter
            // timeout keep the added latency bounded.
            if (!retriedPreferred) {
              retriedPreferred = true;
              phase = "retry";
              attempt = 0;
              log("mtproto_dc_retry", "DF-1", socket.remoteAddress, {
                after: `${dc.host}:${dc.port}`,
                retry: `${candidates[0].host}:${candidates[0].port}`,
              });
              setTimeout(() => tryConnect(UPSTREAM_RETRY_TIMEOUT_MS), DC_RETRY_DELAY_MS).unref?.();
              return;
            }
          }
          releasePending(); // never entering relay
          log("mtproto_upstream_error", "DF-1", `${dc.host}:${dc.port}`, err.code || err.message);
          socket.destroy();
        });
      };
      tryConnect();
      // Abort an in-flight DC connect when the client dies during the connect window. The error
      // path is handled explicitly because a socket error does not always reach the relay's
      // teardown (relayUpstream stays null while a candidate is still connecting).
      const abortConnecting = () => {
        if (connecting) {
          connecting.destroy();
          connecting = null;
        }
      };
      socket.once("close", abortConnecting);
      socket.once("error", () => {
        abortConnecting();
        if (relayUpstream) relayUpstream.destroy();
      });
      // END_BLOCK_MT_RELAY
    };

    const detachHandshake = () => {
      handedOff = true;
      clearTimeout(timer);
    };

    // Full handoff (mask splice / reject / drop): socket ownership leaves the handshake
    // state machine entirely. The 'data' listener MUST be removed here — otherwise every
    // byte of a long masked TLS session keeps flowing into processBuffer and accumulating
    // in `buf` without bound (remote OOM vector on the 512MB box). complete() deliberately
    // does NOT use this: the relay still needs onData to collect pendingData during the
    // async DC connect.
    const detachForHandoff = () => {
      detachHandshake();
      socket.removeListener("data", onData);
      buf = null;
    };

    const complete = () => {
      completed = true;
      detachHandshake();
      finishHandshakeAndRelay();
    };

    const processBuffer = (data) => {
      buf = data;
      if (completed || handedOff) return;

      // Pre-handshake memory bound: no legitimate client needs more than 64 KiB before
      // the handshake completes (ClientHello <= ~16 KiB, obfuscated2 hello = 64 B).
      if (buf.length > HANDSHAKE_BUF_MAX_BYTES) {
        detachForHandoff();
        releasePending();
        log("handshake_overflow", "DF-1", socket.remoteAddress, { kind: "handshake_buf", bytes: buf.length });
        socket.destroy();
        return;
      }

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
          detachForHandoff();
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
          detachForHandoff();
          log("faketls_auth_fail", "DF-1", socket.remoteAddress, {
            sni: extractSni(clientHello),
            recordLen,
            digestPrefix: clientHello.subarray(11, 15).toString("hex"),
          });
          routeUnknown(socket, clientHello);
          return;
        }
        // SNI gate: a present SNI that does not match the configured front domain is treated as
        // unknown. Absent SNI stays lenient (legacy clients / test emulators without SNI).
        const sni = extractSni(clientHello);
        if (sni !== null && sni !== cfg.mtprotoTlsDomain.toLowerCase()) {
          detachForHandoff();
          log("faketls_unknown_sni", "DF-MASK", socket.remoteAddress, { sni });
          routeUnknown(socket, clientHello);
          return;
        }
        // Replay protection: admit each client digest at most once within the guard window.
        if (replayGuard && !replayGuard.admit(validated.digest)) {
          detachForHandoff();
          log("faketls_replay", "DF-MASK", socket.remoteAddress);
          if (metrics) metrics.inc("simpleproxy_replay_attacks_total");
          routeUnknown(socket, clientHello);
          return;
        }
        const alpn = Array.isArray(cfg.mtprotoTlsAlpn) && cfg.mtprotoTlsAlpn.length > 0
          ? cfg.mtprotoTlsAlpn[0]
          : null;
        const profile = profileManager ? profileManager.get() : null;
        const response = buildServerHello(validated.secret, validated.digest, validated.sessionId, alpn, profile, validated.ciphers);

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

    const onData = (chunk) => {
      if (completed) {
        pendingData = Buffer.concat([pendingData, chunk]);
        // Bound buffering during the async DC connect window (up to 10s per candidate):
        // unbounded accumulation here was a remote OOM vector.
        if (pendingData.length > PENDING_DATA_MAX_BYTES) {
          releasePending();
          log("handshake_overflow", "DF-1", socket.remoteAddress, { kind: "pending_data", bytes: pendingData.length });
          socket.destroy();
        }
        return;
      }
      processBuffer(Buffer.concat([buf, chunk]));
    };

    const timer = setTimeout(() => {
      socket.removeListener("data", onData);
      // Silent handshake deaths are the server-side signature of ISP drop windows: the
      // client's TLS-shaped flight never arrived, so nothing completed. A burst of these
      // (vs a trickle of scanners) means a window is open — watch
      // simpleproxy_handshake_timeouts_total to map them from the panel.
      // `phase` disambiguates the two silent states: "plain"/"tls-hello" = the opening flight
      // never completed, while "tls-app" (+ bytes 0) = we already answered a valid fake-TLS
      // ClientHello with a ServerHello and the client then went quiet (client abort after
      // ServerHello, or the ISP dropped the follow-up) — counted separately below.
      log("mtproto_handshake_timeout", "DF-1", socket.remoteAddress, {
        bytes: buf ? buf.length : 0,
        phase,
      });
      if (metrics) {
        metrics.inc("simpleproxy_handshake_timeouts_total");
        if (phase === "tls-app") metrics.inc("simpleproxy_faketls_post_hello_timeouts_total");
      }
      socket.destroy();
    }, cfg.mtprotoHandshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS);
    timer.unref?.();

    socket.on("data", onData);
    socket.on("error", () => socket.destroy());
    // Release the pending slot if the socket dies before entering relay. Idempotent:
    // also covers post-handshake failures where `completed` is already true (the
    // v1.3.x leak that let garbage probes exhaust mtprotoPendingMax permanently).
    socket.once("close", () => {
      releasePending();
    });
    processBuffer(buf);
    // END_BLOCK_MT_HANDSHAKE
  };

  return handle;
}