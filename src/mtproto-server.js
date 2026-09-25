// FILE: src/mtproto-server.js
// VERSION: 1.14.0
// START_MODULE_CONTRACT
//   PURPOSE: MTProto connection handler: plain + fake-TLS handshake, DC connect, FAST_MODE relay,
//            periodic [proxy][heartbeat] liveness line, handshake-death and close-death forensics
//   SCOPE: per-connection handshake validation (obfuscated2 / fake-TLS), DC upstream, bidirectional relay,
//          close attribution (reason / error_code / last-byte ages) on the relay and on every
//          terminal handshake rejection
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
//   LAST_CHANGE: v1.14.0 - close attribution. The relay teardown was bound to BOTH sockets'
//                'close' with no way to tell them apart, and both 'error' handlers were empty
//                swallows, so mtproto_close could not say which side died. Prod 15:45 showed why
//                that matters: 14 sessions from 3 different clients, all DC2, all dying at
//                91.3-91.9s after <600 bytes - a lifetime NO timer in this codebase owns (the
//                idle reaper is 300s, handshake 10s), and therefore unattributable. mtproto_close
//                now carries `reason` (client_close | upstream_close | client_error |
//                upstream_error | idle_timeout | user_quota | unknown), `error_code` (errno only,
//                never err.message) and `last_rx_ms`/`last_tx_ms` (age of the last byte per
//                direction, null - not 0 - when that direction never carried app data).
//                FIRST STAMP WINS, so a server-side decision (idle reaper, quota kick) survives
//                the close events its own teardown causes; without that, every reap would be
//                relabelled "the client hung up". Node emits 'error' before 'close', so an errno
//                is recorded ahead of the close it causes. Vocabulary mirrors M-MASK's
//                teardown(reason) so both relays filter by one field. The seven terminal
//                handshake paths now share one rejectWith() helper (stamp, merge reason into the
//                detail, release the pending slot, log, destroy), replacing hand-rolled
//                releasePending/log/destroy triples that had drifted apart; mtproto_bad_dc moved
//                its dc index from the message slot into the detail object.
//   PREVIOUS: v1.13.0 - handshake-death forensics: mtproto_handshake_timeout now carries
//                elapsed_ms, closed, flight_bytes and flight_records on top of bytes/phase.
//                Prod 14:25: a burst of eleven `{"bytes":0,"phase":"tls-app"}` lines from one
//                mobile client was ambiguous - the handshake timer is NOT cleared when the client
//                hangs up, so "the client rejected our ServerHello" and "the follow-up was dropped
//                on the path" produced byte-identical evidence. closed (socket already gone when
//                the timer fired) + elapsed_ms (the socket's REAL lifetime, not the timeout)
//                split those two cases, and flight_bytes/flight_records report what we actually
//                put on the wire, which the coalesced doppelganger line cannot attribute to a
//                single connection. splitTlsRecords moved out of the doppelganger branch so both
//                paths report the same (framed, not per-write) record count.
//   PREVIOUS: v1.12.0 - link attribution: mtproto_connect/mtproto_close now carry `secret`
//                (the matched secret's INDEX, never its bytes) and `proto` (abridged |
//                intermediate | secure). The simple and dd links share the same key material, so
//                tls:0 alone could not tell a stalled dd link from a healthy simple one in the
//                journal. [proxy][doppelganger] additionally reports `certLen` — the fake
//                certificate actually written, so MTPROTO_FAKE_TLS_CERT_LEN_MAX is observable.
//   PREVIOUS: v1.11.0 - the fake-TLS ClientHello extent comes from resolveClientHelloEnd
//                (handshake-message length) instead of requiring the declared TLS record length
//                to be satisfiable, with the record framing kept as a second attempt for clients
//                that sign the padded record. Prod 14:43: a client delivered the same 1298 bytes
//                on every attempt and stalled in phase="tls-hello" until the timeout — no
//                validation, no ServerHello, endless reconnects across all ee links. A genuinely
//                fragmented hello still waits (resolver returns 0), so no partial hello is served.
//                mtproto_handshake_timeout now also logs recordLen/hsLen in phase=tls-hello, so a
//                future stall is self-explanatory without packet captures.
//   PREVIOUS: v1.10.0 - coalesce the [proxy][doppelganger] line (cfg.mtprotoDoppelgangerLogMs,
//                default 5s, 0 = per-connection): at most one line per interval plus a
//                `suppressed` count of skipped occurrences. A busy fake-TLS client logged a line
//                per connection, which flooded the journal and churned the panel's stdout socket.
//   PREVIOUS: v1.9.0 - periodic [proxy][heartbeat] line (cfg.mtprotoHeartbeatMs, default 60s,
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
  describeProtoTag,
} from "./mtproto.js";
import {
  validateClientHello,
  buildServerHello,
  createTlsRecordReader,
  wrapTlsRecord,
  buildTlsAlert,
  extractSni,
  splitTlsRecords,
  resolveClientHelloEnd,
  resolveFakeCertLen,
} from "./faketls.js";
import { maskConnection } from "./mask.js";

const HANDSHAKE_LEN = 64;
const HANDSHAKE_TIMEOUT_MS = 10_000;
// Default period of the [proxy][heartbeat] liveness line (overridable via MTPROTO_HEARTBEAT_MS).
const HEARTBEAT_INTERVAL_MS = 60_000;
// Default minimum spacing between [proxy][doppelganger] lines (overridable via
// MTPROTO_DOPPELGANGER_LOG_MS; 0 restores one line per connection).
const DOPPELGANGER_LOG_INTERVAL_MS = 5_000;
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

  // START_BLOCK_MT_DOPPELGANGER_LOG
  // Doppelganger log coalescing (shared across connections): at most one line per interval, with
  // a `suppressed` count of occurrences skipped since the previous line. A busy fake-TLS client
  // otherwise logs one line per connection, which floods the journal and churns the panel's
  // stdout socket — the panel then stalls and replays its whole buffer on reconnect. The count is
  // carried forward until it is emitted, so a burst is never lost, only reported later.
  // interval <= 0 restores the old log-every-event behaviour.
  let dgLoggedAt = 0;
  let dgSuppressed = 0;
  const logDoppelganger = (addr, records, delays, certLen) => {
    const interval = cfg.mtprotoDoppelgangerLogMs ?? DOPPELGANGER_LOG_INTERVAL_MS;
    const now = Date.now();
    if (interval <= 0 || now - dgLoggedAt >= interval) {
      dgLoggedAt = now;
      // certLen = the fake certificate actually put on the wire, so a capped flight
      // (MTPROTO_FAKE_TLS_CERT_LEN_MAX) is visible in the journal instead of assumed.
      log("doppelganger", "DF-DOPPELGANGER", addr, { records, delays, certLen, suppressed: dgSuppressed });
      dgSuppressed = 0;
    } else {
      dgSuppressed += 1;
    }
  };
  // END_BLOCK_MT_DOPPELGANGER_LOG

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
      log("mtproto_pending_cap", "DF-4", socket.remoteAddress, { pending: pendingHandshakes, reason: "pending_cap" });
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

    // Close attribution. The relay teardown is bound to BOTH sockets, so without a stamp
    // mtproto_close cannot say which side went first - and prod showed a tight cluster of sessions
    // (3 different clients, all DC2) dying at 91.3-91.9s after <600 bytes, a lifetime no timer in
    // this codebase owns. FIRST STAMP WINS: a server-side decision (idle reaper, quota kick) must
    // survive the close events its own teardown then causes, otherwise every reap would be
    // relabelled "the client hung up". Vocabulary mirrors M-MASK's teardown(reason) so both relays
    // can be filtered by one field.
    let closeReason = null;
    let closeErrorCode = null;
    const stampClose = (reason, errorCode = null) => {
      if (closeReason !== null) return;
      closeReason = reason;
      closeErrorCode = errorCode;
    };
    // The single terminal path of the handshake phase: stamp, merge the reason into the detail,
    // release the pending slot, log, destroy. Replaces the hand-rolled
    // releasePending/log/destroy triples that had drifted apart.
    const rejectWith = (reason, event, df, target, detail, errorCode = null) => {
      stampClose(reason, errorCode);
      releasePending();
      log(event, df, target, errorCode ? { ...detail, reason, error_code: errorCode } : { ...detail, reason });
      socket.destroy();
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
    // Handshake-death forensics (mtproto_handshake_timeout detail). A silent client and a client
    // that hung up on our ServerHello used to produce the identical `bytes:0 phase:tls-app` line,
    // because the timer is not cleared on close - so the line cannot tell "abort after
    // ServerHello" from "the follow-up was dropped". acceptedAt/closedMs recover the socket's real
    // lifetime, and the flight fields report what we actually put on the wire for that attempt.
    const acceptedAt = Date.now();
    let closedMs = 0;
    let flightBytes = 0;
    let flightRecords = 0;

    const finishHandshakeAndRelay = () => {
      const parsed = parseClientHandshake(obfsHandshake.subarray(0, HANDSHAKE_LEN), secrets);
      if (!parsed) {
        rejectWith("auth_fail", "mtproto_auth_fail", "DF-1", socket.remoteAddress, null);
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
          if (unknownDenied && metrics) metrics.inc("simpleproxy_user_unknown_total");
          rejectWith(
            unknownDenied ? "user_unknown" : "user_reject",
            unknownDenied ? "mtproto_user_unknown" : "mtproto_user_reject",
            "DF-4",
            socket.remoteAddress,
            { user: user ? user.user : "unknown", strict: cfg.mtprotoUsersStrict === true }
          );
          return;
        }
      }
      // DC resolution with IPv4↔IPv6 fallback: resolveDc may return a single {host,port}
      // (legacy/test resolver) or an ordered candidate array (production). Normalise to a list.
      const resolved = resolveDc(parsed.dcIdx, { preferIpv6: cfg.mtprotoPreferIpv6, hasIpv6 });
      const candidates = Array.isArray(resolved) ? resolved : resolved ? [resolved] : [];
      if (candidates.length === 0) {
        rejectWith("bad_dc", "mtproto_bad_dc", "DF-1", socket.remoteAddress, { dc: parsed.dcIdx });
        return;
      }
      const up = buildUpstreamHandshake(parsed);

      // Link attribution for the journal. The secret is reported by INDEX only — never its bytes.
      // simple and dd carry the SAME key material (the `dd`/`ee` prefixes are client-side transport
      // routing), so `tls` alone cannot tell them apart; `proto` can: simple = abridged,
      // dd = secure, ee = any proto with tls:1. Without it a stalled dd link is indistinguishable
      // from a healthy simple one in the journal.
      const secretIndex = secrets.findIndex((s) => s.equals(parsed.secret));
      const link = {
        secret: secretIndex >= 0 ? `s${secretIndex}` : "s?",
        proto: describeProtoTag(parsed.protoTag) || "unknown",
      };

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
          ...link,
        });
        upstream.write(up.rndEnc);

        let bytesIn = 0;
        let bytesOut = 0;
        // Age of the last byte carried by each direction, stamped in the same two places as the
        // byte counters so the two always describe the same stream. 0 = that direction never
        // carried post-handshake app data, reported as null (NOT 0, which would read as "just now").
        let lastRxAt = 0;
        let lastTxAt = 0;
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
            // Stamp BEFORE destroying: the close events this triggers would otherwise relabel a
            // server-side reap as a client hangup.
            stampClose("idle_timeout");
            log("mtproto_idle_timeout", "DF-3", dc.host, dc.port, {
              dc: parsed.dcIdx,
              client: socket.remoteAddress,
              idle_ms: idleMs,
              reason: "idle_timeout",
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
          const now = Date.now();
          log("mtproto_close", "DF-2", dc.host, dc.port, {
            dc: parsed.dcIdx,
            client: socket.remoteAddress,
            tls: isTls ? 1 : 0,
            ...link,
            bytes_in: bytesIn,
            bytes_out: bytesOut,
            duration_ms: now - startedAt,
            reason: closeReason ?? "unknown",
            ...(closeErrorCode ? { error_code: closeErrorCode } : {}),
            last_rx_ms: lastRxAt === 0 ? null : now - lastRxAt,
            last_tx_ms: lastTxAt === 0 ? null : now - lastTxAt,
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
          lastRxAt = Date.now();
          if (metrics) metrics.inc("simpleproxy_bytes_in_total", appData.length);
          // Per-user byte quota, mid-stream enforcement (W2-2): addBytes charges first and
          // returns false once the quota is crossed -> tear the relay down immediately
          // instead of letting an exhausted user keep transferring until TCP EOF.
          if (userStore && user && !userStore.addBytes(user, appData.length)) {
            log("mtproto_quota_exceeded", "DF-USER", dc.host, dc.port, { user: user.user, bytes_in: bytesIn, reason: "user_quota" });
            if (metrics) metrics.inc("simpleproxy_quota_exceeded_total");
            stampClose("user_quota");
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
            lastTxAt = Date.now();
            if (metrics) metrics.inc("simpleproxy_bytes_out_total", chunk.length);
            if (userStore && user && !userStore.addBytes(user, chunk.length)) {
              log("mtproto_quota_exceeded", "DF-USER", dc.host, dc.port, { user: user.user, bytes_out: bytesOut, reason: "user_quota" });
              if (metrics) metrics.inc("simpleproxy_quota_exceeded_total");
              stampClose("user_quota");
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
            lastTxAt = Date.now();
            if (metrics) metrics.inc("simpleproxy_bytes_out_total", chunk.length);
            if (userStore && user && !userStore.addBytes(user, chunk.length)) {
              log("mtproto_quota_exceeded", "DF-USER", dc.host, dc.port, { user: user.user, bytes_out: bytesOut, reason: "user_quota" });
              if (metrics) metrics.inc("simpleproxy_quota_exceeded_total");
              stampClose("user_quota");
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

        // Close attribution. Node emits 'error' before 'close' for a given socket, so an errno is
        // recorded ahead of the close it causes and the close cannot mask it. The handlers only
        // stamp: teardown (bound to both close events) does the logging, once.
        socket.on("error", (err) => stampClose("client_error", err.code ?? null));
        upstream.on("error", (err) => stampClose("upstream_error", err.code ?? null));
        socket.on("close", () => {
          stampClose("client_close");
          teardown();
        });
        upstream.on("close", () => {
          stampClose("upstream_close");
          teardown();
        });
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
          // Every candidate (and the one preferred retry) is unreachable: the client is dropped.
          rejectWith(
            "upstream_error",
            "mtproto_upstream_error",
            "DF-1",
            `${dc.host}:${dc.port}`,
            { attempts: attempt + 1 },
            err.code ?? null
          );
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
        rejectWith("handshake_overflow", "handshake_overflow", "DF-1", socket.remoteAddress, {
          kind: "handshake_buf",
          bytes: buf.length,
        });
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
          rejectWith("faketls_record_short", "faketls_reject", "DF-1", socket.remoteAddress, { recordLen });
          return;
        }
        // The record length may overstate what the client actually wrote (prod: a client sent the
        // same 1298 bytes on every attempt and stalled in phase="tls-hello" until the timeout).
        // resolveClientHelloEnd trusts the ClientHello's own handshake-message length in that
        // case, and returns 0 while the message itself is still incomplete — so a genuinely
        // fragmented hello keeps waiting instead of being answered from partial bytes.
        const recordEnd = 5 + recordLen;
        let helloEnd = resolveClientHelloEnd(buf);
        if (helloEnd === 0) return;
        let clientHello = buf.subarray(0, helloEnd);
        let validated = validateClientHello(clientHello, secrets);
        if (!validated && helloEnd !== recordEnd && buf.length >= recordEnd) {
          // Other clients sign the whole TLS record, padding included, so their record length
          // exceeds the handshake message. Try that framing before treating the hello as foreign.
          helloEnd = recordEnd;
          clientHello = buf.subarray(0, helloEnd);
          validated = validateClientHello(clientHello, secrets);
        }
        buf = buf.subarray(helloEnd);
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
        // Resolve the fake-certificate size ONCE (cap applied here, not inside buildServerHello) so
        // the number reported in the doppelganger line is exactly what goes on the wire.
        const certLen = resolveFakeCertLen(profile, cfg.mtprotoFakeTlsCertLenMax ?? 0);
        const response = buildServerHello(validated.secret, validated.digest, validated.sessionId, alpn, profile, validated.ciphers, certLen);
        // Frame the flight unconditionally: the doppelganger path needs the records to pace, and
        // both paths need the shape for the handshake-death log (a single write is not a single TLS
        // record, so counting the framing is the only honest record count).
        const records = splitTlsRecords(response);
        flightBytes = response.length;
        flightRecords = records.length;

        // Doppelganger: replay captured inter-arrival delays so the flight is timed like the
        // real origin, not bursty-instant. Only the handshake flight is shaped; steady-state
        // relay stays untouched. Falls back to a single write when disabled / no profile.
        if (cfg.mtprotoDoppelganger && profile && Array.isArray(profile.recordDelays) && profile.recordDelays.length > 0) {
          const delays = profile.recordDelays;
          let sent = 0;
          const sendNext = (idx) => {
            if (idx >= records.length || socket.destroyed) return;
            socket.write(records[idx]);
            const d = delays[Math.min(idx, delays.length - 1)];
            setTimeout(() => sendNext(idx + 1), Math.min(d, cfg.mtprotoDoppelgangerMaxDelayMs)).unref?.();
          };
          logDoppelganger(socket.remoteAddress, records.length, delays.length, certLen);
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
          rejectWith("handshake_overflow", "handshake_overflow", "DF-1", socket.remoteAddress, {
            kind: "pending_data",
            bytes: pendingData.length,
          });
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
      // In "tls-hello" the declared lengths are logged as well: they separate "the client is
      // still mid-flight" (recordLen/hsLen beyond `bytes`) from "the ClientHello message is
      // complete but its record length overstates it" (the exact prod stall that resolveClientHelloEnd
      // now recovers from) without needing packet captures.
      const now = Date.now();
      const closed = closedMs > 0 || socket.destroyed;
      const detail = {
        bytes: buf ? buf.length : 0,
        phase,
        // The socket's real lifetime, NOT the timeout: when the client hung up early this is how
        // long it lasted, which is what separates "rejected our flight" from "still waiting".
        elapsed_ms: (closed && closedMs > 0 ? closedMs : now) - acceptedAt,
        closed,
        flight_bytes: flightBytes,
        flight_records: flightRecords,
      };
      if (phase === "tls-hello" && detail.bytes >= 5) {
        detail.recordLen = buf.readUInt16BE(3);
        if (detail.bytes >= 9 && buf[5] === 0x01) detail.hsLen = buf.readUIntBE(6, 3);
      }
      log("mtproto_handshake_timeout", "DF-1", socket.remoteAddress, detail);
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
      // Stamp the first close so a handshake timeout can report the socket's real lifetime
      // (see acceptedAt). The timer itself is deliberately left armed: the timeout line is the
      // only evidence a handshake died, so it must survive the client's own hangup.
      if (closedMs === 0) closedMs = Date.now();
      releasePending();
    });
    processBuffer(buf);
    // END_BLOCK_MT_HANDSHAKE
  };

  return handle;
}