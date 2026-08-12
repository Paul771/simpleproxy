// FILE: src/mtproto-server.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: MTProto connection handler: parse client handshake, connect to DC, relay with FAST_MODE
//   SCOPE: per-connection handshake validation, DC upstream connection, bidirectional relay
//   DEPENDS: M-MTPROTO, M-TUNNEL-style relay, M-LOG
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
} from "./mtproto.js";

const HANDSHAKE_LEN = 64;
const HANDSHAKE_TIMEOUT_MS = 10_000;
const UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;

// START_CONTRACT: createMtprotoHandler
//   PURPOSE: Create the mtproto mux handler; validates handshake, connects to DC, relays
//   INPUTS: { cfg: Config, log: Log, resolveDc?: (dcIdx: number) => { host, port } | null }
//   OUTPUTS: { (socket, head) => void }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO
// END_CONTRACT: createMtprotoHandler
export function createMtprotoHandler(cfg, log, resolveDc = getDcAddress) {
  let activeConnections = 0;

  const handle = (socket, head) => {
    // START_BLOCK_MT_HANDSHAKE
    if (activeConnections >= cfg.mtprotoMaxConnections) {
      log("mtproto_cap", "DF-4", socket.remoteAddress, { active: activeConnections });
      socket.destroy();
      return;
    }

    let buf = head;
    let completed = false;

    const processBuffer = (data) => {
      buf = data;
      if (buf.length < HANDSHAKE_LEN) return;
      completed = true;
      socket.removeListener("data", onData);
      clearTimeout(timer);

      const secrets = cfg.mtprotoSecrets.map((s) => Buffer.from(s, "hex"));
      const parsed = parseClientHandshake(buf.subarray(0, HANDSHAKE_LEN), secrets);
      if (!parsed) {
        log("mtproto_auth_fail", "DF-1", socket.remoteAddress);
        socket.destroy();
        return;
      }

      const dc = resolveDc(parsed.dcIdx);
      if (!dc) {
        log("mtproto_bad_dc", "DF-1", socket.remoteAddress, parsed.dcIdx);
        socket.destroy();
        return;
      }

      const up = buildUpstreamHandshake(parsed);

      // START_BLOCK_MT_RELAY
      const upstream = net.connect({ host: dc.host, port: dc.port });
      upstream.setTimeout(UPSTREAM_CONNECT_TIMEOUT_MS, () => {
        upstream.destroy(new Error("upstream connect timeout"));
      });

      upstream.once("connect", () => {
        upstream.setTimeout(0);
        activeConnections += 1;
        log("mtproto_connect", "DF-1", socket.remoteAddress, `${dc.host}:${dc.port}`, {
          dc: parsed.dcIdx,
        });
        upstream.write(up.rndEnc);

        let bytesIn = 0; // client -> DC
        let bytesOut = 0; // DC -> client
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
          log("mtproto_close", "DF-2", dc.host, dc.port, {
            bytes_in: bytesIn,
            bytes_out: bytesOut,
            duration_ms: Date.now() - startedAt,
          });
          socket.destroy();
          upstream.destroy();
        };

        // FAST_MODE: client -> DC is re-encrypted (decrypt client, encrypt upstream);
        // DC -> client flows byte-for-byte (mirrored keys match what the client expects).
        const relayClientChunk = (chunk) => {
          bytesIn += chunk.length;
          armIdle();
          const plain = parsed.decryptor.decrypt(chunk);
          upstream.write(up.encryptorUp.encrypt(plain));
        };

        socket.on("data", relayClientChunk);

        // Forward any client bytes that arrived together with the handshake.
        const rest = buf.subarray(HANDSHAKE_LEN);
        if (rest.length > 0) {
          relayClientChunk(rest);
        }

        upstream.on("data", (chunk) => {
          bytesOut += chunk.length;
          armIdle();
          socket.write(chunk);
        });

        socket.on("error", () => {});
        upstream.on("error", () => {});
        socket.on("close", teardown);
        upstream.on("close", teardown);
        armIdle();
        // END_BLOCK_MT_RELAY
      });

      upstream.once("error", (err) => {
        log("mtproto_upstream_error", "DF-1", `${dc.host}:${dc.port}`, err.code || err.message);
        socket.destroy();
      });

      socket.once("error", () => {
        upstream.destroy();
      });
    };

    const onData = (chunk) => {
      if (completed) return;
      processBuffer(Buffer.concat([buf, chunk]));
    };

    const timer = setTimeout(() => {
      socket.removeListener("data", onData);
      socket.destroy();
    }, HANDSHAKE_TIMEOUT_MS);
    timer.unref?.();

    socket.on("data", onData);
    socket.on("error", () => socket.destroy());
    // The mux already buffered the head; process it synchronously if complete.
    processBuffer(buf);
    // END_BLOCK_MT_HANDSHAKE
  };

  return handle;
}
