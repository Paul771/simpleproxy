// FILE: src/mtproto-server.js
// VERSION: 1.1.0
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
} from "./mtproto.js";
import {
  validateClientHello,
  buildServerHello,
  createTlsRecordReader,
  wrapTlsRecord,
} from "./faketls.js";

const HANDSHAKE_LEN = 64;
const HANDSHAKE_TIMEOUT_MS = 10_000;
const UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;
const TLS_START = [0x16, 0x03, 0x01];

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
            armIdle();
            socket.write(wrapTlsRecord(chunk));
          });
        } else {
          socket.on("data", pushAppDataToDc);
          upstream.on("data", (chunk) => {
            bytesOut += chunk.length;
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
        // END_BLOCK_MT_RELAY
      });

      upstream.once("error", (err) => {
        log("mtproto_upstream_error", "DF-1", `${dc.host}:${dc.port}`, err.code || err.message);
        socket.destroy();
      });
      socket.once("error", () => upstream.destroy());
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
          log("faketls_auth_fail", "DF-1", socket.remoteAddress);
          socket.destroy();
          return;
        }
        const response = buildServerHello(validated.secret, validated.digest, validated.sessionId);
        socket.write(response);
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
    processBuffer(buf);
    // END_BLOCK_MT_HANDSHAKE
  };

  return handle;
}