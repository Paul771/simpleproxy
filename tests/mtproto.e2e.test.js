// FILE: tests/mtproto.e2e.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: End-to-end MTProto flow: client handshake -> proxy -> fake DC, data round-trip
//   SCOPE: full obfuscated2 handshake over real sockets, relay integrity
//   DEPENDS: M-MTPROTO, M-MUX, M-MTPROTO-SERVER
//   LINKS: V-M-MTPROTO
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { randomBytes, createHash } from "node:crypto";
import { createMuxServer } from "../src/mux.js";
import { createMtprotoHandler } from "../src/mtproto-server.js";
import { createConnectHandler } from "../src/proxy.js";
import { makeLog } from "../src/log.js";
import { createAesCtr } from "../src/mtproto.js";
import {
  validateClientHello,
  buildServerHello,
  createTlsRecordReader,
  wrapTlsRecord,
} from "../src/faketls.js";
import { createHmac } from "node:crypto";

const PROTO_TAG_ABRIDGED = Buffer.from([0xef, 0xef, 0xef, 0xef]);

function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

// --- Client emulator (mirrors the reference client behaviour) ---
function buildClientHandshake(secret, protoTag, dcIdx) {
  let init;
  for (;;) {
    init = randomBytes(64);
    if (init[0] === 0xef) continue;
    if (init.subarray(4, 8).equals(Buffer.alloc(4))) continue;
    break;
  }
  protoTag.copy(init, 56);
  init.writeInt16LE(dcIdx, 60);
  const key = sha256(init.subarray(8, 40), secret);
  const stream = createAesCtr(key, init.subarray(40, 56));
  const encrypted = stream.encrypt(init);
  const handshake = Buffer.concat([init.subarray(0, 56), encrypted.subarray(56, 64)]);
  // Incoming direction (proxy -> client) uses the reversed prekey+iv with the secret.
  const reversed = Buffer.from(init.subarray(8, 56)).reverse();
  const encKey = sha256(reversed.subarray(0, 32), secret);
  const encIv = reversed.subarray(32, 48);
  return { handshake, stream, encKey, encIv };
}

// --- Fake DC: acts like a Telegram datacenter for the proxy ---
function startFakeDc() {
  const server = net.createServer((socket) => {
    let buf = Buffer.alloc(0);
    let ready = false;
    let tgDec = null;
    let tgEnc = null;

    socket.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!ready && buf.length >= 64) {
        const rndEnc = buf.subarray(0, 64);
        buf = buf.subarray(64);
        ready = true;

        // obfuscated2 server side: incoming decrypted with prekey as-is,
        // outgoing encrypted with the REVERSED prekey+iv slice.
        const keyUp = rndEnc.subarray(8, 40);
        const ivUp = rndEnc.subarray(40, 56);
        const rev = Buffer.from(rndEnc.subarray(8, 56)).reverse();
        tgDec = createAesCtr(keyUp, ivUp);
        tgEnc = createAesCtr(rev.subarray(0, 32), rev.subarray(32, 48));
        // The proxy's encryptor was advanced past the 64-byte handshake.
        tgDec.decrypt(Buffer.alloc(64));
        // Any bytes after the handshake were already buffered — process them.
        if (buf.length > 0) {
          const data = buf;
          buf = Buffer.alloc(0);
          const plain = tgDec.decrypt(data);
          socket.write(tgEnc.encrypt(plain));
        }
        return;
      }
      if (ready && buf.length > 0) {
        const data = buf;
        buf = Buffer.alloc(0);
        const plain = tgDec.decrypt(data);
        socket.write(tgEnc.encrypt(plain));
      }
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function startProxy(cfgOverrides = {}, resolveDc) {
  const cfg = {
    port: 0,
    host: "127.0.0.1",
    maxTunnels: 32,
    idleTimeoutMs: 120_000,
    rules: [],
    mtprotoSecrets: [],
    mtprotoPort: 0,
    mtprotoMaxConnections: 64,
    ...cfgOverrides,
  };
  const log = makeLog();
  const allow = () => true;
  const auth = () => true;
  const httpHandlers = createConnectHandler(cfg, allow, auth, log);
  const handlers = {
    "http-connect": httpHandlers["http-connect"],
    "http-other": httpHandlers["http-other"],
    "mtproto": createMtprotoHandler(cfg, log, resolveDc),
  };
  const server = createMuxServer(handlers);
  return new Promise((resolve) => {
    server.listen(cfg.port, cfg.host, () => resolve({ server, addr: server.address() }));
  });
}

test("e2e: MTProto client handshake -> proxy -> fake DC, data round-trips", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    const { handshake, stream, encKey, encIv } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);

    const payload = "mtproto-echo-payload";
    const sent = stream.encrypt(Buffer.from(payload));
    // The client decrypts the proxy->client direction with its enc key+iv.
    const clientDec = createAesCtr(encKey, encIv);

    const result = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([handshake, sent]));
      });
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`timeout, got: ${buf.toString("hex")}`)), 3000);
      socket.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        if (buf.length >= payload.length) {
          clearTimeout(timer);
          socket.destroy();
          resolve(clientDec.decrypt(buf).toString());
        }
      });
      socket.on("error", reject);
    });

    assert.equal(result, payload);
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("e2e: wrong secret is rejected, connection closed", async () => {
  const secret = randomBytes(16);
  const wrong = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    const { handshake } = buildClientHandshake(wrong, PROTO_TAG_ABRIDGED, 1);
    const closed = await new Promise((resolve) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(handshake);
      });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 1500);
    });
    assert.equal(closed, true, "socket must be closed for wrong secret");
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("e2e: unknown DC index is rejected", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => null // resolveDc returns null -> bad DC
  );

  try {
    const { handshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
    const closed = await new Promise((resolve) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(handshake);
      });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 1500);
    });
    assert.equal(closed, true, "socket must be closed for bad DC");
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

// --- fake-TLS (ee-secret) client emulator ---
const FT_DIGEST_POS = 11;
const FT_DIGEST_LEN = 32;

function hmacSha256(key, msg) {
  return createHmac("sha256", key).update(msg).digest();
}

// Build a fake-TLS ClientHello carrying the obfuscated2 handshake in the TLS random field's
// successor: the 64-byte obfs handshake is sent as the first TLS application-data record.
function buildFakeTlsClientHello(secret, obfsHandshake) {
  const sessionId = randomBytes(16);
  const timestamp = Math.floor(Date.now() / 1000);
  const tsBytes = Buffer.alloc(4);
  tsBytes.writeUInt32LE(timestamp, 0);

  const cipherSuites = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const compression = Buffer.from([0x01, 0x00]);
  const padLen = 533;
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
  padExt.writeUInt16BE(padLen, 2);
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(padExt.length, 0);
  const extensions = Buffer.concat([extTotal, padExt]);

  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    Buffer.alloc(FT_DIGEST_LEN),
    Buffer.from([sessionId.length]),
    sessionId,
    cipherSuites,
    compression,
    extensions,
  ]);
  const hsLenBuf = Buffer.alloc(3);
  hsLenBuf.writeUIntBE(inner.length, 0, 3);
  const handshakeMsg = Buffer.concat([Buffer.from([0x01]), hsLenBuf, inner]);
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(handshakeMsg.length, 0);
  let hello = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recordLenBuf, handshakeMsg]);

  const msg = Buffer.concat([
    hello.subarray(0, FT_DIGEST_POS),
    Buffer.alloc(FT_DIGEST_LEN),
    hello.subarray(FT_DIGEST_POS + FT_DIGEST_LEN),
  ]);
  const computed = hmacSha256(secret, msg);
  const digest = Buffer.alloc(FT_DIGEST_LEN);
  for (let i = 0; i < FT_DIGEST_LEN; i++) {
    digest[i] = computed[i] ^ (i < FT_DIGEST_LEN - 4 ? 0 : tsBytes[i - (FT_DIGEST_LEN - 4)]);
  }
  hello = Buffer.concat([
    hello.subarray(0, FT_DIGEST_POS),
    digest,
    hello.subarray(FT_DIGEST_POS + FT_DIGEST_LEN),
  ]);
  return { hello, sessionId, digest };
}

test("e2e: fake-TLS (ee) handshake -> proxy -> fake DC, data round-trips", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    // Inner obfuscated2 handshake the client wants to send.
    const { handshake: obfsHandshake, stream, encKey, encIv } = buildClientHandshake(
      secret,
      PROTO_TAG_ABRIDGED,
      1
    );
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, obfsHandshake);

    const payload = "faketls-echo-payload";
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);

    const result = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        // Send TLS ClientHello, then the obfuscated2 handshake inside a TLS app-data record,
        // then the encrypted payload inside another app-data record.
        socket.write(
          Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake), wrapTlsRecord(sent)])
        );
      });
      // The proxy responds with: 0x16 ServerHello + 0x14 ChangeCipherSpec + 0x17 (fake cert).
      // Consume those response records first, then read real app-data records.
      let rawBuf = Buffer.alloc(0);
      let phase = "consume-response";
      let tlsIn = null;
      let appBuf = Buffer.alloc(0);
      const timer = setTimeout(
        () => reject(new Error(`faketls timeout, phase=${phase} got: ${appBuf.toString("hex")}`)),
        3000
      );
      socket.on("data", (d) => {
        rawBuf = Buffer.concat([rawBuf, d]);
        if (phase === "consume-response") {
          while (rawBuf.length >= 5) {
            const recLen = rawBuf.readUInt16BE(3);
            if (rawBuf.length < 5 + recLen) break;
            const recType = rawBuf[0];
            rawBuf = rawBuf.subarray(5 + recLen);
            if (recType === 0x17) {
              // First 0x17 record is the fake-cert app-data; response fully consumed.
              phase = "app-data";
              tlsIn = createTlsRecordReader();
              break;
            }
          }
        }
        if (phase === "app-data" && rawBuf.length > 0) {
          for (const appData of tlsIn.feed(rawBuf)) {
            appBuf = Buffer.concat([appBuf, appData]);
            if (appBuf.length >= payload.length) {
              clearTimeout(timer);
              socket.destroy();
              resolve(clientDec.decrypt(appBuf).toString());
              return;
            }
          }
          rawBuf = Buffer.alloc(0);
        }
      });
      socket.on("error", reject);
    });

    assert.equal(result, payload);
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("e2e: fake-TLS with wrong secret is rejected, connection closed", async () => {
  const secret = randomBytes(16);
  const wrong = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    const { handshake: obfsHandshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
    const { hello: tlsHello } = buildFakeTlsClientHello(wrong, obfsHandshake);
    const closed = await new Promise((resolve) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake)]));
      });
      socket.on("close", () => resolve(true));
      socket.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 2000);
    });
    assert.equal(closed, true, "fake-TLS with wrong secret must close the connection");
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});
