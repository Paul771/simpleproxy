// FILE: tests/mtproto.e2e.test.js
// VERSION: 1.3.0
// START_MODULE_CONTRACT
//   PURPOSE: End-to-end MTProto flow: client handshake -> proxy -> fake DC, data round-trip
//   SCOPE: full obfuscated2 handshake over real sockets, relay integrity, fake-TLS ClientHello
//          whose declared lengths overstate what the client actually sends
//   DEPENDS: M-MTPROTO, M-MUX, M-MTPROTO-SERVER
//   LINKS: V-M-MTPROTO
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT
//
// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.3.0 - a strict ALPN-demanding client, end to end. This is the production failure:
//                the proxy logged a successful fake-TLS handshake and then relayed the client's bytes
//                into a DC that answered nothing (bytes_out: 0, dc_replies: 0). Cause: a captured
//                profile with alpnKnown=true made the ServerHello omit the ALPN extension, and a
//                client that OFFERED ALPN treats that silence as a failed handshake. The emulator now
//                refuses to send its obfuscated2 handshake until the ServerHello actually answers the
//                offer, which is what a strict real client does. The fixture builders gained an
//                `exts` parameter so a test can demand a strict server, and the assertion matches the
//                exact extension bytes rather than re-walking the ServerHello extension list — a
//                test that re-implements that walk only tests itself.
//   PREVIOUS: v1.2.0 - buildFakeTlsClientHello gained extLenPad so the e2e can inflate the
//                extensions block total too, and a new test drives that end to end: the proxy must
//                answer with a ServerHello and relay the payload. This is the client that survived
//                v1.1.0's structural fix — 1298 bytes against a ~1789-byte hello with every declared
//                length, including the innermost one, inflated — and it reproduces the production line
//                (bytes:1298, phase=tls-hello, flight_bytes:0, closed:false). The client also sends
//                its ClientHello and WAITS for the ServerHello before writing the app records,
//                because that is the behaviour the production signature actually shows and pipelining
//                would model a client the evidence does not support.
//   PREVIOUS: v1.1.0 - buildFakeTlsClientHello gained recordLenPad/hsLenPad so the fake-TLS
//                ClientHello can overstate its declared lengths without writing those bytes, and a
//                new e2e drives that end to end: the proxy must still answer with a ServerHello and
//                relay the payload. RED reproduced the production line verbatim (bytes:702,
//                phase=tls-hello, recordLen:1080, hsLen:1076, flight_bytes:0) — 85% of a real
//                110-minute window died exactly this way, unanswered until the handshake timeout.
// END_CHANGE_SUMMARY

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
  buildAlpnExtension,
  extractAlpnList,
  resolveClientHelloStructuralEnd,
} from "../src/faketls.js";
import { createHmac } from "node:crypto";
import { createReplayGuard } from "../src/replay-guard.js";
import { maskConnection } from "../src/mask.js";
import { createProfileManager } from "../src/tls-profile.js";

const PROTO_TAG_ABRIDGED = Buffer.from([0xef, 0xef, 0xef, 0xef]);

// ALPN offer extension (type 0x0010). extension_data is `u16 list_len || ProtocolNameList`, so the
// extension length spans the length field AND the entries — and the 6-byte header below already
// carries that inner length. Getting this wrong is the easiest way to build an offer the parser
// correctly refuses, which looks exactly like "the client never offered ALPN".
function alpnExt(protocols) {
  const list = Buffer.concat(protocols.map((p) => {
    const b = Buffer.from(p, "latin1");
    return Buffer.concat([Buffer.from([b.length]), b]);
  }));
  const ext = Buffer.alloc(6);
  ext.writeUInt16BE(0x0010, 0);
  ext.writeUInt16BE(2 + list.length, 2);
  ext.writeUInt16BE(list.length, 4);
  return Buffer.concat([ext, list]);
}

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
    mtprotoPendingMax: 256,
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
// extLenPad additionally inflates the extensions block total, which is what a client does when it
// inflates every declared length including the innermost one (prod: 1298 bytes against a ~1789-byte
// hello, resolved by neither the record, the handshake, nor the structural walk).
// exts appends real ClientHello extensions (e.g. an ALPN offer) to the padding extension, so a test
// can demand a strict server. extLenPad still inflates only the declared extensions total.
function buildFakeTlsClientHello(
  secret,
  obfsHandshake,
  recordLenPad = 0,
  hsLenPad = 0,
  extLenPad = 0,
  exts = []
) {
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
  extTotal.writeUInt16BE(padExt.length + exts.reduce((n, e) => n + e.length, 0) + extLenPad, 0);
  const extensions = Buffer.concat([extTotal, padExt, ...exts]);

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
  hsLenBuf.writeUIntBE(inner.length + hsLenPad, 0, 3);
  const handshakeMsg = Buffer.concat([Buffer.from([0x01]), hsLenBuf, inner]);
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(handshakeMsg.length + recordLenPad, 0);
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

// Production stall: the client's record AND handshake length fields both overstated what it sent,
// in agreement with each other (recordEnd == messageEnd), so neither declared extent was reachable.
// The proxy must still answer with a ServerHello from the structurally-resolved ClientHello instead
// of leaving the client waiting for a handshake timeout (prod: flight_bytes: 0 on every attempt).
test("e2e: fake-TLS handshake completes when both declared lengths overstate the ClientHello", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    const { handshake: obfsHandshake, stream, encKey, encIv } = buildClientHandshake(
      secret,
      PROTO_TAG_ABRIDGED,
      1
    );
    // Same pad in both fields reproduces the prod signature.
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, obfsHandshake, 480, 480);
    assert.equal(
      5 + tlsHello.readUInt16BE(3),
      9 + tlsHello.readUIntBE(6, 3),
      "fixture must keep the declared extents in agreement"
    );
    assert.ok(5 + tlsHello.readUInt16BE(3) > tlsHello.length, "record must promise more than arrived");

    const payload = "inflated-length-payload";
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);

    const result = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(
          Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake), wrapTlsRecord(sent)])
        );
      });
      let rawBuf = Buffer.alloc(0);
      let phase = "consume-response";
      let tlsIn = null;
      let appBuf = Buffer.alloc(0);
      const timer = setTimeout(
        () => reject(new Error(`inflated-length timeout, phase=${phase} got: ${appBuf.toString("hex")}`)),
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

// Drive a fake-TLS client through a live proxy and return the echoed payload. The client sends its
// ClientHello and then WAITS for the ServerHello before writing the obfuscated2 handshake — that is
// what real TLS clients do, and it is what production does too: the stalled client's hello arrived
// alone (bytes:1298, closed:false), holding the socket open for a ServerHello that never came. So the
// app records go out only after the flight lands, not pipelined into the hello's segment.
function fakeTlsRoundTrip(addr, secret, tlsHello) {
  const { handshake: obfsHandshake, stream, encKey, encIv } = buildClientHandshake(
    secret,
    PROTO_TAG_ABRIDGED,
    1
  );
  const payload = "extensions-inflated-payload";
  const sent = stream.encrypt(Buffer.from(payload));
  const clientDec = createAesCtr(encKey, encIv);

  return new Promise((resolve, reject) => {
    const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(tlsHello));
    let rawBuf = Buffer.alloc(0);
    let phase = "consume-response";
    let tlsIn = null;
    let appBuf = Buffer.alloc(0);
    const timer = setTimeout(
      () => reject(new Error(`extensions-inflated timeout, phase=${phase} got: ${appBuf.toString("hex")}`)),
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
            phase = "app-data";
            tlsIn = createTlsRecordReader();
            // ServerHello landed — now send what the hello did not cover.
            socket.write(Buffer.concat([wrapTlsRecord(obfsHandshake), wrapTlsRecord(sent)]));
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
}

// The stall that survived the structural fix: every declared length overstates, INCLUDING the
// extensions block total, so the structural walk yields no extent either and the client waits for a
// ServerHello that never comes (prod: bytes:1298, recordLen/hsLen ~1784/1780, flight_bytes: 0, and
// closed: false — the client was alive, holding the connection open, waiting). The proxy must now
// answer it, because the client's own HMAC confirms the extent it really signed.
test("e2e: fake-TLS handshake completes when the extensions length overstates too", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, Buffer.alloc(64), 480, 480, 480);
    assert.ok(5 + tlsHello.readUInt16BE(3) > tlsHello.length, "record must promise more than arrived");
    assert.equal(resolveClientHelloStructuralEnd(tlsHello), 0, "structure must yield no extent either");

    assert.equal(await fakeTlsRoundTrip(addr, secret, tlsHello), "extensions-inflated-payload");
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

// The production symptom, end to end: the proxy logged a successful fake-TLS handshake, then relayed
// the client's bytes to the DC and got NOTHING back (bytes_out: 0, dc_replies: 0, first_dc_reply_ms:
// null). The client had OFFERED ALPN, and a captured profile with alpnKnown=true made buildServerHello
// omit the extension to mirror a fronted origin that negotiated none — so the client aborted its
// MTProto stream and everything we forwarded was garbage the DC ignored. This client refuses to send
// its obfuscated2 handshake unless the ServerHello actually answered its ALPN offer, which is what a
// strict real client does.
test("e2e: a client that offered ALPN is answered even when the profile recorded none", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const profile = {
    cipher: [0x13, 0x01],
    alpn: null,
    alpnKnown: true, // origin negotiated no ALPN
    ccsCount: 1,
    appDataSizes: [180, 360],
    certLen: 360,
    recordDelays: [],
  };
  const log = makeLog();
  const cfg = {
    port: 0,
    host: "127.0.0.1",
    maxTunnels: 32,
    idleTimeoutMs: 5_000,
    rules: [],
    mtprotoSecrets: [secret.toString("hex")],
    mtprotoPort: 0,
    mtprotoMaxConnections: 64,
    mtprotoTlsDomain: "www.google.com",
    mtprotoTlsAlpn: ["h2", "http/1.1"],
  };
    // The profile reaches the handler through a profileManager, not as a positional arg.
    const profileManager = { get: () => profile };
    const handlers = {
      "http-connect": createConnectHandler(cfg, () => true, () => true, log)["http-connect"],
      "http-other": createConnectHandler(cfg, () => true, () => true, log)["http-other"],
      "mtproto": createMtprotoHandler(cfg, log, () => ({ host: "127.0.0.1", port: dcAddr.port }), null, maskConnection, profileManager),
    };
  const server = createMuxServer(handlers);
  await new Promise((resolve) => server.listen(cfg.port, cfg.host, resolve));
  const addr = server.address();

  try {
    const { handshake: obfsHandshake, stream, encKey, encIv } = buildClientHandshake(
      secret,
      PROTO_TAG_ABRIDGED,
      1
    );
    // Same ClientHello the other fake-TLS tests use, plus the ALPN offer this client insists on.
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, obfsHandshake, 0, 0, 0, [alpnExt(["h2", "http/1.1"])]);
    // Assert the premise here: a silently malformed fixture would otherwise look like a proxy bug.
    assert.deepEqual(extractAlpnList(tlsHello), ["h2", "http/1.1"], "the client must really offer ALPN");

    const payload = "alpn-demanding-payload";
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);

    // Extract the ServerHello and require an ALPN answer before the client sends anything. Matched
    // on the exact extension bytes rather than by hand-walking the extension list: the ServerHello
    // carries nested lengths, and a test that re-implements that walk only tests itself.
    const answer = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(tlsHello));
      let raw = Buffer.alloc(0);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error("no ServerHello before timeout"));
      }, 3000);
      socket.on("data", (d) => {
        raw = Buffer.concat([raw, d]);
        if (raw.length >= 5 && raw[0] === 0x16 && raw.length >= 5 + raw.readUInt16BE(3)) {
          clearTimeout(timer);
          const answered = raw.includes(buildAlpnExtension(["h2"]));
          socket.write(wrapTlsRecord(obfsHandshake));
          socket.write(wrapTlsRecord(sent));
          resolve({ answered, socket });
        }
      });
      socket.on("error", reject);
    });

    assert.equal(answer.answered, true, "the ServerHello must answer an ALPN offer");

    const echoed = await new Promise((resolve, reject) => {
      let appBuf = Buffer.alloc(0);
      const tlsIn = createTlsRecordReader();
      const timer = setTimeout(() => reject(new Error(`relay timeout, got ${appBuf.length} bytes`)), 3000);
      answer.socket.on("data", (d) => {
        for (const app of tlsIn.feed(d)) {
          appBuf = Buffer.concat([appBuf, app]);
          if (appBuf.length >= payload.length) {
            clearTimeout(timer);
            resolve(clientDec.decrypt(appBuf).toString());
            return;
          }
        }
      });
    });
    answer.socket.destroy();
    assert.equal(echoed, payload);
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("e2e: fake-TLS relay carries a 1 MiB payload (backpressure) without loss", async () => {
  // Regression guard (wave-1): bursts of failing writes used to stack 'drain'
  // listeners and trip MaxListenersExceededWarning. The transfer below must not
  // emit any process warning of that kind.
  const warnings = [];
  const onWarning = (w) => {
    if (w && w.name === "MaxListenersExceededWarning") warnings.push(w);
  };
  process.on("warning", onWarning);

  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    const { handshake: obfsHandshake, stream, encKey, encIv } = buildClientHandshake(
      secret,
      PROTO_TAG_ABRIDGED,
      1
    );
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, obfsHandshake);

    // 1 MiB — large enough to overflow the default 16 KiB socket write buffer and
    // force the relay's pause/resume backpressure path in both directions.
    const payload = randomBytes(1024 * 1024);
    const payloadHash = createHash("sha256").update(payload).digest("hex");
    const sent = stream.encrypt(payload);
    const clientDec = createAesCtr(encKey, encIv);

    const result = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(
          Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake), wrapTlsRecord(sent)])
        );
      });
      let rawBuf = Buffer.alloc(0);
      let phase = "consume-response";
      let tlsIn = null;
      let appBuf = Buffer.alloc(0);
      const timer = setTimeout(
        () => reject(new Error(`large-payload timeout, got ${appBuf.length} bytes`)),
        10000
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
              phase = "app-data";
              tlsIn = createTlsRecordReader();
              break;
            }
          }
        }
        if (phase === "app-data" && rawBuf.length > 0) {
          for (const appData of tlsIn.feed(rawBuf)) appBuf = Buffer.concat([appBuf, appData]);
          rawBuf = Buffer.alloc(0);
          if (appBuf.length >= payload.length) {
            clearTimeout(timer);
            socket.destroy();
            const plain = clientDec.decrypt(appBuf.subarray(0, payload.length));
            resolve(createHash("sha256").update(plain).digest("hex"));
            return;
          }
        }
      });
      socket.on("error", reject);
    });

    assert.equal(result, payloadHash);
    assert.equal(
      warnings.length,
      0,
      `relay must not stack drain listeners (got ${warnings.length} MaxListenersExceededWarning)`
    );
  } finally {
    process.off("warning", onWarning);
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

// --- Anti-DPI: replay protection + traffic masking (telemt-inspired) ---

// A tiny mask upstream that replies with a real, plain HTTP-ish line so the masked client
// sees a legitimate-looking response (and DPI sees a real server, not a RST).
function startMaskServer() {
  const server = net.createServer((socket) => {
    socket.on("data", () => {});
    socket.write("MASK-OK\n");
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

test("e2e: replayed fake-TLS ClientHello is masked instead of reaching the DC twice", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const mask = await startMaskServer();
  const maskAddr = mask.address();
  const log = makeLog();
  const cfg = {
    port: 0,
    host: "127.0.0.1",
    maxTunnels: 32,
    idleTimeoutMs: 5_000,
    rules: [],
    mtprotoSecrets: [secret.toString("hex")],
    mtprotoPort: 0,
    mtprotoMaxConnections: 64,
    mtprotoTlsDomain: "www.google.com",
    mtprotoMaskHost: "127.0.0.1",
    mtprotoMaskPort: maskAddr.port,
    mtprotoUnknownSniAction: "mask",
  };
  const replayGuard = createReplayGuard({ maxSize: 8, ttlMs: 60_000, freshnessMs: 0 });
  const handlers = {
    "http-connect": createConnectHandler(cfg, () => true, () => true, log)["http-connect"],
    "http-other": createConnectHandler(cfg, () => true, () => true, log)["http-other"],
    "mtproto": createMtprotoHandler(cfg, log, () => ({ host: "127.0.0.1", port: dcAddr.port }), replayGuard, maskConnection),
  };
  const server = createMuxServer(handlers);
  await new Promise((resolve) => server.listen(cfg.port, cfg.host, resolve));
  const addr = server.address();

  try {
    // One shared ClientHello -> identical digest on both connections.
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, Buffer.alloc(64));

    // First connection: valid digest -> admitted -> MTProto path -> fake DC echo.
    const { handshake: obfsHandshake, stream, encKey, encIv } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
    const payload = "replay-first";
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);
    const first = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake), wrapTlsRecord(sent)]));
      });
      let rawBuf = Buffer.alloc(0);
      let phase = "consume-response";
      let tlsIn = null;
      let appBuf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`first timeout phase=${phase}`)), 3000);
      socket.on("data", (d) => {
        rawBuf = Buffer.concat([rawBuf, d]);
        if (phase === "consume-response") {
          while (rawBuf.length >= 5) {
            const recLen = rawBuf.readUInt16BE(3);
            if (rawBuf.length < 5 + recLen) break;
            const recType = rawBuf[0];
            rawBuf = rawBuf.subarray(5 + recLen);
            if (recType === 0x17) {
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
    assert.equal(first, payload, "first connection must complete the MTProto round-trip");

    // Second connection: SAME digest -> replay guard rejects -> routed to mask server.
    const second = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(tlsHello));
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`mask timeout got: ${buf.toString("latin1")}`)), 3000);
      socket.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        if (buf.includes("MASK-OK")) {
          clearTimeout(timer);
          socket.destroy();
          resolve(buf.toString("latin1"));
        }
      });
      socket.on("error", reject);
    });
    assert.ok(second.includes("MASK-OK"), "replayed ClientHello must be masked, not reach the DC");
  } finally {
    replayGuard.stop();
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    mask.closeAllConnections?.();
    server.close();
    fakeDc.close();
    mask.close();
  }
});

// --- TLS profile capture & replay: profiled fake-TLS ServerHello still round-trips ---

function buildScriptedFlight(appDataSizes) {
  const parts = [];
  const srvHello = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    randomBytes(32),
    Buffer.from([0x00]), // sidLen 0
    Buffer.from([0x13, 0x02]), // cipher TLS_AES_256_GCM_SHA384
    Buffer.from([0x00]), // compression
    Buffer.from([0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]), // supported_versions ext
  ]);
  const hsLen = Buffer.alloc(3);
  hsLen.writeUIntBE(srvHello.length, 0, 3);
  const hsMsg = Buffer.concat([Buffer.from([0x02]), hsLen, srvHello]);
  const recLen = Buffer.alloc(2);
  recLen.writeUInt16BE(hsMsg.length, 0);
  parts.push(Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), recLen, hsMsg]));
  parts.push(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01])); // CCS
  for (const size of appDataSizes) {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(size, 0);
    parts.push(Buffer.from([0x17, 0x03, 0x03]), len, randomBytes(size));
  }
  return Buffer.concat(parts);
}

function startScriptOrigin(flight) {
  const server = net.createServer((socket) => {
    socket.on("data", () => { socket.write(flight); socket.end(); });
    socket.on("error", () => {});
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

test("e2e: profiled fake-TLS (TLS profile capture & replay) round-trips through the proxy", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const origin = await startScriptOrigin(buildScriptedFlight([180, 360, 90]));
  const originAddr = origin.address();

  const log = makeLog();
  const cfg = {
    port: 0,
    host: "127.0.0.1",
    maxTunnels: 32,
    idleTimeoutMs: 5_000,
    rules: [],
    mtprotoSecrets: [secret.toString("hex")],
    mtprotoPort: 0,
    mtprotoMaxConnections: 64,
    mtprotoTlsDomain: "www.google.com",
    mtprotoTlsAlpn: ["h2"],
  };
  const profileManager = createProfileManager({
    host: "127.0.0.1",
    port: originAddr.port,
    refreshMs: 60_000,
    timeoutMs: 3000,
  });
  profileManager.start();
  // Wait for the initial capture to populate the profile.
  for (let i = 0; i < 20 && !profileManager.get(); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(profileManager.get(), "profile must be captured before the client connects");

  const handlers = {
    "http-connect": createConnectHandler(cfg, () => true, () => true, log)["http-connect"],
    "http-other": createConnectHandler(cfg, () => true, () => true, log)["http-other"],
    "mtproto": createMtprotoHandler(cfg, log, () => ({ host: "127.0.0.1", port: dcAddr.port }), null, maskConnection, profileManager),
  };
  const server = createMuxServer(handlers);
  await new Promise((resolve) => server.listen(cfg.port, cfg.host, resolve));
  const addr = server.address();

  try {
    const { handshake: obfsHandshake, stream, encKey, encIv } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, obfsHandshake);
    const payload = "profiled-faketls-payload";
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);

    const result = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake), wrapTlsRecord(sent)]));
      });
      let rawBuf = Buffer.alloc(0);
      let phase = "consume-response";
      let tlsIn = null;
      let appBuf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`profiled timeout phase=${phase} got: ${appBuf.toString("hex")}`)), 3000);
      socket.on("data", (d) => {
        rawBuf = Buffer.concat([rawBuf, d]);
        if (phase === "consume-response") {
          while (rawBuf.length >= 5) {
            const recLen = rawBuf.readUInt16BE(3);
            if (rawBuf.length < 5 + recLen) break;
            const recType = rawBuf[0];
            rawBuf = rawBuf.subarray(5 + recLen);
            if (recType === 0x17) {
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
    assert.equal(result, payload, "profiled fake-TLS must round-trip the MTProto payload");
  } finally {
    profileManager.stop();
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    origin.closeAllConnections?.();
    server.close();
    fakeDc.close();
    origin.close();
  }
});

test("e2e: pending-handshake cap rejects slowloris connections", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")], mtprotoPendingMax: 1 },
    () => ({ host: "127.0.0.1", port: dcAddr.port })
  );

  try {
    // First connection: send only 8 bytes (no full handshake) -> holds the single pending slot.
    const holder = net.connect(addr.port, "127.0.0.1", () => {
      holder.write(Buffer.alloc(8, 0xab)); // not enough for a 64-byte handshake
    });
    await new Promise((r) => holder.once("connect", r));

    // Give the proxy a moment to register the pending socket.
    await new Promise((r) => setTimeout(r, 100));

    // Second connection: must be rejected (pending cap reached) before completing handshake.
    const closed = await new Promise((resolve) => {
      const s = net.connect(addr.port, "127.0.0.1", () => {
        s.write(Buffer.alloc(8, 0xcd));
      });
      s.on("close", () => resolve(true));
      s.on("error", () => resolve(true));
      setTimeout(() => resolve(false), 1500);
    });
    assert.equal(closed, true, "pending-cap must drop the slowloris connection");

    holder.destroy();
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("e2e: DC fallback — first candidate unreachable, second candidate serves the relay", async () => {
  const secret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();

  // A dead port: listen, grab the port, close -> connect will be refused fast.
  const dead = net.createServer();
  await new Promise((r) => dead.listen(0, "127.0.0.1", r));
  const deadPort = dead.address().port;
  await new Promise((r) => dead.close(r));

  // Ordered candidates: dead first, real fake-DC second -> proxy must fall back.
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => [
      { host: "127.0.0.1", port: deadPort },
      { host: "127.0.0.1", port: dcAddr.port },
    ]
  );

  try {
    const { handshake, stream, encKey, encIv } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
    const payload = "fallback-echo";
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);

    const result = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([handshake, sent]));
      });
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`timeout, got: ${buf.toString("hex")}`)), 4000);
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

    // Reaching the echo proves the proxy fell back from the dead candidate to the live one.
    assert.equal(result, payload);
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});
