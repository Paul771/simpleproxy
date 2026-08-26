// FILE: tests/hardening.test.js
// VERSION: 1.2.0
// START_MODULE_CONTRACT
//   PURPOSE: Wave-1 hardening regression tests: pending-slot release, bounded handshake
//            buffers, bounded masked sessions; Wave-2 multi-tenant enforcement: mid-stream
//            byte-quota teardown, strict unknown-user denial, CONNECT header slowloris guard;
//            Wave-A DPI-window resilience: MTProto-specific idle/handshake timeout overrides
//            and handshake-death observability
//   SCOPE: C-1 pendingHandshakes leak (auth-fail / bad-dc paths), B4 buffer caps
//          (handshake_overflow), B3 mask relay byte cap, MTPROTO_MASK_RELAY_MAX_BYTES config;
//          W2-2 mtproto_quota_exceeded teardown, W2-3 MTPROTO_USERS_STRICT deny-unknown,
//          W2-4 connect_header_timeout on stalled partial CONNECT headers;
//          A-1 mtprotoIdleTimeoutMs override, A-2 mtprotoHandshakeTimeoutMs +
//          mtproto_handshake_timeout marker + simpleproxy_handshake_timeouts_total
//   DEPENDS: M-MTPROTO, M-MUX, M-MTPROTO-SERVER, M-MASK, M-METRICS, M-CONFIG, M-USER-STORE,
//            M-PROXY
//   LINKS: V-M-MTPROTO-SERVER, V-M-MASK, V-M-CONFIG, V-M-USER-STORE, V-M-PROXY
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT
//
// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.2.0 - wave-A tests added: config parsing of MTPROTO_IDLE_TIMEOUT_MS /
//               MTPROTO_HANDSHAKE_TIMEOUT_MS (unset -> null inherit), idle override reaps a
//               stalled relay per override value, handshake timeout logs the marker and bumps
//               simpleproxy_handshake_timeouts_total
// END_CHANGE_SUMMARY

// START_MODULE_MAP
//   sha256 - SHA-256 over concatenated parts (obfuscated2 key derivation helper)
//   buildClientHandshake - build a valid/wrong obfuscated2 client handshake + crypto state
//   startFakeDc - minimal Telegram DC emulator echoing decrypted payloads
//   hmacSha256 - HMAC-SHA256 helper for fake-TLS digests
//   buildFakeTlsClientHello - synthetic fake-TLS ClientHello carrying an obfs handshake
//   startEchoMaskServer - mask upstream echoing received bytes back
//   startProxy - mux server wiring a real mtproto handler with injectable resolver/metrics
//   awaitClose - await socket closure (or error) with a deadline
//   roundTripPayload - full obfuscated2 round trip through the proxy (encrypt -> echo -> decrypt)
// END_MODULE_MAP

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { Duplex } from "node:stream";
import { randomBytes, createHash, createHmac } from "node:crypto";
import { createMuxServer } from "../src/mux.js";
import { createMtprotoHandler } from "../src/mtproto-server.js";
import { makeLog } from "../src/log.js";
import { createMetrics } from "../src/metrics.js";
import { createAesCtr } from "../src/mtproto.js";
import { loadConfig } from "../src/config.js";
import { wrapTlsRecord } from "../src/faketls.js";
import { maskConnection } from "../src/mask.js";
import { createUserStore } from "../src/user-store.js";
import { createConnectHandler } from "../src/proxy.js";

const PROTO_TAG_ABRIDGED = Buffer.from([0xef, 0xef, 0xef, 0xef]);

function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

// --- Client emulator (mirrors tests/mtproto.e2e.test.js helpers) ---
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
  const reversed = Buffer.from(init.subarray(8, 56)).reverse();
  const encKey = sha256(reversed.subarray(0, 32), secret);
  const encIv = reversed.subarray(32, 48);
  return { handshake, stream, encKey, encIv };
}

// --- Fake DC: echoes decrypted payloads back (same shape as the e2e suite) ---
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
        const keyUp = rndEnc.subarray(8, 40);
        const ivUp = rndEnc.subarray(40, 56);
        const rev = Buffer.from(rndEnc.subarray(8, 56)).reverse();
        tgDec = createAesCtr(keyUp, ivUp);
        tgEnc = createAesCtr(rev.subarray(0, 32), rev.subarray(32, 48));
        tgDec.decrypt(Buffer.alloc(64));
        if (buf.length > 0) {
          const data = buf;
          buf = Buffer.alloc(0);
          socket.write(tgEnc.encrypt(tgDec.decrypt(data)));
        }
        return;
      }
      if (ready && buf.length > 0) {
        const data = buf;
        buf = Buffer.alloc(0);
        socket.write(tgEnc.encrypt(tgDec.decrypt(data)));
      }
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

// --- fake-TLS ClientHello builder (subset of tests/mtproto.e2e.test.js) ---
const FT_DIGEST_POS = 11;
const FT_DIGEST_LEN = 32;

function hmacSha256(key, msg) {
  return createHmac("sha256", key).update(msg).digest();
}

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

function startEchoMaskServer() {
  const server = net.createServer((socket) => {
    socket.write("MASK-OK\n"); // splice greeting, mirrors tests/mtproto.e2e.test.js
    socket.on("data", (d) => socket.write(d));
    socket.on("error", () => {});
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

// Real mtproto handler behind a real mux, with injectable resolver and a real metrics
// registry so pending-slot accounting can be asserted deterministically.
function startProxy(cfgOverrides = {}, resolveDc, metrics = null) {
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
  const handlers = {
    "http-connect": () => {},
    "http-other": () => {},
    "mtproto": createMtprotoHandler(cfg, log, resolveDc, null, null, null, metrics),
  };
  const server = createMuxServer(handlers);
  return new Promise((resolve) => {
    server.listen(cfg.port, cfg.host, () => resolve({ server, addr: server.address() }));
  });
}

// Await socket closure (or error) with a deadline.
function awaitClose(socket, ms = 2000) {
  return new Promise((resolve) => {
    const done = () => resolve(true);
    socket.once("close", done);
    socket.once("error", done);
    setTimeout(() => resolve(false), ms);
  });
}

test("hardening: pending slots survive a burst of wrong-secret probes (C-1 leak)", async () => {
  const goodSecret = randomBytes(16);
  const wrongSecret = randomBytes(16);
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
  const metrics = createMetrics();
  // Small cap: pre-fix, 10 leaked slots would exceed it and brick the listener.
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [goodSecret.toString("hex")], mtprotoPendingMax: 4 },
    () => ({ host: "127.0.0.1", port: dcAddr.port }),
    metrics
  );

  try {
    // 10 full handshakes with a wrong secret: each reaches finishHandshakeAndRelay,
    // fails auth there (completed=true), and must release its pending slot.
    for (let i = 0; i < 10; i++) {
      const { handshake } = buildClientHandshake(wrongSecret, PROTO_TAG_ABRIDGED, 1);
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(handshake));
      const closed = await awaitClose(socket);
      assert.equal(closed, true, `probe ${i} must be closed`);
    }
    // Let close handlers settle.
    await new Promise((r) => setTimeout(r, 50));

    assert.equal(
      metrics.get("simpleproxy_pending_mtproto"),
      0,
      "pending gauge must return to zero after failed handshakes"
    );

    // The decisive check: a VALID client must still be served after the probe burst.
    const { handshake, stream, encKey, encIv } = buildClientHandshake(goodSecret, PROTO_TAG_ABRIDGED, 1);
    const payload = "after-probes";
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);
    const result = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([handshake, sent]));
      });
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`timeout, got ${buf.length} bytes`)), 3000);
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
    assert.equal(result, payload, "valid connection must work after the probe burst");
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("hardening: bad-dc failure releases the pending slot", async () => {
  const secret = randomBytes(16);
  const metrics = createMetrics();
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    () => null, // resolver yields no candidates -> mtproto_bad_dc
    metrics
  );

  try {
    for (let i = 0; i < 5; i++) {
      const { handshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(handshake));
      assert.equal(await awaitClose(socket), true, `bad-dc probe ${i} must be closed`);
    }
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(metrics.get("simpleproxy_pending_mtproto"), 0, "slots must be released on bad-dc");
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test("hardening: pre-handshake buffer overflow destroys the socket (handshake_overflow)", async () => {
  const secret = randomBytes(16);
  const { server, addr } = await startProxy({ mtprotoSecrets: [secret.toString("hex")] }, () => null);

  try {
    // First byte 0xab (not TLS): plain phase, accumulates towards the 64-byte handshake —
    // but we push 65 KiB, crossing HANDSHAKE_BUF_MAX_BYTES before any handshake completes.
    const socket = net.connect(addr.port, "127.0.0.1", () => {
      socket.write(Buffer.alloc(65 * 1024, 0xab));
    });
    assert.equal(await awaitClose(socket), true, "oversized pre-handshake buffer must be destroyed");
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test("hardening: pending-data overflow during a stalled DC connect destroys the socket", async () => {
  const secret = randomBytes(16);
  const { server, addr } = await startProxy(
    { mtprotoSecrets: [secret.toString("hex")] },
    // Blackhole address: TCP connect hangs (well beyond the test deadline), keeping the
    // completed-handshake connection in the pendingData collection window.
    () => ({ host: "10.255.255.1", port: 81 })
  );

  try {
    const { handshake: obfsHandshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
    const { hello: tlsHello } = buildFakeTlsClientHello(secret, obfsHandshake);

    const closed = await new Promise((resolve) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake)]));
        // 2 MiB of app-data records: crosses PENDING_DATA_MAX_BYTES (1 MiB) while the
        // upstream connect is still pending -> handshake_overflow(pending_data).
        const chunk = randomBytes(64 * 1024);
        let sent = 0;
        const pump = () => {
          while (sent < 2 * 1024 * 1024) {
            sent += chunk.length;
            if (!socket.write(wrapTlsRecord(chunk))) {
              socket.once("drain", pump);
              return;
            }
          }
        };
        pump();
      });
      socket.once("close", () => resolve(true));
      socket.once("error", () => resolve(true));
      setTimeout(() => resolve(false), 8000);
    });

    assert.equal(closed, true, "connection must be destroyed after pending-data overflow");
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test("hardening: masked session is torn down at MTPROTO_MASK_RELAY_MAX_BYTES", async () => {
  const goodSecret = randomBytes(16);
  const wrongSecret = randomBytes(16);
  const mask = await startEchoMaskServer();
  const maskAddr = mask.address();

  const cfg = {
    port: 0,
    host: "127.0.0.1",
    maxTunnels: 32,
    idleTimeoutMs: 30_000,
    rules: [],
    mtprotoSecrets: [goodSecret.toString("hex")],
    mtprotoPort: 0,
    mtprotoMaxConnections: 64,
    mtprotoPendingMax: 256,
    mtprotoTlsDomain: "www.google.com",
    mtprotoMaskHost: "127.0.0.1",
    mtprotoMaskPort: maskAddr.port,
    mtprotoUnknownSniAction: "mask",
    mtprotoMaskRelayMaxBytes: 64 * 1024,
  };
  const log = makeLog();
  const handlers = {
    "http-connect": () => {},
    "http-other": () => {},
    "mtproto": createMtprotoHandler(cfg, log, undefined, null, maskConnection, null, null),
  };
  const server = createMuxServer(handlers);
  await new Promise((resolve) => server.listen(cfg.port, cfg.host, resolve));
  const addr = server.address();

  try {
    // Wrong secret -> faketls_auth_fail -> routeUnknown(mask) -> spliced to the echo server.
    const { handshake: obfsHandshake } = buildClientHandshake(goodSecret, PROTO_TAG_ABRIDGED, 1);
    const { hello: tlsHello } = buildFakeTlsClientHello(wrongSecret, obfsHandshake);

    const outcome = await new Promise((resolve) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.write(Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake)]));
      });
      let sawMaskGreeting = false;
      let sawCapTeardown = false;
      // Blast far beyond the 64 KiB cap once the splice greeting arrives; the masked
      // session must be torn down (mask_relay_cap) instead of relaying forever.
      const chunk = randomBytes(32 * 1024);
      let sent = 0;
      const pump = () => {
        while (!socket.destroyed && sent < 1024 * 1024) {
          sent += chunk.length;
          if (!socket.write(chunk)) {
            socket.once("drain", pump);
            return;
          }
        }
      };
      socket.on("data", (d) => {
        if (d.includes("MASK-OK")) {
          sawMaskGreeting = true;
          pump();
        }
      });
      socket.once("close", () => {
        sawCapTeardown = sent > 64 * 1024;
        resolve({ sawMaskGreeting, sawCapTeardown });
      });
      socket.once("error", () => {});
      setTimeout(() => {
        socket.destroy();
        resolve({ sawMaskGreeting, sawCapTeardown });
      }, 8000);
    });

    assert.equal(outcome.sawMaskGreeting, true, "client must be spliced to the mask server");
    assert.equal(outcome.sawCapTeardown, true, "masked session must be torn down after the byte cap");
  } finally {
    server.closeAllConnections?.();
    mask.closeAllConnections?.();
    server.close();
    mask.close();
  }
});

test("config: MTPROTO_MASK_RELAY_MAX_BYTES default, override, disable, invalid", () => {
  const defaults = loadConfig({});
  assert.equal(defaults.mtprotoMaskRelayMaxBytes, 33_554_432, "default must be 32 MiB");

  const custom = loadConfig({ MTPROTO_MASK_RELAY_MAX_BYTES: "1048576" });
  assert.equal(custom.mtprotoMaskRelayMaxBytes, 1_048_576);

  const disabled = loadConfig({ MTPROTO_MASK_RELAY_MAX_BYTES: "0" });
  assert.equal(disabled.mtprotoMaskRelayMaxBytes, 0, "0 must disable the cap");

  assert.throws(
    () => loadConfig({ MTPROTO_MASK_RELAY_MAX_BYTES: "-5" }),
    /INVALID_ENV/
  );
  assert.throws(
    () => loadConfig({ MTPROTO_MASK_RELAY_MAX_BYTES: "soon" }),
    /INVALID_ENV/
  );
});

// --- Wave 2 helpers ---

// START_CONTRACT: roundTripPayload
//   PURPOSE: Full obfuscated2 round trip against a running proxy: handshake -> encrypted
//            payload -> DC echo -> decrypt, asserting byte equality end-to-end
//   INPUTS: { addr: {port}, secretBuf: Buffer(32), payload: string, timeoutMs?: number }
//   OUTPUTS: { Promise<string> - decrypted echo of payload }
//   SIDE_EFFECTS: opens/closes one TCP connection
//   LINKS: fn-buildClientHandshake, V-M-MTPROTO-SERVER
// END_CONTRACT: roundTripPayload
function roundTripPayload(addr, secretBuf, payload, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const { handshake, stream, encKey, encIv } = buildClientHandshake(secretBuf, PROTO_TAG_ABRIDGED, 1);
    const sent = stream.encrypt(Buffer.from(payload));
    const clientDec = createAesCtr(encKey, encIv);
    const socket = net.connect(addr.port, "127.0.0.1", () => {
      socket.write(Buffer.concat([handshake, sent]));
    });
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => reject(new Error(`round-trip timeout, got ${buf.length} bytes`)), timeoutMs);
    socket.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= payload.length) {
        clearTimeout(timer);
        socket.destroy();
        resolve(clientDec.decrypt(buf.subarray(0, payload.length)).toString());
      }
    });
    socket.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
  });
}

// Multi-tenant proxy fixture: real mtproto handler behind mux, injectable userStore/log/
// metrics so markers and counters can be asserted deterministically.
async function startTenantProxy(cfgOverrides, userStore, logCollector, metrics) {
  const fakeDc = await startFakeDc();
  const dcAddr = fakeDc.address();
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
  const handlers = {
    "http-connect": () => {},
    "http-other": () => {},
    "mtproto": createMtprotoHandler(cfg, logCollector, () => ({ host: "127.0.0.1", port: dcAddr.port }), null, null, null, metrics, userStore),
  };
  const server = createMuxServer(handlers);
  await new Promise((resolve) => server.listen(cfg.port, cfg.host, resolve));
  return { server, fakeDc, addr: server.address() };
}

test("hardening: per-user byte quota tears the relay down mid-stream (mtproto_quota_exceeded)", async () => {
  const aliceSecret = randomBytes(16);
  const metrics = createMetrics();
  const logs = [];
  const logCollector = (event, ref, src, detail) => logs.push({ event, ref, src, detail });
  const userStore = createUserStore([
    { user: "alice", secretHex: aliceSecret.toString("hex"), maxConns: null, expiresAt: null, byteQuota: 1024 },
  ]);
  const { server, fakeDc, addr } = await startTenantProxy(
    { mtprotoSecrets: [aliceSecret.toString("hex")] },
    userStore,
    logCollector,
    metrics
  );

  try {
    // One blast of 4 KiB crosses the 1 KiB quota during relay setup -> immediate teardown.
    const { handshake } = buildClientHandshake(aliceSecret, PROTO_TAG_ABRIDGED, 1);
    const closed = await new Promise((resolve) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => {
        socket.end(Buffer.concat([handshake, randomBytes(4 * 1024)]));
      });
      socket.once("close", () => resolve(true));
      socket.once("error", () => resolve(true));
      setTimeout(() => {
        socket.destroy();
        resolve(false);
      }, 4000);
    });

    assert.equal(closed, true, "quota-exhausted connection must be torn down");
    assert.ok(
      logs.some((l) => l.event === "mtproto_quota_exceeded"),
      "mtproto_quota_exceeded marker must be logged"
    );
    assert.equal(
      metrics.get("simpleproxy_quota_exceeded_total") >= 1,
      true,
      "simpleproxy_quota_exceeded_total must count the kick"
    );
    assert.equal(
      userStore.snapshot().alice.bytes >= 1024,
      true,
      "bytes must be charged up to (and past) the quota before the kick"
    );
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("hardening: strict mode denies unknown secrets but keeps listed users working", async () => {
  const aliceSecret = randomBytes(16);
  const mallorySecret = randomBytes(16);
  const metrics = createMetrics();
  const logs = [];
  const logCollector = (event, ref, src, detail) => logs.push({ event, ref, src, detail });
  // Only alice exists in the tenant table; mallory's secret passes HMAC (it IS configured)
  // but resolves to no user record.
  const userStore = createUserStore([
    { user: "alice", secretHex: aliceSecret.toString("hex"), maxConns: null, expiresAt: null, byteQuota: null },
  ]);
  const { server, fakeDc, addr } = await startTenantProxy(
    { mtprotoSecrets: [aliceSecret.toString("hex"), mallorySecret.toString("hex")], mtprotoUsersStrict: true },
    userStore,
    logCollector,
    metrics
  );

  try {
    const { handshake } = buildClientHandshake(mallorySecret, PROTO_TAG_ABRIDGED, 1);
    const socket = net.connect(addr.port, "127.0.0.1", () => socket.end(handshake));
    assert.equal(await awaitClose(socket), true, "unknown secret must be denied in strict mode");
    assert.ok(
      logs.some((l) => l.event === "mtproto_user_unknown"),
      "mtproto_user_unknown marker must be logged"
    );
    assert.equal(metrics.get("simpleproxy_user_unknown_total"), 1);

    // Strict mode must not punish legitimate tenants.
    const echoed = await roundTripPayload(addr, aliceSecret, "strict-alice-ok");
    assert.equal(echoed, "strict-alice-ok", "listed user must keep working under strict mode");
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("hardening: strict mode with an EMPTY tenant table keeps single-tenant secrets working", async () => {
  const secret = randomBytes(16);
  const logs = [];
  const logCollector = (event, ref, src, detail) => logs.push({ event, ref, src, detail });
  // Store exists (always-built since W2-1) but holds zero tenants; strict flag on.
  // Nothing to resolve against -> denial must stay gated off (size() === 0).
  const userStore = createUserStore([]);
  const { server, fakeDc, addr } = await startTenantProxy(
    { mtprotoSecrets: [secret.toString("hex")], mtprotoUsersStrict: true },
    userStore,
    logCollector,
    createMetrics()
  );

  try {
    const echoed = await roundTripPayload(addr, secret, "empty-table-ok");
    assert.equal(echoed, "empty-table-ok", "strict mode without tenants must not blackhole secrets");
    assert.ok(
      !logs.some((l) => l.event === "mtproto_user_unknown"),
      "no unknown-user denials expected with an empty tenant table"
    );
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("hardening: non-strict mode preserves the legacy unlimited path for unknown secrets", async () => {
  const aliceSecret = randomBytes(16);
  const mallorySecret = randomBytes(16);
  const logs = [];
  const logCollector = (event, ref, src, detail) => logs.push({ event, ref, src, detail });
  const userStore = createUserStore([
    { user: "alice", secretHex: aliceSecret.toString("hex"), maxConns: null, expiresAt: null, byteQuota: null },
  ]);
  // No mtprotoUsersStrict -> default false -> mallory takes the legacy unlimited path.
  const { server, fakeDc, addr } = await startTenantProxy(
    { mtprotoSecrets: [aliceSecret.toString("hex"), mallorySecret.toString("hex")] },
    userStore,
    logCollector,
    createMetrics()
  );

  try {
    const echoed = await roundTripPayload(addr, mallorySecret, "legacy-mallory-ok");
    assert.equal(echoed, "legacy-mallory-ok", "unknown secret must still relay when strict mode is off");
    assert.ok(
      !logs.some((l) => l.event === "mtproto_user_unknown"),
      "strict-only marker must stay silent"
    );
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("hardening: stalled partial CONNECT header is answered 408 and destroyed (W2-4)", async () => {
  const logs = [];
  const written = [];
  const sock = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      written.push(Buffer.from(chunk));
      cb();
    },
  });
  sock.remoteAddress = "203.0.113.77";

  const handlers = createConnectHandler(
    { maxTunnels: 8, connectHeaderTimeoutMs: 50 },
    () => true, // allow
    () => true, // auth
    (event) => logs.push(event)
  );

  // Incomplete header: method line without the terminating CRLFCRLF.
  handlers["http-connect"](sock, Buffer.from("CONNECT api.telegram.org:443 HTTP/1.1\r\n"));
  await new Promise((r) => setTimeout(r, 150));

  assert.equal(sock.destroyed, true, "stalled header socket must be destroyed");
  assert.ok(
    Buffer.concat(written).toString("latin1").includes("408"),
    "server must answer 408 Request Timeout"
  );
  assert.ok(logs.includes("connect_header_timeout"), "connect_header_timeout marker must be logged");

  // Regression guard: a COMPLETED header must never hit the timer (auth-fail answers 407
  // synchronously instead of dialing upstream).
  const logs2 = [];
  const written2 = [];
  const sock2 = new Duplex({
    read() {},
    write(chunk, _enc, cb) {
      written2.push(Buffer.from(chunk));
      cb();
    },
  });
  sock2.remoteAddress = "203.0.113.78";
  const handlers2 = createConnectHandler(
    { maxTunnels: 8, connectHeaderTimeoutMs: 50 },
    () => true,
    () => false, // force 407 without touching the network
    (event) => logs2.push(event)
  );
  handlers2["http-connect"](
    sock2,
    Buffer.from("CONNECT api.telegram.org:443 HTTP/1.1\r\nHost: api.telegram.org:443\r\n\r\n")
  );
  await new Promise((r) => setTimeout(r, 150));

  assert.ok(
    Buffer.concat(written2).toString("latin1").includes("407"),
    "complete header must proceed to normal handling (407 here)"
  );
  assert.ok(!logs2.includes("connect_header_timeout"), "timer must not fire for complete headers");
});

// --- Wave A: DPI-window resilience ---

test("config: MTPROTO_IDLE_TIMEOUT_MS / MTPROTO_HANDSHAKE_TIMEOUT_MS unset -> null, garbage -> INVALID_ENV", () => {
  const defaults = loadConfig({ MTPROTO_SECRET: "25a36e7142e90fa52c2f29e276392a7f" });
  assert.equal(defaults.mtprotoIdleTimeoutMs, null, "unset idle override must inherit (null)");
  assert.equal(defaults.mtprotoHandshakeTimeoutMs, null, "unset handshake override must inherit (null)");

  const custom = loadConfig({
    MTPROTO_SECRET: "25a36e7142e90fa52c2f29e276392a7f",
    MTPROTO_IDLE_TIMEOUT_MS: "300000",
    MTPROTO_HANDSHAKE_TIMEOUT_MS: "8000",
  });
  assert.equal(custom.mtprotoIdleTimeoutMs, 300_000);
  assert.equal(custom.mtprotoHandshakeTimeoutMs, 8_000);

  for (const bad of ["0", "-5", "soon"]) {
    assert.throws(
      () => loadConfig({ MTPROTO_SECRET: "25a36e7142e90fa52c2f29e276392a7f", MTPROTO_IDLE_TIMEOUT_MS: bad }),
      /INVALID_ENV/,
      `MTPROTO_IDLE_TIMEOUT_MS="${bad}" must be rejected`
    );
    assert.throws(
      () => loadConfig({ MTPROTO_SECRET: "25a36e7142e90fa52c2f29e276392a7f", MTPROTO_HANDSHAKE_TIMEOUT_MS: bad }),
      /INVALID_ENV/,
      `MTPROTO_HANDSHAKE_TIMEOUT_MS="${bad}" must be rejected`
    );
  }
});

test("hardening: handshake timeout logs marker and counts simpleproxy_handshake_timeouts_total (A-2)", async () => {
  const secret = randomBytes(16);
  const metrics = createMetrics();
  const logs = [];
  const logCollector = (event, ref, src, detail) => logs.push({ event, ref, src, detail });
  // Silent client: opens the socket and sends nothing — exactly what a DPI drop window
  // looks like from the server side (flight discarded before reaching us).
  const { server, fakeDc, addr } = await startTenantProxy(
    { mtprotoSecrets: [secret.toString("hex")], mtprotoHandshakeTimeoutMs: 80 },
    createUserStore([]),
    logCollector,
    metrics
  );

  try {
    // Junk bytes route through the mux into the mtproto handler (PEEK_LEN=8 satisfied,
    // classify: not HTTP), but stay far short of the 64-byte handshake -> only the
    // override can reap this.
    const socket = net.connect(addr.port, "127.0.0.1", () =>
      socket.write(Buffer.alloc(16, 0x01))
    );
    assert.equal(await awaitClose(socket, 1500), true, "silent socket must be reaped by the override");

    assert.ok(
      logs.some((l) => l.event === "mtproto_handshake_timeout"),
      "mtproto_handshake_timeout must be logged on timer fire"
    );
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(metrics.get("simpleproxy_handshake_timeouts_total"), 1);
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});

test("hardening: MTPROTO_IDLE_TIMEOUT_MS override reaps a stalled relay per its value (A-1)", async () => {
  const secret = randomBytes(16);
  const logs = [];
  const logCollector = (event, ref, src, detail) => logs.push({ event, ref, src, detail });
  const { server, fakeDc, addr } = await startTenantProxy(
    { mtprotoSecrets: [secret.toString("hex")], mtprotoIdleTimeoutMs: 150 },
    createUserStore([]),
    logCollector,
    createMetrics()
  );

  try {
    // Establish the relay (handshake + DC connect) and then go silent: no further bytes,
    // socket kept OPEN (no FIN — a half-closed socket would tear down before the timer).
    // The shared idleTimeoutMs is 120s here; only the MTProto override may reap this pair.
    const closed = await new Promise((resolve) => {
      const { handshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(handshake));
      socket.once("close", () => resolve(true));
      socket.once("error", () => resolve(true));
      setTimeout(() => {
        socket.destroy();
        resolve(false);
      }, 2000);
    });

    assert.equal(closed, true, "stalled relay must be reaped by the MTProto-specific override");
    assert.ok(
      logs.some((l) => l.event === "mtproto_idle_timeout"),
      "mtproto_idle_timeout must be logged"
    );
  } finally {
    server.closeAllConnections?.();
    fakeDc.closeAllConnections?.();
    server.close();
    fakeDc.close();
  }
});
