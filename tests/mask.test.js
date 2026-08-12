// FILE: tests/mask.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-MASK traffic-masking splice and reject_handshake alert
//   SCOPE: failed fake-TLS auth -> transparent splice to a local mask server; reject -> TLS alert; drop -> destroy
//   DEPENDS: M-MASK, M-FAKETLS, M-MUX, M-MTPROTO-SERVER
//   LINKS: V-M-MASK
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { randomBytes } from "node:crypto";
import { createMuxServer } from "../src/mux.js";
import { createMtprotoHandler } from "../src/mtproto-server.js";
import { createConnectHandler } from "../src/proxy.js";
import { makeLog } from "../src/log.js";
import { buildTlsAlert, extractSni, buildAlpnExtension } from "../src/faketls.js";
import { maskConnection } from "../src/mask.js";

// Minimal TLS ClientHello frame (>=512 bytes) without a valid secret digest -> auth fails.
function buildNonKeyedClientHello(sni) {
  const sessionId = randomBytes(16);
  const cipherSuites = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const compression = Buffer.from([0x01, 0x00]);
  const padLen = 533;
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
  padExt.writeUInt16BE(padLen, 2);
  const exts = [padExt];
  if (sni) exts.unshift(buildSniExtension(sni));
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(Buffer.concat(exts).length, 0);
  const extensions = Buffer.concat([extTotal, ...exts]);
  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    randomBytes(32), // random/digest (no valid HMAC -> auth fail)
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
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recordLenBuf, handshakeMsg]);
}

function buildSniExtension(host) {
  const name = Buffer.from(host, "latin1");
  const snEntry = Buffer.concat([Buffer.from([0x00]), Buffer.from([name.length & 0xff, (name.length >> 8) & 0xff]).reverse(), name]);
  // server_name list: listLen(2) + entries
  const listLen = Buffer.alloc(2);
  listLen.writeUInt16BE(snEntry.length, 0);
  const body = Buffer.concat([listLen, snEntry]);
  const ext = Buffer.alloc(4);
  ext.writeUInt16BE(0x0000, 0);
  ext.writeUInt16BE(body.length, 2);
  return Buffer.concat([ext, body]);
}

function startMaskServer() {
  const server = net.createServer((socket) => {
    socket.on("data", () => {}); // drain
    socket.write("MASK-OK\n");
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

function startProxy(cfgOverrides, extras = {}) {
  const cfg = {
    port: 0,
    host: "127.0.0.1",
    maxTunnels: 32,
    idleTimeoutMs: 5_000,
    rules: [],
    mtprotoSecrets: [],
    mtprotoPort: 0,
    mtprotoMaxConnections: 64,
    mtprotoTlsDomain: "www.google.com",
    mtprotoMaskHost: "127.0.0.1",
    mtprotoMaskPort: 0,
    mtprotoUnknownSniAction: "mask",
    ...cfgOverrides,
  };
  const log = makeLog();
  const allow = () => true;
  const auth = () => true;
  const httpHandlers = createConnectHandler(cfg, allow, auth, log);
  const handlers = {
    "http-connect": httpHandlers["http-connect"],
    "http-other": httpHandlers["http-other"],
    "mtproto": createMtprotoHandler(cfg, log, () => null, null, extras.maskImpl || maskConnection),
  };
  const server = createMuxServer(handlers);
  return new Promise((resolve) => {
    server.listen(cfg.port, cfg.host, () => resolve({ server, addr: server.address(), cfg }));
  });
}

test("extractSni: parses the hostname from a ClientHello with SNI", () => {
  const hello = buildNonKeyedClientHello("example.com");
  assert.equal(extractSni(hello), "example.com");
});

test("extractSni: returns null when no SNI extension is present", () => {
  const hello = buildNonKeyedClientHello(null);
  assert.equal(extractSni(hello), null);
});

test("buildTlsAlert: produces unrecognized_name alert bytes", () => {
  const alert = buildTlsAlert(112);
  assert.deepEqual(Array.from(alert), [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70]);
});

test("buildAlpnExtension: advertises protocols with correct type and list length", () => {
  const ext = buildAlpnExtension(["h2"]);
  assert.equal(ext.readUInt16BE(0), 0x0010);
  // body: listLen(2)=3, protoLen(1)=2, "h2"
  assert.equal(ext.readUInt16BE(4), 3);
  assert.equal(ext[6], 2);
  assert.equal(ext.subarray(7, 9).toString("latin1"), "h2");
});

test("mask: failed fake-TLS auth splices the client to the mask server (default action=mask)", async () => {
  const mask = await startMaskServer();
  const { server, addr } = await startProxy({ mtprotoMaskPort: mask.address().port });
  try {
    const hello = buildNonKeyedClientHello(null); // no SNI, invalid digest -> auth fail -> mask
    const reply = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(hello));
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`mask timeout, got: ${buf.toString("latin1")}`)), 3000);
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
    assert.ok(reply.includes("MASK-OK"), "client must receive the real mask-server response");
  } finally {
    server.closeAllConnections?.();
    mask.closeAllConnections?.();
    server.close();
    mask.close();
  }
});

test("mask: unknown SNI is routed to the mask server", async () => {
  const mask = await startMaskServer();
  const { server, addr } = await startProxy({
    mtprotoTlsDomain: "www.google.com",
    mtprotoMaskPort: mask.address().port,
  });
  try {
    const hello = buildNonKeyedClientHello("evil.example"); // SNI mismatch -> unknown -> mask
    const reply = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(hello));
      let buf = Buffer.alloc(0);
      const timer = setTimeout(() => reject(new Error(`timeout, got: ${buf.toString("latin1")}`)), 3000);
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
    assert.ok(reply.includes("MASK-OK"));
  } finally {
    server.closeAllConnections?.();
    mask.closeAllConnections?.();
    server.close();
    mask.close();
  }
});

test("reject: unknown SNI with action=reject emits TLS unrecognized_name alert", async () => {
  const { server, addr } = await startProxy({
    mtprotoTlsDomain: "www.google.com",
    mtprotoUnknownSniAction: "reject",
    mtprotoMaskPort: 1, // should not be used
  });
  try {
    const hello = buildNonKeyedClientHello("evil.example");
    const got = await new Promise((resolve, reject) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(hello));
      const chunks = [];
      const timer = setTimeout(() => reject(new Error("timeout")), 3000);
      socket.on("data", (d) => {
        chunks.push(d);
        clearTimeout(timer);
        socket.destroy();
        resolve(Buffer.concat(chunks));
      });
      socket.on("close", () => resolve(Buffer.concat(chunks)));
      socket.on("error", reject);
    });
    assert.equal(got[0], 0x15, "first byte must be a TLS alert record");
    assert.equal(got[5], 0x02, "fatal alert level");
    assert.equal(got[6], 0x70, "unrecognized_name (112)");
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test("drop: action=drop destroys the socket with no response (legacy behaviour)", async () => {
  const { server, addr } = await startProxy({
    mtprotoUnknownSniAction: "drop",
  });
  try {
    const hello = buildNonKeyedClientHello(null);
    const closed = await new Promise((resolve) => {
      const socket = net.connect(addr.port, "127.0.0.1", () => socket.write(hello));
      let gotData = false;
      socket.on("data", () => { gotData = true; });
      socket.on("close", () => resolve({ closed: true, gotData }));
      socket.on("error", () => resolve({ closed: true, gotData }));
      setTimeout(() => resolve({ closed: false, gotData }), 1500);
    });
    assert.equal(closed.closed, true, "socket must be closed");
    assert.equal(closed.gotData, false, "no bytes must be written in drop mode");
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});