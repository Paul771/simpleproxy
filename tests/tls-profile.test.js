// FILE: tests/tls-profile.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-TLS-PROFILE capture, replay and profile manager
//   SCOPE: scripted local TLS origin -> capture profile; buildServerHello replay; manager start/get/stop
//   DEPENDS: M-TLS-PROFILE, M-FAKETLS
//   LINKS: V-M-TLS-PROFILE
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { randomBytes, createHmac } from "node:crypto";
import {
  buildCaptureClientHello,
  captureTlsProfile,
  createProfileManager,
  createTlsRecordObserver,
} from "../src/tls-profile.js";
import { buildServerHello } from "../src/faketls.js";

// Build a scripted TLS 1.3 server flight: ServerHello(cipher, alpn) + CCS + N app-data records.
function buildScriptedFlight({ cipher, alpn, appDataSizes }) {
  const parts = [];

  // ServerHello handshake body.
  const sid = Buffer.alloc(0);
  let srvExtensions = Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions TLS 1.3
  if (alpn) {
    const name = Buffer.from(alpn, "latin1");
    const snEntry = Buffer.concat([Buffer.from([name.length]), name]);
    const list = Buffer.concat([Buffer.from([snEntry.length & 0xff, (snEntry.length >> 8) & 0xff]), snEntry]);
    const alpnExt = Buffer.concat([Buffer.from([0x00, 0x10, 0x00, 0x00]), list]);
    alpnExt.writeUInt16BE(list.length, 2);
    srvExtensions = Buffer.concat([srvExtensions, alpnExt]);
  }
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(srvExtensions.length, 0);
  const srvHello = Buffer.concat([
    Buffer.from([0x03, 0x03]), // version
    randomBytes(32), // random
    Buffer.from([sid.length]),
    sid,
    cipher, // 2-byte cipher suite
    Buffer.from([0x00]), // compression
    extTotal,
    srvExtensions,
  ]);
  const hsLen = Buffer.alloc(3);
  hsLen.writeUIntBE(srvHello.length, 0, 3);
  const hsMsg = Buffer.concat([Buffer.from([0x02]), hsLen, srvHello]);
  const recLen = Buffer.alloc(2);
  recLen.writeUInt16BE(hsMsg.length, 0);
  parts.push(Buffer.concat([Buffer.from([0x16, 0x03, 0x03]), recLen, hsMsg]));

  // One ChangeCipherSpec.
  parts.push(Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]));

  // Application-data records with the scripted sizes.
  for (const size of appDataSizes) {
    const len = Buffer.alloc(2);
    len.writeUInt16BE(size, 0);
    parts.push(Buffer.from([0x17, 0x03, 0x03]), len, randomBytes(size));
  }
  return Buffer.concat(parts);
}

function startScriptOrigin(flight) {
  const server = net.createServer((socket) => {
    socket.on("data", () => {
      socket.write(flight);
      socket.end();
    });
    socket.on("error", () => {});
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

test("buildCaptureClientHello: produces a TLS 1.3 ClientHello record >= 512 bytes", () => {
  const hello = buildCaptureClientHello("www.example.com");
  assert.equal(hello[0], 0x16, "must be a TLS handshake record");
  assert.equal(hello[1], 0x03);
  assert.equal(hello[5], 0x01, "handshake type = ClientHello");
  const recLen = hello.readUInt16BE(3);
  assert.ok(hello.length >= 5 + recLen, "record must be complete");
  assert.ok(hello.length >= 512, "ClientHello must be padded to >= 512 bytes");
});

test("createTlsRecordObserver: yields type+length for each complete record", () => {
  const obs = createTlsRecordObserver();
  const flight = buildScriptedFlight({ cipher: Buffer.from([0x13, 0x02]), alpn: "h2", appDataSizes: [10, 20] });
  // Feed in tiny chunks to exercise buffering.
  const recs = [];
  for (let i = 0; i < flight.length; i += 7) {
    recs.push(...obs.feed(flight.subarray(i, Math.min(i + 7, flight.length))));
  }
  assert.equal(recs[0].type, 0x16); // ServerHello
  assert.equal(recs[1].type, 0x14); // CCS
  assert.equal(recs[2].type, 0x17);
  assert.equal(recs[2].length, 10);
  assert.equal(recs[3].type, 0x17);
  assert.equal(recs[3].length, 20);
});

test("captureTlsProfile: captures cipher, ALPN, ccsCount and app-data sizes from a scripted origin", async () => {
  const flight = buildScriptedFlight({
    cipher: Buffer.from([0x13, 0x02]), // TLS_AES_256_GCM_SHA384
    alpn: "h2",
    appDataSizes: [150, 300, 80],
  });
  const origin = await startScriptOrigin(flight);
  const port = origin.address().port;
  try {
    const profile = await captureTlsProfile("127.0.0.1", port, { timeoutMs: 3000 });
    assert.ok(profile, "profile must be captured");
    assert.deepEqual(Array.from(profile.cipher), [0x13, 0x02]);
    assert.equal(profile.alpn, "h2");
    assert.equal(profile.ccsCount, 1);
    assert.deepEqual(profile.appDataSizes, [150, 300, 80]);
    // recordDelays: one entry per gap between consecutive records
    // (ServerHello + CCS + 3 app-data = 5 records -> 4 gaps).
    assert.ok(Array.isArray(profile.recordDelays), "recordDelays must be captured");
    assert.equal(profile.recordDelays.length, 4, "5 records -> 4 gaps");
    for (const d of profile.recordDelays) {
      assert.ok(Number.isFinite(d) && d >= 0, "delay must be a non-negative finite number");
    }
  } finally {
    origin.closeAllConnections?.();
    origin.close();
  }
});

test("captureTlsProfile: returns null when the origin sends no TLS records", async () => {
  const server = net.createServer((socket) => {
    socket.on("data", () => { socket.end(); });
    socket.on("error", () => {});
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  try {
    const profile = await captureTlsProfile("127.0.0.1", port, { timeoutMs: 1500 });
    assert.equal(profile, null);
  } finally {
    server.closeAllConnections?.();
    server.close();
  }
});

test("buildServerHello: with a profile replays ccsCount + app-data sizes and keeps the digest valid", () => {
  const secret = randomBytes(16);
  const clientDigest = randomBytes(32);
  const sessionId = randomBytes(16);
  const profile = {
    host: "www.example.com",
    capturedAt: Date.now(),
    cipher: Buffer.from([0x13, 0x02]),
    alpn: "h2",
    ccsCount: 1,
    appDataSizes: [150, 300, 80],
    ticketSizes: [80],
    certLen: 300,
  };
  const response = buildServerHello(secret, clientDigest, sessionId, null, profile);

  // Walk the records: 0x16 ServerHello, 0x14 CCS, then ONE 0x17 fake-cert record sized to certLen.
  const obs = createTlsRecordObserver();
  const recs = obs.feed(response);
  assert.equal(recs[0].type, 0x16);
  assert.equal(recs[1].type, 0x14);
  const appData = recs.filter((r) => r.type === 0x17);
  assert.equal(appData.length, 1, "fake-TLS protocol expects exactly one fake-cert 0x17 record");
  assert.equal(appData[0].length, 300, "fake-cert size must match profile.certLen");

  // The cipher in the ServerHello must be the profile's cipher (0x13 0x02), not the synthetic default.
  // ServerHello record body: header(5) + hs-type(1)+hs-len(3) + version(2) + random(32) + sidLen(1) + sid.
  const cipherOff = 5 + 4 + 2 + 32 + 1 + sessionId.length;
  assert.equal(response[cipherOff], 0x13);
  assert.equal(response[cipherOff + 1], 0x02);

  // Digest at [11:43] must equal HMAC(secret, clientDigest + zeroDigest(response)).
  const zeroed = Buffer.concat([response.subarray(0, 11), Buffer.alloc(32), response.subarray(43)]);
  const expected = createHmac("sha256", secret).update(Buffer.concat([clientDigest, zeroed])).digest();
  assert.ok(response.subarray(11, 43).equals(expected), "response digest must match HMAC");
});

test("buildServerHello: profile=null keeps the synthetic single-CCS + single-app-data shape", () => {
  const secret = randomBytes(16);
  const response = buildServerHello(secret, randomBytes(32), randomBytes(16), null, null);
  const obs = createTlsRecordObserver();
  const recs = obs.feed(response);
  const ccs = recs.filter((r) => r.type === 0x14);
  const appData = recs.filter((r) => r.type === 0x17);
  assert.equal(ccs.length, 1);
  assert.equal(appData.length, 1);
});

test("createProfileManager: start captures a profile, get returns it, stop clears the timer", async () => {
  const flight = buildScriptedFlight({
    cipher: Buffer.from([0x13, 0x01]),
    alpn: "http/1.1",
    appDataSizes: [200, 400],
  });
  const origin = await startScriptOrigin(flight);
  const port = origin.address().port;
  const mgr = createProfileManager({ host: "127.0.0.1", port, refreshMs: 60_000, timeoutMs: 3000 });
  try {
    mgr.start();
    // Wait for the initial async capture to complete.
    await new Promise((resolve) => setTimeout(resolve, 400));
    const profile = mgr.get();
    assert.ok(profile, "profile must be populated after start");
    assert.deepEqual(profile.appDataSizes, [200, 400]);
    assert.equal(profile.alpn, "http/1.1");
  } finally {
    mgr.stop();
    origin.closeAllConnections?.();
    origin.close();
  }
});