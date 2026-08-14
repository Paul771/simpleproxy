// FILE: tests/faketls.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-FAKETLS ClientHello validation, ServerHello build, TLS record framing
//   SCOPE: HMAC digest round-trip, record reader/writer, wrong-secret rejection
//   DEPENDS: M-FAKETLS
//   LINKS: V-M-FAKETLS
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes } from "node:crypto";
import {
  validateClientHello,
  buildServerHello,
  createTlsRecordReader,
  wrapTlsRecord,
  genX25519PublicKey,
  extractSni,
  buildTlsAlert,
  buildAlpnExtension,
  splitTlsRecords,
} from "../src/faketls.js";

const DIGEST_POS = 11;
const DIGEST_LEN = 32;

function hmacSha256(key, msg) {
  return createHmac("sha256", key).update(msg).digest();
}

// Emulate a client building a fake-TLS ClientHello with the HMAC digest.
function buildClientHello(secret) {
  const sessionId = randomBytes(16);
  const timestamp = Math.floor(Date.now() / 1000);
  const tsBytes = Buffer.alloc(4);
  tsBytes.writeUInt32LE(timestamp, 0);

  // Build the ClientHello with a zeroed digest field first.
  const cipherSuites = Buffer.from([0x00, 0x02, 0x13, 0x01]); // 1 suite: TLS_AES_128_GCM_SHA256
  const compression = Buffer.from([0x01, 0x00]); // 1 method: null
  // Real Telegram ClientHellos exceed 512 bytes (the proxy rejects smaller as non-TLS).
  // Pad with a TLS padding extension (0x0015) to cross that threshold.
  const padLen = 533;
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
  padExt.writeUInt16BE(padLen, 2);
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(padExt.length, 0);
  const extensions = Buffer.concat([extTotal, padExt]);

  const sidLen = Buffer.from([sessionId.length]);
  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]), // client version
    Buffer.alloc(DIGEST_LEN), // random (digest placeholder)
    sidLen,
    sessionId,
    cipherSuites,
    compression,
    extensions,
  ]);

  // Handshake message: type(1) + length(3) + inner
  const hsLenBuf = Buffer.alloc(3);
  hsLenBuf.writeUIntBE(inner.length, 0, 3);
  const handshakeMsg = Buffer.concat([Buffer.from([0x01]), hsLenBuf, inner]);

  // TLS record header: 0x16 0x03 0x01 + u16(recordLen) + handshakeMsg
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(handshakeMsg.length, 0);
  let hello = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recordLenBuf, handshakeMsg]);

  // Compute digest: msg = hello with digest field zeroed; digest = hmac XOR (zeros(28) || ts)
  const msg = Buffer.concat([
    hello.subarray(0, DIGEST_POS),
    Buffer.alloc(DIGEST_LEN),
    hello.subarray(DIGEST_POS + DIGEST_LEN),
  ]);
  const computed = hmacSha256(secret, msg);
  const digest = Buffer.alloc(DIGEST_LEN);
  for (let i = 0; i < DIGEST_LEN; i++) {
    digest[i] = computed[i] ^ (i < DIGEST_LEN - 4 ? 0 : tsBytes[i - (DIGEST_LEN - 4)]);
  }
  hello = Buffer.concat([hello.subarray(0, DIGEST_POS), digest, hello.subarray(DIGEST_POS + DIGEST_LEN)]);
  return { hello, sessionId, digest };
}

test("validateClientHello: accepts a valid ClientHello and returns the matched secret", () => {
  const secret = randomBytes(16);
  const { hello, sessionId } = buildClientHello(secret);
  const result = validateClientHello(hello, [secret]);
  assert.ok(result);
  assert.ok(result.secret.equals(secret));
  assert.ok(result.sessionId.equals(sessionId));
});

test("validateClientHello: rejects wrong secret, returns null", () => {
  const secret = randomBytes(16);
  const wrong = randomBytes(16);
  const { hello } = buildClientHello(secret);
  assert.equal(validateClientHello(hello, [wrong]), null);
  assert.ok(validateClientHello(hello, [wrong, secret]) !== null);
});

test("validateClientHello: rejects non-TLS buffers", () => {
  const secret = randomBytes(16);
  assert.equal(validateClientHello(randomBytes(64), [secret]), null);
  assert.equal(validateClientHello(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x10]), [secret]), null);
});

test("buildServerHello: response digest matches HMAC over clientDigest + helloPkt", () => {
  const secret = randomBytes(16);
  const { hello, digest } = buildClientHello(secret);
  const result = validateClientHello(hello, [secret]);
  assert.ok(result);

  const response = buildServerHello(secret, result.digest, result.sessionId);
  // Response is a TLS record starting with 0x16 0x03 0x03.
  assert.equal(response[0], 0x16);
  assert.equal(response[1], 0x03);
  assert.equal(response[2], 0x03);
  // Recompute the expected response digest and compare with response[11:43].
  const expected = hmacSha256(secret, Buffer.concat([result.digest, zeroDigest(response)]));
  assert.ok(response.subarray(11, 43).equals(expected), "response digest must match HMAC");
});

// Replace response[11:43] with zeros to recompute the HMAC the proxy used internally.
function zeroDigest(pkt) {
  return Buffer.concat([pkt.subarray(0, 11), Buffer.alloc(32), pkt.subarray(43)]);
}

test("createTlsRecordReader + wrapTlsRecord: round-trip app data through TLS framing", () => {
  const reader = createTlsRecordReader();
  const payload1 = Buffer.from("hello-fake-tls");
  const payload2 = Buffer.from("second-record-payload");

  const wrapped = Buffer.concat([wrapTlsRecord(payload1), wrapTlsRecord(payload2)]);
  // Feed in tiny chunks to exercise buffering.
  const out = [];
  for (let i = 0; i < wrapped.length; i += 3) {
    out.push(...reader.feed(wrapped.subarray(i, Math.min(i + 3, wrapped.length))));
  }
  assert.deepEqual(Buffer.concat(out), Buffer.concat([payload1, payload2]));
});

test("createTlsRecordReader: skips ChangeCipherSpec (0x14) records", () => {
  const reader = createTlsRecordReader();
  const ccs = Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
  const payload = Buffer.from("after-ccs");
  const out = reader.feed(Buffer.concat([ccs, wrapTlsRecord(payload)]));
  assert.deepEqual(Buffer.concat(out), payload);
});

test("wrapTlsRecord: chunks large data into multiple records", () => {
  const data = randomBytes(40000);
  const wrapped = wrapTlsRecord(data);
  // First record header
  assert.equal(wrapped[0], 0x17);
  let off = 0;
  const reader = createTlsRecordReader();
  assert.deepEqual(Buffer.concat(reader.feed(wrapped)), data);
});

test("genX25519PublicKey: returns 32 bytes, high bit cleared", () => {
  const k = genX25519PublicKey();
  assert.equal(k.length, 32);
  assert.ok((k[31] & 0x80) === 0, "high bit must be clear for a valid x25519 key");
});

test("buildServerHello: omits ALPN extension when no alpn is given (backward compatible)", () => {
  const secret = randomBytes(16);
  const sessionId = randomBytes(16);
  const response = buildServerHello(secret, randomBytes(32), sessionId);
  // Scan the ServerHello record for the ALPN extension type 0x0010 -> must be absent.
  const hasAlpn = response.subarray(0, 100).includes(Buffer.from([0x00, 0x10]));
  assert.equal(hasAlpn, false, "no ALPN extension when alpn is null");
});

test("buildServerHello: includes ALPN extension with the negotiated protocol when alpn is set", () => {
  const secret = randomBytes(16);
  const sessionId = randomBytes(16);
  const response = buildServerHello(secret, randomBytes(32), sessionId, "h2");
  // The ServerHello must carry the ALPN extension (type 0x00 0x10) advertising "h2".
  const alpnExt = buildAlpnExtension(["h2"]);
  assert.ok(response.includes(alpnExt), "ALPN extension must be present in the response packet");
});

test("buildTlsAlert: unrecognized_name alert (112) has the expected wire bytes", () => {
  assert.deepEqual(Array.from(buildTlsAlert(112)), [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70]);
});

test("extractSni: parses hostname from a synthetic ClientHello carrying SNI", () => {
  const sessionId = randomBytes(16);
  const cipherSuites = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const compression = Buffer.from([0x01, 0x00]);
  // SNI extension for "www.example.com"
  const name = Buffer.from("www.example.com", "latin1");
  const snEntry = Buffer.concat([Buffer.from([0x00]), Buffer.from([name.length & 0xff, (name.length >> 8) & 0xff].reverse()), name]);
  const snList = Buffer.concat([Buffer.from([snEntry.length & 0xff, (snEntry.length >> 8) & 0xff].reverse()), snEntry]);
  const sniExt = Buffer.concat([Buffer.from([0x00, 0x00, 0x00, 0x00]), snList]);
  sniExt.writeUInt16BE(snList.length, 2);
  const padLen = 40;
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
  padExt.writeUInt16BE(padLen, 2);
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(Buffer.concat([sniExt, padExt]).length, 0);
  const extensions = Buffer.concat([extTotal, sniExt, padExt]);
  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    randomBytes(32),
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
  const hello = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recordLenBuf, handshakeMsg]);
  assert.equal(extractSni(hello), "www.example.com");
});

test("extractSni: returns null for a ClientHello without SNI", () => {
  const sessionId = randomBytes(16);
  const cipherSuites = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const compression = Buffer.from([0x01, 0x00]);
  const padLen = 40;
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
  padExt.writeUInt16BE(padLen, 2);
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(padExt.length, 0);
  const extensions = Buffer.concat([extTotal, padExt]);
  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    randomBytes(32),
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
  const hello = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recordLenBuf, handshakeMsg]);
  assert.equal(extractSni(hello), null);
});

test("splitTlsRecords: splits concatenated records into individual record buffers", () => {
  const secret = randomBytes(16);
  const { hello, sessionId, digest } = buildClientHello(secret);
  const result = validateClientHello(hello, [secret]);
  const response = buildServerHello(secret, result.digest, result.sessionId, null, null);

  const records = splitTlsRecords(response);
  // Synthetic flight: 0x16 ServerHello, 0x14 CCS, 0x17 app-data = 3 records.
  assert.equal(records.length, 3);
  assert.equal(records[0][0], 0x16);
  assert.equal(records[1][0], 0x14);
  assert.equal(records[2][0], 0x17);
  // Concatenating the records back must reproduce the original bytes exactly.
  assert.ok(Buffer.concat(records).equals(response));
});