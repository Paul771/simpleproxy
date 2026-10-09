// FILE: tests/faketls.test.js
// VERSION: 1.4.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-FAKETLS ClientHello validation, ServerHello build, TLS record framing
//   SCOPE: HMAC digest round-trip, record reader/writer, wrong-secret rejection, ClientHello
//          extent resolution when declared lengths overstate what the client wrote
//   DEPENDS: M-FAKETLS
//   LINKS: V-M-FAKETLS
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   buildClientHello - fake-TLS ClientHello fixture; recordLenPad/hsLenPad inflate the declared
//                      length fields without writing those bytes (the prod signature uses both)
//   hmacSha256 - local HMAC helper mirroring the client's digest computation
//   fakeCertLen - last TLS record of a flight is the fake certificate
// END_MODULE_MAP
//
// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.4.0 - extractAlpn (first offered protocol, absent -> null) and
//                resolveServerCipher (profile cipher only when offered; Buffer / byte Array / hex
//                string all accepted, unparseable -> default). The hex case is the load-bearing one:
//                Buffer.from("1302") is 4 UTF-8 bytes and could never match a 2-byte suite, so a
//                hex-valued profile would have silently degraded to the default forever.
//                buildHelloWithExtensions/alpnExt fixtures added; note extLen must span the
//                ProtocolNameList length field AND its entries, which is the easy way to get this
//                wrong (the first run of this test failed on exactly that).
//   PREVIOUS: v1.3.0 - pin the structural ClientHello fallback. Three cases: both declared
//                lengths overstate in agreement (recordEnd == messageEnd, the prod signature that
//                v1.3.0 missed) and must resolve to the structural end; a hello whose extensions
//                block has not fully landed must still return 0 rather than be answered from
//                truncated bytes; and the HMAC must accept the structural extent while rejecting a
//                one-byte-short guess and a wrong secret — the safety property that makes the
//                fallback a confirmation rather than a guess.
//   PREVIOUS: v1.2.0 - certLenCap coverage for the bounded server flight.
// END_CHANGE_SUMMARY

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
  resolveClientHelloEnd,
  resolveClientHelloStructuralEnd,
  extractAlpn,
  resolveServerCipher,
} from "../src/faketls.js";

const DIGEST_POS = 11;
const DIGEST_LEN = 32;

function hmacSha256(key, msg) {
  return createHmac("sha256", key).update(msg).digest();
}

// Emulate a client building a fake-TLS ClientHello with the HMAC digest.
// recordLenPad / hsLenPad inflate the declared length fields WITHOUT writing those bytes: they model
// a client whose length fields overstate the message it actually sends (the digest is computed
// over the inflated buffer, exactly as such a client would sign what it wrote). Passing the SAME
// pad to both reproduces the production signature, where the two declared extents agree with each
// other (recordEnd == messageEnd) yet both promise ~460 bytes more than the client ever delivers.
function buildClientHello(secret, offeredCiphers = [0x13, 0x01], recordLenPad = 0, hsLenPad = 0) {
  const sessionId = randomBytes(16);
  const timestamp = Math.floor(Date.now() / 1000);
  const tsBytes = Buffer.alloc(4);
  tsBytes.writeUInt32LE(timestamp, 0);

  // Build the ClientHello with a zeroed digest field first.
  const cipherSuites = Buffer.concat([Buffer.from([0x00, offeredCiphers.length]), Buffer.from(offeredCiphers)]);
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
  hsLenBuf.writeUIntBE(inner.length + hsLenPad, 0, 3);
  const handshakeMsg = Buffer.concat([Buffer.from([0x01]), hsLenBuf, inner]);

  // TLS record header: 0x16 0x03 0x01 + u16(recordLen) + handshakeMsg
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(handshakeMsg.length + recordLenPad, 0);
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

// --- v1.1.0: profile.cipher replayed only when the client offered it ---
test("buildServerHello: profile cipher is used only when the client offered it (dd/simple regression)", () => {
  const secret = randomBytes(16);
  const profile = {
    cipher: [0x13, 0x02], // rutube's real suite — NOT in the default client offer
    alpn: null,
    ccsCount: 1,
    appDataSizes: [7331, 281],
    certLen: 7331,
    recordDelays: [],
  };

  // Client offers ONLY 0x1301 (default Telegram-like offer): profile's 0x1302 must NOT leak
  // into the ServerHello; the default 0x1301 must be selected instead.
  const built1301 = buildClientHello(secret);
  const res1301 = validateClientHello(built1301.hello, [secret]);
  assert.deepEqual(res1301.ciphers.map((c) => c.toString("hex")), ["1301"]);
  const resp1301 = buildServerHello(secret, res1301.digest, res1301.sessionId, "h2", profile, res1301.ciphers);
  const sh1301 = splitTlsRecords(resp1301)[0];
  assert.ok(sh1301.includes(Buffer.from([0x13, 0x01])), "must select the client-offered 0x1301");
  assert.ok(!sh1301.includes(Buffer.from([0x13, 0x02])), "must not leak the unoffered 0x1302");

  // Client that DOES offer 0x1302 alongside: profile replay becomes eligible.
  const builtBoth = buildClientHello(secret, [0x13, 0x01, 0x13, 0x02]);
  const resBoth = validateClientHello(builtBoth.hello, [secret]);
  assert.deepEqual(resBoth.ciphers.map((c) => c.toString("hex")), ["1301", "1302"]);
  const respBoth = buildServerHello(secret, resBoth.digest, resBoth.sessionId, "h2", profile, resBoth.ciphers);
  const shBoth = splitTlsRecords(respBoth)[0];
  assert.ok(shBoth.includes(Buffer.from([0x13, 0x02])), "profile cipher is eligible when offered");

  // Legacy call shape (no ciphers passed): must stay conservative and use the default.
  const respLegacy = buildServerHello(secret, res1301.digest, res1301.sessionId, "h2", profile);
  assert.ok(splitTlsRecords(respLegacy)[0].includes(Buffer.from([0x13, 0x01])));
});

// --- v1.2.0: ALPN fidelity under a captured profile ---
test("buildServerHello: omits ALPN when the captured profile negotiated none (alpnKnown=true)", () => {
  const secret = randomBytes(16);
  const profile = {
    cipher: [0x13, 0x01],
    alpn: null,
    alpnKnown: true, // ServerHello parsed; the origin answered WITHOUT ALPN (rutube.ru-like)
    ccsCount: 1,
    appDataSizes: [1000],
    certLen: 1000,
    recordDelays: [],
  };
  // Configured ALPN "h2" must NOT leak in when the profile proves the origin negotiated none.
  const response = buildServerHello(secret, randomBytes(32), randomBytes(16), "h2", profile, [Buffer.from([0x13, 0x01])]);
  assert.equal(
    response.includes(buildAlpnExtension(["h2"])),
    false,
    "profile-absent ALPN must be mirrored (extension omitted)"
  );
});

test("buildServerHello: replays the profile's ALPN when it negotiated one", () => {
  const secret = randomBytes(16);
  const profile = {
    cipher: null,
    alpn: "http/1.1",
    alpnKnown: true,
    ccsCount: 1,
    appDataSizes: [500],
    certLen: 500,
    recordDelays: [],
  };
  const response = buildServerHello(secret, randomBytes(32), randomBytes(16), "h2", profile);
  assert.ok(response.includes(buildAlpnExtension(["http/1.1"])), "profile ALPN must be replayed");
  assert.equal(
    response.includes(buildAlpnExtension(["h2"])),
    false,
    "configured ALPN must not be used when the profile has its own"
  );
});

test("buildServerHello: legacy profile without alpnKnown still falls back to configured ALPN", () => {
  const secret = randomBytes(16);
  const profile = { cipher: null, alpn: null, ccsCount: 1, appDataSizes: [500], certLen: 500, recordDelays: [] };
  const response = buildServerHello(secret, randomBytes(32), randomBytes(16), "h2", profile);
  assert.ok(response.includes(buildAlpnExtension(["h2"])), "no alpnKnown -> configured ALPN is used");
});

// --- ALPN offer: needed to tell "client offered ALPN, we sent none" apart from "client offered none" ---
// Production showed a fake-TLS client that receives our flight and closes ~90ms later having sent
// nothing, while another client on the same proxy relays megabytes. The journal carried neither the
// selected cipher nor whether ALPN was offered, so the two cases were indistinguishable.
function buildHelloWithExtensions(exts) {
  const sessionId = randomBytes(16);
  const cipherSuites = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const compression = Buffer.from([0x01, 0x00]);
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(Buffer.concat(exts).length, 0);
  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]),
    randomBytes(32),
    Buffer.from([sessionId.length]),
    sessionId,
    cipherSuites,
    compression,
    extTotal,
    Buffer.concat(exts),
  ]);
  const hsLenBuf = Buffer.alloc(3);
  hsLenBuf.writeUIntBE(inner.length, 0, 3);
  const handshakeMsg = Buffer.concat([Buffer.from([0x01]), hsLenBuf, inner]);
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(handshakeMsg.length, 0);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recordLenBuf, handshakeMsg]);
}

function alpnExt(protocols) {
  const list = Buffer.concat(protocols.map((p) => {
    const b = Buffer.from(p, "latin1");
    return Buffer.concat([Buffer.from([b.length]), b]);
  }));
  // extLen spans the ProtocolNameList length field AND its entries; extData then carries that
  // length separately. Missing the second field is the easy way to get this wrong.
  const ext = Buffer.alloc(6);
  ext.writeUInt16BE(0x0010, 0);
  ext.writeUInt16BE(2 + list.length, 2);
  ext.writeUInt16BE(list.length, 4);
  return Buffer.concat([ext, list]);
}

test("extractAlpn: returns the first offered protocol, or null when absent", () => {
  assert.equal(extractAlpn(buildHelloWithExtensions([alpnExt(["h2", "http/1.1"])])), "h2");
  assert.equal(extractAlpn(buildHelloWithExtensions([alpnExt(["http/1.1"])])), "http/1.1");
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(40)]);
  padExt.writeUInt16BE(40, 2);
  assert.equal(extractAlpn(buildHelloWithExtensions([padExt])), null, "no ALPN extension -> null");
  assert.equal(extractAlpn(Buffer.alloc(64)), null, "not a ClientHello -> null");
});

// The cipher actually put on the wire is the one thing a strict client aborts on right after
// ServerHello, and it was invisible in the journal.
test("resolveServerCipher: replays profile.cipher only when the client offered it", () => {
  const offered1301 = [Buffer.from([0x13, 0x01])];
  const offered1302 = [Buffer.from([0x13, 0x02])];
  const profile = { cipher: "1302" };
  assert.equal(
    resolveServerCipher(profile, offered1302).toString("hex"),
    "1302",
    "offered -> profile cipher is replayed"
  );
  assert.equal(
    resolveServerCipher(profile, offered1301).toString("hex"),
    "1301",
    "not offered -> RFC 8446 fallback, never a foreign suite"
  );
  assert.equal(resolveServerCipher(null, offered1302).toString("hex"), "1301", "no profile -> default");
  assert.equal(resolveServerCipher(profile, null).toString("hex"), "1301", "no offer list -> default");
  assert.equal(resolveServerCipher(profile, []).toString("hex"), "1301", "empty offer list -> default");
  // Byte Array and Buffer forms must keep working (existing callers / captured profile).
  assert.equal(
    resolveServerCipher({ cipher: [0x13, 0x02] }, offered1302).toString("hex"),
    "1302",
    "byte-array profile cipher"
  );
  assert.equal(
    resolveServerCipher({ cipher: Buffer.from([0x13, 0x02]) }, offered1302).toString("hex"),
    "1302",
    "buffer profile cipher"
  );
  assert.equal(
    resolveServerCipher({ cipher: "not-hex" }, offered1302).toString("hex"),
    "1301",
    "unparseable profile cipher -> default, never garbage on the wire"
  );
});


test("resolveClientHelloEnd: returns the record end when the record framing is satisfied", () => {
  const secret = randomBytes(16);
  const { hello } = buildClientHello(secret);
  const recordLen = hello.readUInt16BE(3);
  assert.equal(resolveClientHelloEnd(hello), 5 + recordLen);
  assert.equal(
    resolveClientHelloEnd(hello.subarray(0, 5 + recordLen - 1)),
    0,
    "a record missing one byte must still wait, not be answered from a truncated hello"
  );
});

test("resolveClientHelloEnd: falls back to the handshake-message length when the record length lies", () => {
  const secret = randomBytes(16);
  const { hello } = buildClientHello(secret, [0x13, 0x01], 64);
  const recordLen = hello.readUInt16BE(3);
  const hsLen = hello.readUIntBE(6, 3);
  assert.ok(9 + hsLen < 5 + recordLen, "fixture must model an overstated record length");
  // The whole message is present even though the record promises 64 bytes more.
  assert.equal(resolveClientHelloEnd(hello), 9 + hsLen);
  assert.equal(
    resolveClientHelloEnd(hello.subarray(0, 9 + hsLen - 1)),
    0,
    "an incomplete message must still wait"
  );
});

test("resolveClientHelloEnd: non-ClientHello or too-short buffers need more bytes", () => {
  assert.equal(resolveClientHelloEnd(Buffer.alloc(4)), 0);
  assert.equal(resolveClientHelloEnd(Buffer.alloc(64)), 0, "no 0x16 0x03 0x01 start");
  const secret = randomBytes(16);
  const { hello } = buildClientHello(secret);
  const notAHello = Buffer.from(hello);
  notAHello[5] = 0x02; // ServerHello: the handshake framing cannot be trusted
  assert.equal(resolveClientHelloEnd(notAHello.subarray(0, 200)), 0);
});

// --- ClientHello extent: BOTH declared lengths can overstate what the client wrote (prod stall) ---
// Production signature: 1298 bytes arrived, recordLen/hsLen agreed with each other but described a
// ~1789-byte hello, so neither declared extent was reachable. The previous fix only covered a
// record length that overstated while the handshake length stayed accurate, so these clients were
// never answered at all and sat until the handshake timeout (flight_bytes: 0 on every attempt).
test("resolveClientHelloEnd: resolves structurally when record AND handshake lengths both overstate", () => {
  const secret = randomBytes(16);
  const { hello } = buildClientHello(secret, [0x13, 0x01], 480, 480);
  const recordLen = hello.readUInt16BE(3);
  const hsLen = hello.readUIntBE(6, 3);
  assert.equal(5 + recordLen, 9 + hsLen, "fixture must keep the two declared extents in agreement");
  assert.ok(5 + recordLen > hello.length, "fixture must model a record longer than what arrived");
  assert.equal(resolveClientHelloEnd(hello), hello.length, "the structural extent is the real end");
});

test("resolveClientHelloEnd: a structurally incomplete hello still waits for more bytes", () => {
  const secret = randomBytes(16);
  const { hello } = buildClientHello(secret, [0x13, 0x01], 480, 480);
  assert.equal(
    resolveClientHelloEnd(hello.subarray(0, hello.length - 1)),
    0,
    "one byte short of the extensions end must still wait, not be answered from a truncated hello"
  );
});

// The safety property that makes the structural fallback acceptable: acceptance stays gated on the
// HMAC, so the extent is CONFIRMED rather than guessed. A wrong guess cannot validate.
test("validateClientHello: the structural extent is exactly what the HMAC covers", () => {
  const secret = randomBytes(16);
  const { hello } = buildClientHello(secret, [0x13, 0x01], 480, 480);
  assert.ok(validateClientHello(hello, [secret]), "the true extent must validate");
  assert.equal(
    validateClientHello(hello.subarray(0, hello.length - 1), [secret]),
    null,
    "a one-byte-short guess must not validate"
  );
  assert.equal(validateClientHello(hello, [randomBytes(16)]), null, "wrong secret still rejected");
});

// --- certLenCap: keep the server flight under a small path MTU ---

// The fake certificate is the LAST record of the flight (SH, then CCS xN, then one 0x17).
function fakeCertLen(response) {
  const records = splitTlsRecords(response);
  const cert = records[records.length - 1];
  assert.equal(cert[0], 0x17, "the trailing app-data record is the fake certificate");
  return cert.readUInt16BE(3);
}

test("buildServerHello: certLenCap truncates the captured certificate, cap 0 keeps it", () => {
  const secret = randomBytes(16);
  const profile = {
    cipher: null,
    alpn: null,
    alpnKnown: true,
    ccsCount: 1,
    appDataSizes: [4091],
    certLen: 4091,
    recordDelays: [],
  };
  const capped = buildServerHello(secret, randomBytes(32), randomBytes(16), null, profile, null, 1200);
  assert.equal(fakeCertLen(capped), 1200, "cap wins over the captured certLen");
  const uncapped = buildServerHello(secret, randomBytes(32), randomBytes(16), null, profile, null, 0);
  assert.equal(fakeCertLen(uncapped), 4091, "cap 0/omitted = replay the captured size");
});

test("buildServerHello: certLenCap also bounds the random certificate without a profile", () => {
  const secret = randomBytes(16);
  for (let i = 0; i < 5; i++) {
    const response = buildServerHello(secret, randomBytes(32), randomBytes(16), null, null, null, 900);
    assert.equal(fakeCertLen(response), 900, "the random 1024-4095 certificate must respect the cap");
  }
});