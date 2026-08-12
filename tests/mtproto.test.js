// FILE: tests/mtproto.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-MTPROTO obfuscated2 handshake parse/build and DC mapping
//   SCOPE: client handshake round-trip, secret validation, upstream handshake, DC resolution
//   DEPENDS: M-MTPROTO
//   LINKS: V-M-MTPROTO
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import {
  parseClientHandshake,
  buildUpstreamHandshake,
  getDcAddress,
  createAesCtr,
} from "../src/mtproto.js";

const PROTO_TAG_ABRIDGED = Buffer.from([0xef, 0xef, 0xef, 0xef]);
const PROTO_TAG_INTERMEDIATE = Buffer.from([0xee, 0xee, 0xee, 0xee]);
const PROTO_TAG_SECURE = Buffer.from([0xdd, 0xdd, 0xdd, 0xdd]);

function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

const RESERVED_BEGINNINGS = [
  Buffer.from("HEAD", "latin1"),
  Buffer.from("POST", "latin1"),
  Buffer.from("GET ", "latin1"),
  Buffer.from([0xee, 0xee, 0xee, 0xee]),
  Buffer.from([0xdd, 0xdd, 0xdd, 0xdd]),
  Buffer.from([0x16, 0x03, 0x01, 0x02]),
];

// Build a client obfuscated2 handshake exactly like the reference client:
// 64 random bytes, proto_tag at [56:60], dc_idx (int16 LE) at [60:62],
// tail [56:64] encrypted with AES-CTR(sha256(init[8:40]+secret), init[40:56]).
// Returns { handshake, stream } where stream is the stateful client stream
// already advanced past the 64-byte handshake.
function buildClientHandshake(secret, protoTag, dcIdx) {
  let init;
  for (;;) {
    init = randomBytes(64);
    if (init[0] === 0xef) continue;
    if (RESERVED_BEGINNINGS.some((b) => b.equals(init.subarray(0, 4)))) continue;
    if (init.subarray(4, 8).equals(Buffer.alloc(4))) continue;
    break;
  }
  protoTag.copy(init, 56);
  init.writeInt16LE(dcIdx, 60);

  const key = sha256(init.subarray(8, 40), secret);
  const stream = createAesCtr(key, init.subarray(40, 56));
  const encrypted = stream.encrypt(init);
  const handshake = Buffer.concat([init.subarray(0, 56), encrypted.subarray(56, 64)]);
  return { handshake, stream };
}

test("parseClientHandshake: accepts valid handshake, returns protoTag and dcIdx", () => {
  const secret = randomBytes(16);
  const dcIdx = 2;
  const { handshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, dcIdx);
  const parsed = parseClientHandshake(handshake, [secret]);
  assert.ok(parsed);
  assert.ok(parsed.protoTag.equals(PROTO_TAG_ABRIDGED));
  assert.equal(parsed.dcIdx, dcIdx);
  assert.ok(parsed.secret.equals(secret));
  assert.ok(parsed.encKey.length === 32);
  assert.ok(parsed.encIv.length === 16);
});

test("parseClientHandshake: accepts all three proto tags", () => {
  const secret = randomBytes(16);
  for (const tag of [PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE]) {
    const { handshake } = buildClientHandshake(secret, tag, 1);
    const parsed = parseClientHandshake(handshake, [secret]);
    assert.ok(parsed, `tag ${tag.toString("hex")} should parse`);
    assert.ok(parsed.protoTag.equals(tag));
  }
});

test("parseClientHandshake: rejects wrong secret", () => {
  const secret = randomBytes(16);
  const other = randomBytes(16);
  const { handshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
  assert.equal(parseClientHandshake(handshake, [other]), null);
  assert.equal(parseClientHandshake(handshake, [other, secret]) !== null, true);
});

test("parseClientHandshake: rejects malformed handshakes", () => {
  const secret = randomBytes(16);
  assert.equal(parseClientHandshake(Buffer.alloc(10), [secret]), null);
  assert.equal(parseClientHandshake(randomBytes(64), [secret]), null);
});

test("parseClientHandshake: client data decrypts through the returned stateful decryptor", () => {
  const secret = randomBytes(16);
  const { handshake, stream } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
  const parsed = parseClientHandshake(handshake, [secret]);
  assert.ok(parsed);

  const payload = "hello-mtproto";
  const sent = stream.encrypt(Buffer.from(payload));
  const received = parsed.decryptor.decrypt(sent);
  assert.equal(received.toString(), payload);
});

test("buildUpstreamHandshake: mirrors client keys, tail decrypts back to protoTag", () => {
  const secret = randomBytes(16);
  const { handshake } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
  const parsed = parseClientHandshake(handshake, [secret]);
  assert.ok(parsed);

  const { rndEnc, encryptorUp } = buildUpstreamHandshake(parsed);
  assert.equal(rndEnc.length, 64);

  // The upstream prekey slot [8:56] mirrors the client enc key+iv reversed.
  const mirrored = rndEnc.subarray(8, 56);
  const expect = Buffer.concat([parsed.encKey, parsed.encIv]).reverse();
  assert.ok(mirrored.equals(expect), "upstream prekey must mirror client enc key+iv");

  // TG side: decrypts the whole 64-byte handshake (keystream from counter 0),
  // then reads proto_tag from the recovered tail [56:60].
  const keyUp = rndEnc.subarray(8, 40);
  const ivUp = rndEnc.subarray(40, 56);
  const tgDec = createAesCtr(keyUp, ivUp);
  const decrypted = tgDec.decrypt(rndEnc);
  assert.ok(decrypted.subarray(56, 60).equals(PROTO_TAG_ABRIDGED), "protoTag must survive to TG");
});

test("buildUpstreamHandshake: relay client->TG data round-trips through the proxy", () => {
  const secret = randomBytes(16);
  const { handshake, stream } = buildClientHandshake(secret, PROTO_TAG_ABRIDGED, 1);
  const parsed = parseClientHandshake(handshake, [secret]);
  assert.ok(parsed);
  const { rndEnc, encryptorUp } = buildUpstreamHandshake(parsed);

  // Client sends data -> proxy decrypts with client decryptor, encrypts with upstream encryptor.
  const payload = "getUpdates-request";
  const fromClient = stream.encrypt(Buffer.from(payload));
  const plain = parsed.decryptor.decrypt(fromClient);
  const toTg = encryptorUp.encrypt(plain);

  // TG decrypts with its own key/iv from the received handshake.
  const tgDec = createAesCtr(rndEnc.subarray(8, 40), rndEnc.subarray(40, 56));
  // TG's incoming keystream starts at offset 64 (after the 64-byte handshake).
  const sink = createAesCtr(rndEnc.subarray(8, 40), rndEnc.subarray(40, 56));
  sink.decrypt(Buffer.alloc(64)); // advance past handshake
  const received = sink.decrypt(toTg);
  assert.equal(received.toString(), payload);
});

test("getDcAddress: maps dc_idx to datacenter", () => {
  assert.deepEqual(getDcAddress(1), { host: "149.154.175.50", port: 443 });
  assert.deepEqual(getDcAddress(-1), { host: "149.154.175.50", port: 443 });
  assert.deepEqual(getDcAddress(2), { host: "149.154.167.51", port: 443 });
  assert.deepEqual(getDcAddress(5), { host: "149.154.171.5", port: 443 });
  assert.equal(getDcAddress(0), null);
  assert.equal(getDcAddress(6), null);
  assert.equal(getDcAddress(-99), null);
});
