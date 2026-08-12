// FILE: src/faketls.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Fake-TLS (ee-secret) handshake validation, ServerHello construction, TLS record framing
//   SCOPE: ClientHello HMAC validation, fake ServerHello build, TLS 1.3 record read/write helpers
//   DEPENDS: node:crypto
//   LINKS: M-FAKETLS
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   validateClientHello - validate a fake-TLS ClientHello against configured secrets
//   buildServerHello - construct the fake ServerHello + ChangeCipherSpec + ApplicationData
//   createTlsRecordReader - stateful TLS record parser (strips framing, yields app data)
//   wrapTlsRecord - wrap app data in a TLS 1.3 application-data record
//   genX25519PublicKey - generate a plausible x25519 public key (square mod P)
// END_MODULE_MAP

import { createHmac, randomBytes } from "node:crypto";

// Byte layout (per alexbers/mtprotoproxy handle_fake_tls_handshake).
const DIGEST_POS = 11;
const DIGEST_LEN = 32;
const DIGEST_HALFLEN = 16;
const SESSION_ID_LEN_POS = DIGEST_POS + DIGEST_LEN; // 43
const SESSION_ID_POS = SESSION_ID_LEN_POS + 1; // 44

const TLS_VERS = Buffer.from([0x03, 0x03]);
const TLS_CIPHERSUITE = Buffer.from([0x13, 0x01]); // TLS_AES_128_GCM_SHA256
const TLS_CHANGE_CIPHER = Buffer.from([0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
const TLS_APP_HDR = Buffer.from([0x17, 0x03, 0x03]);

function hmacSha256(key, msg) {
  return createHmac("sha256", key).update(msg).digest();
}

// START_CONTRACT: genX25519PublicKey
//   PURPOSE: Generate a 32-byte value that is a square modulo 2^255-19 (looks like a valid x25519 key)
//   INPUTS: { none }
//   OUTPUTS: { Buffer(32) - little-endian square mod P }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS
// END_CONTRACT: genX25519PublicKey
export function genX25519PublicKey() {
  // START_BLOCK_X25519
  const P = (1n << 255n) - 19n;
  const raw = randomBytes(32);
  let n = raw.readUInt8(31) & 0x7f; // clear high bit -> < 2^255
  let le = 0n;
  for (let i = 30; i >= 0; i--) le = (le << 8n) | BigInt(raw[i]);
  le |= BigInt(n) << 248n;
  const x = le % P;
  const sq = (x * x) % P;
  const out = Buffer.alloc(32);
  let v = sq;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
  // END_BLOCK_X25519
}

// START_CONTRACT: validateClientHello
//   PURPOSE: Validate a fake-TLS ClientHello against configured secrets via HMAC
//   INPUTS: { handshake: Buffer - full ClientHello from 0x16 onward, secrets: Buffer[] }
//   OUTPUTS: { { secret, sessionId, digest } | null }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS
// END_CONTRACT: validateClientHello
export function validateClientHello(handshake, secrets) {
  // START_BLOCK_VALIDATE
  if (handshake.length < SESSION_ID_POS + 1) return null;
  if (handshake[0] !== 0x16 || handshake[1] !== 0x03 || handshake[2] !== 0x01) return null;
  const recordLen = handshake.readUInt16BE(3);
  if (recordLen < 512) return null;
  if (handshake.length < 5 + recordLen) return null;
  if (handshake[5] !== 0x01) return null; // ClientHello handshake type

  const digest = handshake.subarray(DIGEST_POS, DIGEST_POS + DIGEST_LEN);
  const sidLen = handshake[SESSION_ID_LEN_POS];
  const sessionId = handshake.subarray(SESSION_ID_POS, SESSION_ID_POS + sidLen);
  if (sessionId.length !== sidLen) return null;

  // msg = handshake with the digest field zeroed out
  const msg = Buffer.concat([
    handshake.subarray(0, DIGEST_POS),
    Buffer.alloc(DIGEST_LEN),
    handshake.subarray(DIGEST_POS + DIGEST_LEN),
  ]);

  for (const secret of secrets) {
    const computed = hmacSha256(secret, msg);
    const xored = Buffer.alloc(DIGEST_LEN);
    let ok = true;
    for (let i = 0; i < DIGEST_LEN; i++) {
      xored[i] = digest[i] ^ computed[i];
      if (i < DIGEST_LEN - 4 && xored[i] !== 0) ok = false;
    }
    if (!ok) continue;
    // First 28 bytes zero -> secret matched. Timestamp in last 4 bytes (lenient: accept any).
    return {
      secret,
      sessionId: Buffer.from(sessionId),
      digest: Buffer.from(digest),
      digestPrefix: Buffer.from(digest.subarray(0, DIGEST_HALFLEN)),
    };
  }
  return null;
  // END_BLOCK_VALIDATE
}

// START_CONTRACT: buildServerHello
//   PURPOSE: Build the fake ServerHello + ChangeCipherSpec + ApplicationData response
//   INPUTS: { secret: Buffer(16), clientDigest: Buffer(32), sessionId: Buffer }
//   OUTPUTS: { Buffer - full response packet }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS
// END_CONTRACT: buildServerHello
export function buildServerHello(secret, clientDigest, sessionId) {
  // START_BLOCK_BUILD
  const x25519 = genX25519PublicKey();
  const tlsExtensions = Buffer.concat([
    Buffer.from([0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]),
    x25519,
    Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]),
  ]);
  const srvHello = Buffer.concat([
    TLS_VERS,
    Buffer.alloc(DIGEST_LEN), // random placeholder, replaced by response digest
    Buffer.from([sessionId.length]),
    sessionId,
    TLS_CIPHERSUITE,
    Buffer.from([0x00]),
    tlsExtensions,
  ]);

  const recordLen = 4 + srvHello.length; // 1 (type) + 3 (hs length) + srvHello
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(recordLen, 0);
  const hsLenBuf = Buffer.alloc(3);
  hsLenBuf.writeUIntBE(srvHello.length, 0, 3);

  const fakeCertLen = 1024 + Math.floor(Math.random() * 3072); // 1024..4095
  const httpData = randomBytes(fakeCertLen);
  const httpLenBuf = Buffer.alloc(2);
  httpLenBuf.writeUInt16BE(httpData.length, 0);

  let helloPkt = Buffer.concat([
    Buffer.from([0x16, 0x03, 0x03]),
    recordLenBuf,
    Buffer.from([0x02]),
    hsLenBuf,
    srvHello,
    TLS_CHANGE_CIPHER,
    TLS_APP_HDR,
    httpLenBuf,
    httpData,
  ]);

  // Response digest = HMAC(secret, clientDigest + helloPkt); placed at [11:43].
  const respDigest = hmacSha256(secret, Buffer.concat([clientDigest, helloPkt]));
  helloPkt = Buffer.concat([
    helloPkt.subarray(0, DIGEST_POS),
    respDigest,
    helloPkt.subarray(DIGEST_POS + DIGEST_LEN),
  ]);
  return helloPkt;
  // END_BLOCK_BUILD
}

// START_CONTRACT: createTlsRecordReader
//   PURPOSE: Stateful TLS 1.3 record parser: buffers raw bytes, yields application-data payloads
//   INPUTS: { none } -> { feed(chunk: Buffer): Buffer[] }
//   OUTPUTS: { { feed } - returns array of app-data Buffers; 0x14 ChangeCipherSpec records skipped }
//   SIDE_EFFECTS: maintains internal buffer/state
//   LINKS: M-FAKETLS
// END_CONTRACT: createTlsRecordReader
export function createTlsRecordReader() {
  // START_BLOCK_READER
  let buf = Buffer.alloc(0);
  let state = "header";
  let bodyLen = 0;
  let recType = 0;
  return {
    feed(chunk) {
      buf = Buffer.concat([buf, chunk]);
      const out = [];
      for (;;) {
        if (state === "header") {
          if (buf.length < 5) break;
          recType = buf[0];
          bodyLen = buf.readUInt16BE(3);
          buf = buf.subarray(5);
          state = "body";
        }
        if (state === "body") {
          if (buf.length < bodyLen) break;
          const body = buf.subarray(0, bodyLen);
          buf = buf.subarray(bodyLen);
          state = "header";
          if (recType === 0x14) continue; // skip ChangeCipherSpec
          if (recType === 0x17) out.push(Buffer.from(body));
          // other record types are ignored
        }
      }
      return out;
    },
  };
  // END_BLOCK_READER
}

// START_CONTRACT: wrapTlsRecord
//   PURPOSE: Wrap app data in TLS 1.3 application-data record(s) (0x17 0x03 0x03 <len> <data>)
//   INPUTS: { data: Buffer }
//   OUTPUTS: { Buffer - one or more TLS records, chunked at 16408 bytes }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS
// END_CONTRACT: wrapTlsRecord
export function wrapTlsRecord(data) {
  // START_BLOCK_WRAP
  const MAX = 16384 + 24;
  const parts = [];
  for (let start = 0; start < data.length; start += MAX) {
    const end = Math.min(start + MAX, data.length);
    const len = end - start;
    parts.push(Buffer.from([0x17, 0x03, 0x03, (len >> 8) & 0xff, len & 0xff]));
    parts.push(data.subarray(start, end));
  }
  return Buffer.concat(parts);
  // END_BLOCK_WRAP
}