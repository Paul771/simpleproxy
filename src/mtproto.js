// FILE: src/mtproto.js
// VERSION: 1.1.0
// START_MODULE_CONTRACT
//   PURPOSE: MTProto proxy obfuscated2 handshake parse/build and DC address mapping (pure logic)
//   SCOPE: client handshake validation, upstream handshake construction, DC lookup
//   DEPENDS: node:crypto
//   LINKS: M-MTPROTO
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   parseClientHandshake - validate a 64-byte client handshake against secrets
//   buildUpstreamHandshake - construct the 64-byte handshake sent to a Telegram DC
//   getDcAddress - resolve dc_idx to a Telegram datacenter host:port
//   createAesCtr - AES-256-CTR stream (encrypt/decrypt with state)
// END_MODULE_MAP

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

// Obfuscated2 layout (per alexbers/mtprotoproxy reference implementation).
const SKIP_LEN = 8;
const PREKEY_LEN = 32;
const IV_LEN = 16;
const HANDSHAKE_LEN = 64;
const PROTO_TAG_POS = 56;
const DC_IDX_POS = 60;

const PROTO_TAG_ABRIDGED = Buffer.from([0xef, 0xef, 0xef, 0xef]);
const PROTO_TAG_INTERMEDIATE = Buffer.from([0xee, 0xee, 0xee, 0xee]);
const PROTO_TAG_SECURE = Buffer.from([0xdd, 0xdd, 0xdd, 0xdd]);
const PROTO_TAGS = [PROTO_TAG_ABRIDGED, PROTO_TAG_INTERMEDIATE, PROTO_TAG_SECURE];

// Reserved nonce prefixes a real client never starts with (protects multiplexing).
const RESERVED_NONCE_BEGINNINGS = [
  Buffer.from("HEAD", "latin1"),
  Buffer.from("POST", "latin1"),
  Buffer.from("GET ", "latin1"),
  Buffer.from([0xee, 0xee, 0xee, 0xee]),
  Buffer.from([0xdd, 0xdd, 0xdd, 0xdd]),
  Buffer.from([0x16, 0x03, 0x01, 0x02]),
];
const RESERVED_NONCE_CONTINUES = [Buffer.from([0x00, 0x00, 0x00, 0x00])];

// Telegram datacenter IPs (IPv4, port 443), indexed by abs(dc_idx)-1.
const TG_DATACENTERS_V4 = [
  "149.154.175.50",
  "149.154.167.51",
  "149.154.175.100",
  "149.154.167.91",
  "149.154.171.5",
];
// Telegram datacenter IPv6 addresses (port 443), same DC index order as V4.
// Used only when the operator opts in via MTPROTO_PREFER_IPV6.
const TG_DATACENTERS_V6 = [
  "2001:b28:f23d:f001::a",
  "2001:b28:f23f:f002::a",
  "2001:b28:f23d:f003::a",
  "2001:b28:f23f:f004::a",
  "2001:b28:f23f:f005::a",
];
const TG_DATACENTER_PORT = 443;

// START_CONTRACT: createAesCtr
//   PURPOSE: Create a stateful AES-256-CTR encryptor/decryptor
//   INPUTS: { key: Buffer(32), iv: Buffer(16) }
//   OUTPUTS: { { update(data: Buffer): Buffer } - stream transform }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO
// END_CONTRACT: createAesCtr
export function createAesCtr(key, iv) {
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  const decipher = createDecipheriv("aes-256-ctr", key, iv);
  return {
    encrypt(data) {
      return cipher.update(data);
    },
    decrypt(data) {
      return decipher.update(data);
    },
  };
}

function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}

function reverse(buf) {
  return Buffer.from(buf).reverse();
}

// START_CONTRACT: parseClientHandshake
//   PURPOSE: Validate a 64-byte client obfuscated2 handshake against configured secrets
//   INPUTS: { handshake: Buffer(64), secrets: Buffer[] - each 16 bytes }
//   OUTPUTS: { ParsedHandshake | null - { secret, protoTag, dcIdx, encKey, encIv, decryptor } }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO
// END_CONTRACT: parseClientHandshake
export function parseClientHandshake(handshake, secrets) {
  // START_BLOCK_PARSE_HANDSHAKE
  if (handshake.length !== HANDSHAKE_LEN) return null;

  const decPrekey = handshake.subarray(SKIP_LEN, SKIP_LEN + PREKEY_LEN);
  const decIv = handshake.subarray(SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);

  for (const secret of secrets) {
    const decKey = sha256(decPrekey, secret);
    const stream = createAesCtr(decKey, decIv);
    const decrypted = stream.decrypt(handshake);

    const protoTag = decrypted.subarray(PROTO_TAG_POS, PROTO_TAG_POS + 4);
    if (!PROTO_TAGS.some((t) => t.equals(protoTag))) continue;

    const dcIdx = decrypted.readInt16LE(DC_IDX_POS); // signed little-endian (2 bytes)

    const encPrekeyAndIv = reverse(handshake.subarray(SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN));
    const encPrekey = encPrekeyAndIv.subarray(0, PREKEY_LEN);
    const encIv = encPrekeyAndIv.subarray(PREKEY_LEN, PREKEY_LEN + IV_LEN);
    const encKey = sha256(encPrekey, secret);

    return {
      secret,
      protoTag,
      dcIdx,
      encKey, // TG mirrors this into its stream; the client decrypts with it
      encIv,
      decryptor: stream, // stateful, already advanced past the 64-byte handshake
    };
  }
  return null;
  // END_BLOCK_PARSE_HANDSHAKE
}

// START_CONTRACT: buildUpstreamHandshake
//   PURPOSE: Build the 64-byte handshake sent to a Telegram DC in FAST_MODE
//   INPUTS: { parsed: ParsedHandshake }
//   OUTPUTS: { { rndEnc: Buffer(64), encryptorUp: { encrypt }, decryptorUp: { decrypt } } }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO
// END_CONTRACT: buildUpstreamHandshake
export function buildUpstreamHandshake(parsed) {
  // START_BLOCK_BUILD_HANDSHAKE
  let rnd;
  for (;;) {
    rnd = randomBytes(HANDSHAKE_LEN);
    // Valid nonce: first byte not 0xef, no reserved prefixes, [4:8] not zeroes.
    if (rnd[0] === 0xef) continue;
    if (RESERVED_NONCE_BEGINNINGS.some((b) => b.equals(rnd.subarray(0, 4)))) continue;
    if (RESERVED_NONCE_CONTINUES.some((b) => b.equals(rnd.subarray(4, 8)))) continue;
    break;
  }

  parsed.protoTag.copy(rnd, PROTO_TAG_POS);
  // FAST_MODE: mirror the client's enc key+iv into the upstream prekey slot, reversed.
  const clientKeyIv = Buffer.concat([parsed.encKey, parsed.encIv]);
  reverse(clientKeyIv).copy(rnd, SKIP_LEN);

  // Upstream directions: outgoing (proxy->DC) uses rnd[8:40] as key, incoming uses reversed.
  const encKeyUp = rnd.subarray(SKIP_LEN, SKIP_LEN + PREKEY_LEN);
  const encIvUp = rnd.subarray(SKIP_LEN + PREKEY_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN);
  const decKeyUp = reverse(rnd.subarray(SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)).subarray(0, PREKEY_LEN);
  const decIvUp = reverse(rnd.subarray(SKIP_LEN, SKIP_LEN + PREKEY_LEN + IV_LEN)).subarray(PREKEY_LEN);

  // Encrypt the whole 64-byte nonce with a single continuous keystream; only [56:64] is kept.
  // The same encryptor continues into the relay stream (counter already advanced past 64).
  const encryptorUp = createAesCtr(encKeyUp, encIvUp);
  const decryptorUp = createAesCtr(decKeyUp, decIvUp);
  const encrypted = encryptorUp.encrypt(rnd);
  const rndEnc = Buffer.concat([rnd.subarray(0, PROTO_TAG_POS), encrypted.subarray(PROTO_TAG_POS)]);

  return { rndEnc, encryptorUp, decryptorUp };
  // END_BLOCK_BUILD_HANDSHAKE
}

// START_CONTRACT: getDcAddress
//   PURPOSE: Resolve a handshake dc_idx to a Telegram datacenter address
//   INPUTS: { dcIdx: number - signed little-endian from handshake, opts?: { preferIpv6: boolean } }
//   OUTPUTS: { { host: string, port: number } | null }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO
// END_CONTRACT: getDcAddress
export function getDcAddress(dcIdx, { preferIpv6 = false } = {}) {
  const idx = Math.abs(dcIdx) - 1;
  const table = preferIpv6 ? TG_DATACENTERS_V6 : TG_DATACENTERS_V4;
  if (!Number.isInteger(idx) || idx < 0 || idx >= table.length) return null;
  return { host: table[idx], port: TG_DATACENTER_PORT };
}

// START_CONTRACT: getDcAddressCandidates
//   PURPOSE: Return an ordered list of DC addresses for connect-with-fallback
//   INPUTS: { dcIdx: number, opts?: { preferIpv6: boolean } }
//   OUTPUTS: { Array<{ host: string, port: number }> - preferred family first, then the other }
//   SIDE_EFFECTS: none
//   LINKS: M-MTPROTO
// END_CONTRACT: getDcAddressCandidates
export function getDcAddressCandidates(dcIdx, { preferIpv6 = false } = {}) {
  const idx = Math.abs(dcIdx) - 1;
  if (!Number.isInteger(idx) || idx < 0 || idx >= TG_DATACENTERS_V4.length) return [];
  const port = TG_DATACENTER_PORT;
  const v4 = { host: TG_DATACENTERS_V4[idx], port };
  const v6 = { host: TG_DATACENTERS_V6[idx], port };
  // Only one address family is useful when the operator pinned a family; both lists have an
  // entry for every valid index, so we always return two candidates ordered by preference.
  return preferIpv6 ? [v6, v4] : [v4, v6];
}
