// FILE: scripts/transport-probe.mjs
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Deep transport diagnostics against a deployed SimpleProxy: raw obfuscated2 vs
//            fake-TLS (with/without SNI), handshake-only and full-relay survival, in series
//   SCOPE: measures whether MTProto transports survive repeated handshakes and relay keep-alive
//          (NOT covered by live-smoke's single-shot checks); each iteration builds a FRESH
//          ClientHello/digest so the server-side replay guard (faketls_replay) is not tripped —
//          reusing one hello buffer makes N-1 attempts look like network failures
//   DEPENDS: none (node:net, node:crypto)
//   LINKS: V-M-LIVE-SMOKE, V-M-MTPROTO, V-M-MASK, V-M-REPLAY
//   ROLE: SCRIPT
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   main - parse args, run transport series, print summary
//   normalizeSecretAndDomain - strip user:/dd/ee prefixes, recover raw secret + SNI domain
//   buildObfsHandshake - 64-byte obfuscated2 client handshake
//   buildFakeTlsClientHello - fake-TLS ClientHello (optional SNI) with valid HMAC digest
//   wrapTlsAppdata - wrap bytes in a TLS 1.3 application-data record
//   probeRaw - raw obfuscated2 relay stays open ~1.2s
//   probeHandshakeOnly - fake-TLS: ClientHello -> ServerHello arrives?
//   probeFullRelay - fake-TLS: full handshake + obfs in appdata + relay alive 2s
// END_MODULE_MAP

// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.0.0 - extracted from ad-hoc temp probes used during Rostelecom DPI
//               triage. Consolidates raw/fake-TLS(SNI/no-SNI) handshake and relay checks
//               into a repeatable diagnostic. Key lesson baked in: NEVER reuse a ClientHello
//               buffer across iterations — the proxy's replay guard rejects repeated digests,
//               which looks identical to a network drop.
// END_CHANGE_SUMMARY

import net from "node:net";
import { randomBytes, createHash, createHmac, createCipheriv } from "node:crypto";

const PROTO_TAG_ABRIDGED = Buffer.from([0xef, 0xef, 0xef, 0xef]);
const DEFAULT_HOST = "78.154.103.40";
const DEFAULT_PORT = 13295;
const DEFAULT_ROUNDS = 5;

// --- CLI ---
const args = process.argv.slice(2);
let host = DEFAULT_HOST;
let port = DEFAULT_PORT;
let secretInput = process.env.MTPROTO_SECRET || "";
let rounds = DEFAULT_ROUNDS;
let domainOverride = null;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--secret") secretInput = args[++i] || "";
  else if (a === "--rounds") rounds = Number(args[++i]) || DEFAULT_ROUNDS;
  else if (a === "--domain") domainOverride = args[++i] || null;
  else if (a === "--host") host = args[++i] || host;
  else if (a === "--port") port = Number(args[++i]) || port;
  else if (/^[a-z0-9.-]+:\d+$/.test(a)) [host, port] = [a.slice(0, a.lastIndexOf(":")), Number(a.slice(a.lastIndexOf(":") + 1))];
  else if (a === "-h" || a === "--help") {
    console.log(`Usage: node scripts/transport-probe.mjs [host:port] --secret <hex> [--rounds N] [--domain <host>]`);
    console.log(`  --secret   MTPROTO_SECRET (32 hex; user: and dd/ee prefixes stripped; ee-tail hex -> SNI domain)`);
    console.log(`  --rounds   iterations per transport (default ${DEFAULT_ROUNDS})`);
    console.log(`  --domain   override fake-TLS SNI hostname (default: from ee-secret tail, else none)`);
    process.exit(0);
  }
}

// Accepts: plain 32-hex, "user:"+secret, "dd"+32hex, "ee"+32hex+hex(domain).
// Returns { secretHex, domain } — domain recovered from the ee-link tail unless overridden.
function normalizeSecretAndDomain(raw) {
  let hex = raw.includes(":") ? raw.slice(raw.lastIndexOf(":") + 1) : raw;
  hex = hex.trim().toLowerCase();
  let domain = null;
  if (/^[0-9a-f]{34,}$/.test(hex) && (hex.startsWith("dd") || hex.startsWith("ee"))) {
    const rest = hex.slice(34); // after prefix(2) + raw secret(32)
    if (rest.length >= 2) {
      try {
        domain = Buffer.from(rest, "hex").toString("latin1");
      } catch {
        domain = null;
      }
    }
    hex = hex.slice(2, 34);
  }
  if (domainOverride) domain = domainOverride;
  return { secretHex: hex, domain };
}

// --- MTProto primitives (mirror src/mtproto.js + src/faketls.js, self-contained) ---
function sha256(...parts) {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
}
function ctrKeystream(key, iv) {
  const c = createCipheriv("aes-256-ecb", key, null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(iv), c.final()]);
}
function createAesCtr(key, iv) {
  let counter = Buffer.from(iv);
  const enc = (data) => {
    const out = Buffer.alloc(data.length);
    let pos = 0;
    while (pos < data.length) {
      const ks = ctrKeystream(key, counter);
      const n = Math.min(16, data.length - pos);
      for (let i = 0; i < n; i++) out[pos + i] = data[pos + i] ^ ks[i];
      pos += n;
      for (let i = 15; i >= 0; i--) {
        counter[i] = (counter[i] + 1) & 0xff;
        if (counter[i] !== 0) break;
      }
    }
    return out;
  };
  return { encrypt: enc, decrypt: enc };
}
function buildObfsHandshake(secret, protoTag, dcIdx) {
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
  return Buffer.concat([init.subarray(0, 56), encrypted.subarray(56, 64)]);
}
const len16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
};
function buildSniExtension(host) {
  const name = Buffer.from(host, "latin1");
  const snEntry = Buffer.concat([Buffer.from([0x00]), len16(name.length), name]);
  const list = Buffer.concat([len16(snEntry.length), snEntry]);
  return Buffer.concat([Buffer.from([0x00, 0x00]), len16(list.length), list]);
}

// FRESH per call: fresh random + fresh sessionId -> fresh HMAC digest. Never reuse the
// returned buffer across connections (replay guard would reject repeated digests).
function buildFakeTlsClientHello(secret, domain) {
  const sessionId = randomBytes(16);
  const timestamp = Math.floor(Date.now() / 1000);
  const tsBytes = Buffer.alloc(4);
  tsBytes.writeUInt32LE(timestamp, 0);
  const cipherSuites = Buffer.from([0x00, 0x02, 0x13, 0x01]);
  const compression = Buffer.from([0x01, 0x00]);
  const padLen = 533;
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
  padExt.writeUInt16BE(padLen, 2);
  const sniExt = domain ? buildSniExtension(domain) : Buffer.alloc(0);
  const extensions = Buffer.concat([sniExt, padExt]);
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(extensions.length, 0);
  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]), Buffer.alloc(32), Buffer.from([sessionId.length]), sessionId,
    cipherSuites, compression, extTotal, extensions,
  ]);
  const hsLenBuf = Buffer.alloc(3);
  hsLenBuf.writeUIntBE(inner.length, 0, 3);
  const handshakeMsg = Buffer.concat([Buffer.from([0x01]), hsLenBuf, inner]);
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(handshakeMsg.length, 0);
  let hello = Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recordLenBuf, handshakeMsg]);
  const DIGEST_POS = 11, DIGEST_LEN = 32;
  const msg = Buffer.concat([hello.subarray(0, DIGEST_POS), Buffer.alloc(DIGEST_LEN), hello.subarray(DIGEST_POS + DIGEST_LEN)]);
  const computed = createHmac("sha256", secret).update(msg).digest();
  const digest = Buffer.alloc(DIGEST_LEN);
  for (let i = 0; i < DIGEST_LEN; i++) digest[i] = computed[i] ^ (i < DIGEST_LEN - 4 ? 0 : tsBytes[i - (DIGEST_LEN - 4)]);
  return Buffer.concat([hello.subarray(0, DIGEST_POS), digest, hello.subarray(DIGEST_POS + DIGEST_LEN)]);
}
function wrapTlsAppdata(data) {
  const l = Buffer.alloc(2);
  l.writeUInt16BE(data.length, 0);
  return Buffer.concat([Buffer.from([0x17, 0x03, 0x03]), l, data]);
}

// --- Probes ---

// Raw obfuscated2: send 64-byte handshake, relay must stay open ~1.2s.
function probeRaw(obfsHandshake) {
  return new Promise((resolve) => {
    const s = net.connect(port, host, () => s.write(obfsHandshake));
    const t = setTimeout(() => { s.destroy(); resolve("relay-open"); }, 1200);
    s.on("error", (e) => { clearTimeout(t); resolve("err:" + e.code); });
    s.on("close", () => { clearTimeout(t); resolve("closed"); });
  });
}

// fake-TLS handshake-only: ClientHello -> ServerHello (0x16) arrives?
function probeHandshakeOnly(secret) {
  return new Promise((resolve) => {
    const s = net.connect(port, host, () => s.write(buildFakeTlsClientHello(secret, null)));
    let saw = false;
    const t = setTimeout(() => { s.destroy(); resolve("timeout"); }, 6000);
    s.on("data", (d) => { if (d[0] === 0x16) { saw = true; clearTimeout(t); s.destroy(); resolve("serverhello"); } });
    s.on("error", (e) => { clearTimeout(t); resolve("err:" + e.code); });
    s.on("close", () => { clearTimeout(t); resolve(saw ? "serverhello" : "closed"); });
  });
}

// fake-TLS with SNI + full relay: ClientHello(SNI) -> ServerHello -> obfs in appdata -> alive 2s?
function probeFullRelay(secret, obfsHandshake, domain) {
  return new Promise((resolve) => {
    const s = net.connect(port, host, () => s.write(buildFakeTlsClientHello(secret, domain)));
    let raw = Buffer.alloc(0);
    let sawSH = false;
    let sent = false;
    const t = setTimeout(() => { s.destroy(); resolve("timeout"); }, 8000);
    const finish = (v) => { clearTimeout(t); s.destroy(); resolve(v); };
    s.on("data", (d) => {
      raw = Buffer.concat([raw, d]);
      if (!sent) {
        while (raw.length >= 5) {
          const recLen = raw.readUInt16BE(3);
          if (raw.length < 5 + recLen) break;
          if (raw[0] === 0x16) sawSH = true;
          raw = raw.subarray(5 + recLen);
        }
        if (sawSH && !sent) {
          sent = true;
          setTimeout(() => { if (!s.destroyed) s.write(wrapTlsAppdata(obfsHandshake)); }, 150);
        }
      }
    });
    s.on("error", (e) => finish("err:" + e.code));
    s.on("close", () => finish(sent ? "relay-closed" : "closed-pre-relay"));
    setTimeout(() => { if (sent) finish("relay-open-2s"); }, 2000);
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- main ---
const { secretHex, domain } = normalizeSecretAndDomain(secretInput);
if (!/^[0-9a-f]{32}$/.test(secretHex)) {
  console.error("no valid secret (set --secret or MTPROTO_SECRET; 32 hex after dd/ee/user: stripping)");
  process.exit(2);
}
const secret = Buffer.from(secretHex, "hex");
const obfsHandshake = buildObfsHandshake(secret, PROTO_TAG_ABRIDGED, 2);

console.log(`transport-probe ${host}:${port} | rounds=${rounds} | SNI domain=${domain ?? "(none)"}`);
const rows = [];
for (let i = 0; i < rounds; i++) {
  const raw = await probeRaw(obfsHandshake);
  const hs = await probeHandshakeOnly(secret);
  const relay = await probeFullRelay(secret, obfsHandshake, domain);
  rows.push({ i: i + 1, raw, hs, relay });
  console.log(`  #${i + 1}: raw=${raw} handshake=${hs} relay=${relay}`);
  await sleep(400);
}

const count = (col, v) => rows.filter((r) => r[col] === v).length;
console.log("\nSUMMARY");
console.log(`  raw obfs2 relay-open      : ${count("raw", "relay-open")}/${rounds}`);
console.log(`  fake-TLS handshake (SH)   : ${count("hs", "serverhello")}/${rounds}`);
console.log(`  fake-TLS full relay open  : ${count("relay", "relay-open-2s")}/${rounds}`);
process.exit(rows.every((r) => r.raw === "relay-open" && r.hs === "serverhello" && r.relay === "relay-open-2s") ? 0 : 1);
