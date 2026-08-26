// FILE: scripts/live-smoke.mjs
// VERSION: 1.1.1
// START_MODULE_CONTRACT
//   PURPOSE: Live smoke-test suite against a deployed SimpleProxy instance (Wispbyte / any host)
//   SCOPE: TCP reachability, CONNECT allowlist/denylist, plain-HTTP 405, plain-MTProto reject,
//          fake-TLS mask splice (byte-compare vs real origin), obfuscated2 + fake-TLS handshake;
//          --isp-diag mode: Telegram-DC reachability from the runner's network and a timed
//          fake-TLS handshake series against the proxy (ISP/DPI diagnostics, e.g. Rostelecom)
//   DEPENDS: none (node:net, node:crypto)
//   LINKS: V-M-TUNNEL, V-M-PROXY, V-M-MTPROTO, V-M-MASK, V-M-FAKETLS
//   ROLE: SCRIPT
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   main - parse args and run every smoke check in order
//   checkTcp - port is reachable
//   checkConnectTelegram - CONNECT api.telegram.org:443 is allowed (200)
//   checkConnectDenied - CONNECT to a foreign host is rejected (403)
//   checkPlainHttp - plain HTTP GET is answered 405
//   checkPlainMtReject - plain MTProto with a wrong secret is silently closed
//   checkMask - unknown-SNI ClientHello is spliced to mask_host (bytes match the real origin)
//   checkObfs2 - obfuscated2 handshake with the real secret opens the relay
//   checkFakeTls - fake-TLS (dd) handshake with the real secret gets a ServerHello
//   timedTcpConnect - TCP connect latency probe with a hard deadline
//   checkDcReach - Telegram DC IPv4/IPv6:443 reachability from this machine
//   checkHandshakeTiming - N timed fake-TLS handshakes against the proxy, p50/max report
// END_MODULE_MAP

// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.1.1 - normalizeSecret(): ee-links ("ee" + 32 hex + hex(domain), e.g.
//                rutube.ru -> 52+ chars) now reduce to the raw 16-byte secret; previously
//                only the dd-form (exactly 34 chars) was stripped, so ee users got a bogus
//                "no secret" for obfs2/faketls/handshake-timing checks
// END_CHANGE_SUMMARY

import net from "node:net";
import crypto from "node:crypto";
const { randomBytes, createHash, createHmac, createCipheriv, createDecipheriv } = crypto;

const DEFAULT_HOST = "78.154.103.40";
const DEFAULT_PORT = 13295;
const PROTO_TAG_ABRIDGED = Buffer.from([0xef, 0xef, 0xef, 0xef]);
const HANDSHAKE_LEN = 64;
const CONNECT_TIMEOUT_MS = 10_000;
const RELAY_PROBE_MS = 2500;

// --- CLI ---
const args = process.argv.slice(2);
let host = DEFAULT_HOST;
let port = DEFAULT_PORT;
let secretHex = process.env.MTPROTO_SECRET || "";
let compareMask = false;
let ispDiag = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--secret") secretHex = args[++i] || "";
  else if (a === "--compare-mask") compareMask = true;
  else if (a === "--isp-diag" || a === "--rt") ispDiag = true;
  else if (a === "--host") host = args[++i] || host;
  else if (a === "--port") port = Number(args[++i]) || port;
  else if (/^[a-z0-9.-]+:\d+$/.test(a)) [host, port] = [a.slice(0, a.lastIndexOf(":")), Number(a.slice(a.lastIndexOf(":") + 1))];
  else if (a === "-h" || a === "--help") {
    console.log(`Usage: node scripts/live-smoke.mjs [host:port] [--secret <hex>] [--compare-mask] [--isp-diag]`);
    console.log(`  --secret       MTPROTO_SECRET (32 hex; dd/ee prefix and user: prefix are stripped)`);
    console.log(`  --compare-mask byte-compare the mask splice against the real origin (needs outbound 443)`);
    console.log(`  --isp-diag     ISP/DPI diagnostics: Telegram DC reachability + timed handshakes (run from the client network, e.g. under Rostelecom)`);
    process.exit(0);
  }
}

// MTPROTO_SECRET entries may be "user:secret" and/or carry the dd/ee tg://proxy prefix.
// Accepted forms (lowercased): plain 32-hex; "dd"+32-hex (34); "user:"+any of those;
// "ee"+32-hex+hex(domain) — e.g. ee<64hex>7275747562652e7275 for rutube.ru (52+ chars).
function normalizeSecret(raw) {
  let hex = raw.includes(":") ? raw.slice(raw.lastIndexOf(":") + 1) : raw;
  hex = hex.trim().toLowerCase();
  if (/^[0-9a-f]{34,}$/.test(hex) && (hex.startsWith("dd") || hex.startsWith("ee"))) {
    // tg://proxy prefixed form: the next 32 hex chars are the raw 16-byte MTProto secret;
    // anything after them is the fake-TLS domain in hex and must be dropped.
    return hex.slice(2, 34);
  }
  return hex;
}

const secret = normalizeSecret(secretHex.trim().toLowerCase());
const results = [];

// START_BLOCK_SMOKE_UTILS
function report(name, pass, detail) {
  results.push(pass);
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}${detail ? " — " + detail : ""}`);
}

// Diagnostic observation: never affects the exit code (unlike report()).
function info(name, detail) {
  console.log(`INFO  ${name}${detail ? " — " + detail : ""}`);
}

function connectOnce(onConnect, onData, onClose, timeoutMs = CONNECT_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const s = net.connect(port, host, () => onConnect && onConnect(s, finish));
    const timer = setTimeout(() => {
      s.destroy();
      resolve("timeout");
    }, timeoutMs);
    let settled = false;
    const finish = (val) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      s.destroy();
      resolve(val);
    };
    s.on("data", (d) => onData && onData(s, d, finish));
    s.on("close", () => onClose ? onClose(s, finish) : finish("closed"));
    s.on("error", (e) => finish("error:" + e.message));
  });
}
// END_BLOCK_SMOKE_UTILS

// START_BLOCK_CHECK_TCP
async function checkTcp() {
  const out = await connectOnce((s, finish) => finish("open"));
  report("tcp", out === "open", `${host}:${port}`);
}
// END_BLOCK_CHECK_TCP

// START_BLOCK_CHECK_CONNECT
async function checkConnectTelegram() {
  const out = await connectOnce(
    (s) => s.write("CONNECT api.telegram.org:443 HTTP/1.1\r\nHost: api.telegram.org:443\r\n\r\n"),
    (s, d, finish) => {
      const text = d.toString("latin1");
      if (text.includes("200")) finish("200:" + text.split("\r\n")[0]);
      if (text.includes("403") || text.includes("407")) finish(text.split("\r\n")[0]);
    },
    (s, finish) => finish("closed-before-200")
  );
  report("connect-telegram", typeof out === "string" && out.startsWith("200"), out);
}

async function checkConnectDenied() {
  const out = await connectOnce(
    (s) => s.write("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
    (s, d, finish) => finish(d.toString("latin1").split("\r\n")[0])
  );
  report("connect-denied", typeof out === "string" && out.includes("403"), out);
}
// END_BLOCK_CHECK_CONNECT

// START_BLOCK_CHECK_HTTP
async function checkPlainHttp() {
  const out = await connectOnce(
    (s) => s.write("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    (s, d, finish) => finish(d.toString("latin1").split("\r\n")[0])
  );
  report("plain-http-405", typeof out === "string" && out.includes("405"), out);
}
// END_BLOCK_CHECK_HTTP

// START_BLOCK_CHECK_PLAIN_REJECT
async function checkPlainMtReject() {
  const junk = randomBytes(HANDSHAKE_LEN);
  junk[0] = 0x11; // avoid HTTP-method / reserved prefixes
  const out = await connectOnce(
    (s) => s.write(junk),
    null,
    (s, finish) => finish("closed")
  );
  report("plain-mt-reject", out === "closed", out);
}
// END_BLOCK_CHECK_PLAIN_REJECT

// START_BLOCK_CHECK_MASK
function buildClientHello(sni, padLen = 533) {
  const legacyVersion = Buffer.from([0x03, 0x03]);
  const random = randomBytes(32);
  const sessionId = randomBytes(16);
  const cipherSuites = Buffer.from([0x13, 0x01, 0x13, 0x02, 0x00, 0x2f, 0x00, 0x35]);
  const compMethods = Buffer.from([0x01, 0x00]);
  const sniName = Buffer.from(sni, "ascii");
  const sniHost = Buffer.alloc(2 + 1 + 2 + sniName.length);
  sniHost.writeUInt16BE(sniName.length + 3, 0);
  sniHost[2] = 0x00;
  sniHost.writeUInt16BE(sniName.length, 3);
  sniName.copy(sniHost, 5);
  const sniExt = Buffer.alloc(2 + sniHost.length);
  sniExt.writeUInt16BE(sniHost.length, 0);
  sniHost.copy(sniExt, 2);
  const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
  padExt.writeUInt16BE(padLen, 2);
  const exts = Buffer.concat([sniExt, padExt]);
  const extensions = Buffer.alloc(2 + exts.length);
  extensions.writeUInt16BE(exts.length, 0);
  exts.copy(extensions, 2);
  const inner = Buffer.concat([legacyVersion, random, Buffer.from([sessionId.length]), sessionId, Buffer.from([cipherSuites.length]), cipherSuites, compMethods, extensions]);
  const hsLen = Buffer.alloc(3);
  hsLen.writeUIntBE(inner.length, 0, 3);
  const handshake = Buffer.concat([Buffer.from([0x01]), hsLen, inner]);
  const recLen = Buffer.alloc(2);
  recLen.writeUInt16BE(handshake.length, 0);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recLen, handshake]);
}

function sendAndCollect(connectFn, payload, collectMs = 3000) {
  return new Promise((resolve) => {
    const s = connectFn();
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { s.destroy(); resolve(buf); }, collectMs);
    s.on("connect", () => s.write(payload));
    s.on("data", (d) => { buf = Buffer.concat([buf, d]); });
    s.on("error", () => {});
    s.on("close", () => { clearTimeout(timer); resolve(buf); });
  });
}

async function checkMask() {
  const UNKNOWN_SNI = "cdn.nonexistent.example";
  const hello = buildClientHello(UNKNOWN_SNI);
  const viaProxy = await sendAndCollect(() => net.connect(port, host), hello);
  if (!compareMask) {
    report("mask-splice", viaProxy.length > 0, `${viaProxy.length} bytes back (splice to mask_host)`);
    return;
  }
  const direct = await sendAndCollect(() => net.connect(443, "www.google.com"), hello);
  const same = viaProxy.length === direct.length && viaProxy.equals(direct);
  report("mask-splice", same, `proxy ${viaProxy.length}B vs origin ${direct.length}B (byte-compare ${same ? "equal" : "DIFFERS"})`);
}
// END_BLOCK_CHECK_MASK

// START_BLOCK_MT_CLIENT
const sha256 = (...parts) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};

function createAesCtr(key, iv) {
  const cipher = createCipheriv("aes-256-ctr", key, iv);
  const decipher = createDecipheriv("aes-256-ctr", key, iv);
  return {
    encrypt: (data) => cipher.update(data),
    decrypt: (data) => decipher.update(data),
  };
}

function buildClientHandshake(secretBuf, protoTag, dcIdx) {
  let init;
  for (;;) {
    init = randomBytes(HANDSHAKE_LEN);
    if (init[0] === 0xef) continue;
    if (init.subarray(4, 8).equals(Buffer.alloc(4))) continue;
    break;
  }
  protoTag.copy(init, 56);
  init.writeInt16LE(dcIdx, 60);
  const key = sha256(init.subarray(8, 40), secretBuf);
  const stream = createAesCtr(key, init.subarray(40, 56));
  const encrypted = stream.encrypt(init);
  const handshake = Buffer.concat([init.subarray(0, 56), encrypted.subarray(56, HANDSHAKE_LEN)]);
  const reversed = Buffer.from(init.subarray(8, 56)).reverse();
  const encKey = sha256(reversed.subarray(0, 32), secretBuf);
  const encIv = reversed.subarray(32, 48);
  return { handshake, stream, encKey, encIv };
}

function wrapTlsRecord(data) {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(data.length, 0);
  return Buffer.concat([Buffer.from([0x17, 0x03, 0x03]), len, data]);
}

function buildFakeTlsClientHello(secretBuf, obfsHandshake) {
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
    Buffer.alloc(32),
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

  const DIGEST_POS = 11;
  const DIGEST_LEN = 32;
  const msg = Buffer.concat([
    hello.subarray(0, DIGEST_POS),
    Buffer.alloc(DIGEST_LEN),
    hello.subarray(DIGEST_POS + DIGEST_LEN),
  ]);
  const computed = createHmac("sha256", secretBuf).update(msg).digest();
  const digest = Buffer.alloc(DIGEST_LEN);
  for (let i = 0; i < DIGEST_LEN; i++) {
    digest[i] = computed[i] ^ (i < DIGEST_LEN - 4 ? 0 : tsBytes[i - (DIGEST_LEN - 4)]);
  }
  hello = Buffer.concat([hello.subarray(0, DIGEST_POS), digest, hello.subarray(DIGEST_POS + DIGEST_LEN)]);
  return { hello, sessionId, digest };
}
// END_BLOCK_MT_CLIENT

// START_BLOCK_CHECK_OBFS2
async function checkObfs2() {
  if (!/^[0-9a-f]{32}$/.test(secret)) {
    report("obfs2-relay", false, "no secret (set --secret or MTPROTO_SECRET)");
    return;
  }
  const secretBuf = Buffer.from(secret, "hex");
  const { handshake, stream } = buildClientHandshake(secretBuf, PROTO_TAG_ABRIDGED, 2);
  const out = await connectOnce(
    (s) => s.write(Buffer.concat([handshake, stream.encrypt(Buffer.from("live-smoke-probe"))])),
    null,
    null,
    RELAY_PROBE_MS + 2000
  );
  // Relay accepted = connection stays open through the probe window (no close/error).
  report("obfs2-relay", out === "timeout", out);
}
// END_BLOCK_CHECK_OBFS2

// START_BLOCK_CHECK_FAKETLS
async function checkFakeTls() {
  if (!/^[0-9a-f]{32}$/.test(secret)) {
    report("faketls-serverhello", false, "no secret (set --secret or MTPROTO_SECRET)");
    return;
  }
  const secretBuf = Buffer.from(secret, "hex");
  const { handshake: obfsHandshake, stream } = buildClientHandshake(secretBuf, PROTO_TAG_ABRIDGED, 2);
  const { hello: tlsHello } = buildFakeTlsClientHello(secretBuf, obfsHandshake);
  const sent = stream.encrypt(Buffer.from("live-faketls-probe"));

  const out = await new Promise((resolve) => {
    const s = net.connect(port, host, () => {
      s.write(Buffer.concat([tlsHello, wrapTlsRecord(obfsHandshake), wrapTlsRecord(sent)]));
    });
    let rawBuf = Buffer.alloc(0);
    let sawServerHello = false;
    let phase = "consume";
    const timer = setTimeout(() => {
      s.destroy();
      resolve(sawServerHello ? "serverhello" : "timeout-no-serverhello");
    }, RELAY_PROBE_MS + 2000);
    s.on("data", (d) => {
      rawBuf = Buffer.concat([rawBuf, d]);
      if (phase === "consume") {
        while (rawBuf.length >= 5) {
          const recLen = rawBuf.readUInt16BE(3);
          if (rawBuf.length < 5 + recLen) break;
          const recType = rawBuf[0];
          if (recType === 0x16) sawServerHello = true;
          if (recType === 0x17) { phase = "app"; break; }
          rawBuf = rawBuf.subarray(5 + recLen);
        }
      }
    });
    s.on("error", () => {});
    s.on("close", () => {
      clearTimeout(timer);
      resolve(sawServerHello ? "serverhello" : "closed-no-serverhello");
    });
  });
  report("faketls-serverhello", out === "serverhello", out);
}
// END_BLOCK_CHECK_FAKETLS

// START_BLOCK_ISP_DIAG
// Telegram DC addresses, identical to src/mtproto.js getDcAddressCandidates tables — the
// diagnostics must probe exactly what the deployed proxy itself dials.
const TELEGRAM_DCS_V4 = [
  "149.154.175.50",
  "149.154.167.51",
  "149.154.175.100",
  "149.154.167.91",
  "149.154.171.5",
];
const TELEGRAM_DCS_V6 = [
  "2001:b28:f23d:f001::a",
  "2001:b28:f23f:f002::a",
  "2001:b28:f23d:f003::a",
  "2001:b28:f23f:f004::a",
  "2001:b28:f23f:f005::a",
];
const DC_PORT = 443;
const DC_PROBE_TIMEOUT_MS = 3000;
const HANDSHAKE_SERIES = 5;
const HANDSHAKE_TIMEOUT_MS = 5000;

function timedTcpConnect(hostAddr, portAddr, timeoutMs = DC_PROBE_TIMEOUT_MS) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const s = net.connect({ host: hostAddr, port: portAddr });
    let settled = false;
    const done = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      s.destroy();
      resolve(r);
    };
    const timer = setTimeout(() => done({ ok: false, ms: null, err: "timeout" }), timeoutMs);
    s.once("connect", () => done({ ok: true, ms: Math.round(performance.now() - t0) }));
    s.once("error", (e) => done({ ok: false, ms: null, err: e.code || e.message }));
  });
}

async function checkDcReach() {
  console.log("\n--- ISP diag: Telegram DC reachability from this machine ---");
  let v4ok = 0;
  for (let i = 0; i < TELEGRAM_DCS_V4.length; i++) {
    const r = await timedTcpConnect(TELEGRAM_DCS_V4[i], DC_PORT);
    if (r.ok) v4ok += 1;
    info(`dc${i + 1}-ipv4`, r.ok ? `${r.ms}ms` : `BLOCKED/UNREACHABLE (${r.err})`);
  }
  let v6ok = 0;
  let v6tested = 0;
  for (let i = 0; i < TELEGRAM_DCS_V6.length; i++) {
    const r = await timedTcpConnect(TELEGRAM_DCS_V6[i], DC_PORT);
    if (r.err === "timeout") {
      v6tested += 1;
      info(`dc${i + 1}-ipv6`, "BLOCKED/UNREACHABLE (timeout)");
    } else if (r.ok) {
      v6tested += 1;
      v6ok += 1;
      info(`dc${i + 1}-ipv6`, `${r.ms}ms`);
    } else {
      // ENETUNREACH / EADDRNOTAVAIL / DNS-less IPv6 stack: no verdict, just note it.
      info(`dc${i + 1}-ipv6`, `not tested (${r.err})`);
    }
  }
  if (v4ok === 0) {
    info("dc-reach-verdict", "no direct IPv4 route to Telegram DCs — expect degraded/no DIRECT Telegram; proxy relay path is server-side and unaffected");
  } else if (v6tested > 0 && v6ok === 0) {
    info("dc-reach-verdict", "IPv6 to Telegram DCs fully blocked — keep MTPROTO_PREFER_IPV6=false on the SERVER");
  } else {
    info("dc-reach-verdict", `direct reachability ok (v4 ${v4ok}/5${v6tested > 0 ? `, v6 ${v6ok}/${v6tested}` : ""})`);
  }
}

async function checkHandshakeTiming() {
  if (!/^[0-9a-f]{32}$/.test(secret)) {
    info("handshake-timing", "skipped (no --secret / MTPROTO_SECRET)");
    return;
  }
  console.log("\n--- ISP diag: fake-TLS handshake series vs proxy ---");
  const secretBuf = Buffer.from(secret, "hex");
  const samples = [];
  let failures = 0;
  let resets = 0;
  for (let i = 0; i < HANDSHAKE_SERIES; i++) {
    const { handshake: obfsHandshake } = buildClientHandshake(secretBuf, PROTO_TAG_ABRIDGED, 2);
    const { hello: tlsHello } = buildFakeTlsClientHello(secretBuf, obfsHandshake);
    const r = await new Promise((resolve) => {
      const t0 = performance.now();
      const s = net.connect(port, host, () => s.write(tlsHello));
      let tTcp = null;
      let settled = false;
      const finish = (val) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        s.destroy();
        resolve(val);
      };
      const timer = setTimeout(() => finish({ err: "timeout" }), HANDSHAKE_TIMEOUT_MS);
      s.once("connect", () => { tTcp = Math.round(performance.now() - t0); });
      s.on("data", (d) => {
        // ServerHello = first TLS record type 0x16 from the proxy.
        if (d[0] === 0x16) {
          finish({ tTcp, tSh: Math.round(performance.now() - t0) });
        }
      });
      s.once("error", (e) => finish({ err: e.code === "ECONNRESET" ? "reset" : "error:" + e.code }));
      s.once("close", () => finish({ err: "closed-no-serverhello" }));
    });
    if (r.tSh != null) samples.push(r);
    else {
      failures += 1;
      if (r.err === "reset") resets += 1;
      info(`handshake#${i + 1}`, `FAILED (${r.err})`);
    }
  }
  if (samples.length === 0) {
    info("handshake-timing", `all ${HANDSHAKE_SERIES} handshakes failed — proxy unreachable or DPI kills the flight`);
    return;
  }
  const tcp = samples.map((s) => s.tTcp).sort((a, b) => a - b);
  const sh = samples.map((s) => s.tSh).sort((a, b) => a - b);
  const p50 = (arr) => arr[Math.floor(arr.length / 2)];
  info(
    "handshake-timing",
    `${samples.length}/${HANDSHAKE_SERIES} ok | tcp min/p50/max ${tcp[0]}/${p50(tcp)}/${tcp[tcp.length - 1]}ms` +
      ` | serverhello p50/max ${p50(sh)}/${sh[sh.length - 1]}ms`
  );
  if (resets > 0) {
    info("isp-verdict", `${resets} connection reset(s) mid-handshake — typical sign of active DPI interference on this ISP leg`);
  } else if (failures > 0) {
    info("isp-verdict", `${failures} handshake(s) timed out without reset — possible throttling or packet loss on client↔proxy leg`);
  } else if (p50(sh) > 1500) {
    info("isp-verdict", `serverhello p50 ${p50(sh)}ms is high (>1.5s) — likely throttling despite success`);
  } else {
    info("isp-verdict", "handshake latency healthy; ISP leg looks clean");
  }
}
// END_BLOCK_ISP_DIAG

// START_BLOCK_MAIN
await checkTcp();
await checkConnectTelegram();
await checkConnectDenied();
await checkPlainHttp();
await checkPlainMtReject();
await checkMask();
await checkObfs2();
await checkFakeTls();
if (ispDiag) {
  await checkDcReach();
  await checkHandshakeTiming();
}

const passed = results.filter(Boolean).length;
console.log(`\n${passed}/${results.length} checks passed`);
process.exit(results.every(Boolean) ? 0 : 1);
// END_BLOCK_MAIN
