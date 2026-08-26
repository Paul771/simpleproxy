// FILE: src/tls-profile.js
// VERSION: 1.1.0
// START_MODULE_CONTRACT
//   PURPOSE: Capture a real TLS server-flight profile from a fronted domain and replay its structure
//   SCOPE: raw TCP TLS-1.3 capture (ClientHello build, record observer), profile cache + periodic refresh
//   DEPENDS: node:net, node:crypto
//   LINKS: M-TLS-PROFILE
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   buildCaptureClientHello - build a TLS 1.3 ClientHello to probe an origin server flight
//   captureTlsProfile - connect to an origin, capture the server-flight record structure
//   createProfileManager - cached profile with periodic refresh
//   createTlsRecordObserver - stateful raw TLS record observer (type + size of every record)
// END_MODULE_MAP

// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.1.0 - FIX capture ClientHello: (1) key_share extension was missing the
//                2-byte KeyShareClientHello vector length (RFC 8446 section 4.2.8);
//                (2) supported_groups used extension type 0x002a (early_data!) instead of
//                0x000a. Together these made every probe hello structurally invalid — all
//                origins answered fatal alerts and captureTlsProfile never captured anything.
// END_CHANGE_SUMMARY

import net from "node:net";
import { randomBytes } from "node:crypto";

const TLS_REC_HDR = 5; // type(1) + version(2) + length(2)
const TYPE_HANDSHAKE = 0x16;
const TYPE_CCS = 0x14;
const TYPE_APPDATA = 0x17;
const TYPE_ALERT = 0x15;
const HANDSHAKE_SERVER_HELLO = 0x02;
const QUIET_READ_MS = 600; // no-new-byetes gap that ends the first-flight capture

// Real-browser-grade ClientHello TEMPLATE (captured from a live TLS 1.3 stack, rutube.ru SNI,
// ALPN h2/http-1.1). Hand-assembling extensions proved fragile (two structural bugs shipped
// unnoticed — see CHANGE_SUMMARY), so the probe now clones this known-valid hello and swaps
// only SNI + fresh randomness. Base64 of 1604 bytes; fields: ver(2) random(32) sidlen(1)
// sid(32) ciphers comp exts.
const CHLO_TEMPLATE_B64 =
  "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" +
  "s887KQHSvy4=";

// START_CONTRACT: buildCaptureClientHello
//   PURPOSE: Build a TLS 1.3 ClientHello to probe an origin's server flight (no crypto needed)
//   INPUTS: { host: string - SNI hostname, alpn?: string[] - optional ALPN offer }
//   OUTPUTS: { Buffer - a full TLS record containing a ClientHello handshake message }
//   SIDE_EFFECTS: none
//   LINKS: M-TLS-PROFILE
// END_CONTRACT: buildCaptureClientHello
export function buildCaptureClientHello(host, alpn = ["h2", "http/1.1"]) {
  // START_BLOCK_CHLO
  const tpl = parseHello(Buffer.from(CHLO_TEMPLATE_B64, "base64"));

  // Fresh randomness per probe: the template's random/session-id must not repeat across
  // captures (servers and DPI correlate reused handshake material).
  const head = Buffer.from(tpl.head);
  randomBytes(32).copy(head, 2); // legacy_version(2) -> random(32)
  randomBytes(32).copy(head, 35); // sidlen byte at 34 stays 0x20, sid bytes 35..66
  head[34] = 32;

  let exts = tpl.exts;
  if (host) {
    const sniExt = buildSniExtension(host); // [0000][len16][data]
    const entry = { t: 0x0000, data: sniExt.subarray(4) };
    exts = [entry, ...tpl.exts.filter((e) => e.t !== 0x0000)];
  }
  // ALPN is already h2/http-1.1 in the template; a custom offer would need re-encoding,
  // which no caller uses — ignore the parameter beyond API compatibility.
  void alpn;

  return rebuildHello(head, exts);
  // END_BLOCK_CHLO
}

// Parse a full ClientHello RECORD into { head: hs-payload-before-exts, exts: [{t,data}] }.
// Round-trip verified against real stack captures (rebuild(parse(x)) === x).
function parseHello(rec) {
  let o = 9; // record hdr(5) + hs type(1) + hs len(3)
  o += 2 + 32; // legacy_version + random
  o += 1 + rec[o]; // session id
  o += 2 + rec.readUInt16BE(o); // cipher suites
  o += 1 + rec[o]; // compression methods
  const extTotal = rec.readUInt16BE(o);
  o += 2;
  const head = rec.subarray(9, o - 2); // payload prefix WITHOUT the ext_total field
  const end = o + extTotal;
  const exts = [];
  while (o + 4 <= end) {
    const t = rec.readUInt16BE(o);
    const l = rec.readUInt16BE(o + 2);
    exts.push({ t, data: rec.subarray(o + 4, o + 4 + l) });
    o += 4 + l;
  }
  return { head, exts };
}

function rebuildHello(hsHead, exts) {
  const body = Buffer.concat(exts.map((e) => Buffer.concat([len16(e.t), len16(e.data.length), e.data])));
  const inner = Buffer.concat([hsHead, len16(body.length), body]);
  return wrapHandshakeRecord(0x01, inner);
}

function buildSniExtension(host) {
  const name = Buffer.from(host, "latin1");
  const snEntry = Buffer.concat([Buffer.from([0x00]), len16(name.length), name]);
  const list = Buffer.concat([len16(snEntry.length), snEntry]);
  return Buffer.concat([Buffer.from([0x00, 0x00]), len16(list.length), list]);
}

function len16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n, 0);
  return b;
}

function wrapHandshakeRecord(hsType, inner) {
  const hsLen = Buffer.alloc(3);
  hsLen.writeUIntBE(inner.length, 0, 3);
  const hsMsg = Buffer.concat([Buffer.from([hsType]), hsLen, inner]);
  const recLen = Buffer.alloc(2);
  recLen.writeUInt16BE(hsMsg.length, 0);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), recLen, hsMsg]);
}

// START_CONTRACT: createTlsRecordObserver
//   PURPOSE: Stateful raw TLS record observer: records type + length of every record seen
//   INPUTS: { none } -> { feed(chunk: Buffer): { type, length }[] }
//   OUTPUTS: { { feed } - returns array of { type, length } for each fully-seen record }
//   SIDE_EFFECTS: maintains internal buffer/state
//   LINKS: M-TLS-PROFILE
// END_CONTRACT: createTlsRecordObserver
export function createTlsRecordObserver() {
  // START_BLOCK_OBSERVER
  let buf = Buffer.alloc(0);
  return {
    feed(chunk) {
      buf = Buffer.concat([buf, chunk]);
      const out = [];
      for (;;) {
        if (buf.length < TLS_REC_HDR) break;
        const type = buf[0];
        const length = buf.readUInt16BE(3);
        if (buf.length < TLS_REC_HDR + length) break;
        out.push({ type, length });
        buf = buf.subarray(TLS_REC_HDR + length);
      }
      return out;
    },
  };
  // END_BLOCK_OBSERVER
}

// Parse the ServerHello handshake message (inside a 0x16 record body) for cipher + ALPN.
function parseServerHello(recordBody) {
  // recordBody = handshake header (type 0x02 + 3-byte len) + ServerHello fields.
  if (recordBody.length < 4 + 2 + 32 + 1) return null;
  if (recordBody[0] !== HANDSHAKE_SERVER_HELLO) return null;
  let off = 4; // skip handshake header
  off += 2; // legacy_version
  off += 32; // random
  const sidLen = recordBody[off];
  off += 1 + sidLen;
  const cipher = Buffer.from(recordBody.subarray(off, off + 2));
  off += 2;
  off += 1; // legacy_compression_methods
  const extLen = recordBody.readUInt16BE(off);
  off += 2;
  const extEnd = off + extLen;
  let alpn = null;
  while (off + 4 <= extEnd) {
    const extType = recordBody.readUInt16BE(off);
    const eLen = recordBody.readUInt16BE(off + 2);
    off += 4;
    if (extType === 0x0010) {
      // ALPN: listLen(2) + protoLen(1) + proto
      const listLen = recordBody.readUInt16BE(off);
      let p = off + 2;
      if (p + 1 <= off + listLen) {
        const protoLen = recordBody[p];
        alpn = recordBody.subarray(p + 1, p + 1 + protoLen).toString("latin1");
      }
    }
    off += eLen;
  }
  return { cipher, alpn };
}

// START_CONTRACT: captureTlsProfile
//   PURPOSE: Connect to an origin, probe it with a TLS 1.3 ClientHello, capture the server-flight shape
//   INPUTS: { host: string, port: number, timeoutMs?: number, log?: Log }
//   OUTPUTS: { Profile | null - { host, capturedAt, cipher, alpn, ccsCount, appDataSizes, ticketSizes, certLen } }
//   SIDE_EFFECTS: opens a TCP connection; reads bytes; closes it
//   LINKS: M-TLS-PROFILE
// END_CONTRACT: captureTlsProfile
export async function captureTlsProfile(host, port, { timeoutMs = 5000, log } = {}) {
  // START_BLOCK_CAPTURE
  return new Promise((resolve) => {
    let settled = false;
    const finish = (profile) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      clearInterval(quietTimer);
      socket.destroy();
      resolve(profile);
    };

    const socket = net.connect({ host, port });
    const observer = createTlsRecordObserver();
    const records = []; // { type, length } in arrival order
    let serverHelloParsed = null;

    const hardTimer = setTimeout(() => finish(buildProfile(host, serverHelloParsed, records)), timeoutMs);
    if (typeof hardTimer.unref === "function") hardTimer.unref();
    // Quiet-period: when no new records arrive for QUIET_READ_MS after the first app-data, we have the flight.
    let lastRecordAt = 0;
    const quietTimer = setInterval(() => {
      if (records.length > 0 && lastRecordAt > 0 && Date.now() - lastRecordAt >= QUIET_READ_MS) {
        finish(buildProfile(host, serverHelloParsed, records));
      }
    }, 150);
    if (typeof quietTimer.unref === "function") quietTimer.unref();

    socket.once("connect", () => {
      socket.write(buildCaptureClientHello(host));
    });

    socket.on("data", (chunk) => {
      for (const rec of observer.feed(chunk)) {
        records.push({ ...rec, ts: Date.now() });
        lastRecordAt = Date.now();
        if (rec.type === TYPE_HANDSHAKE && serverHelloParsed === null) {
          // record body starts after the 5-byte record header; the observer gives us length only,
          // so we re-slice from the observer's internal buffer is not possible. Re-parse via a
          // dedicated small parse using a second pass: keep the last handshake record body.
          serverHelloParsed = tryParseServerHelloFromFeed(chunk, rec);
        }
        if (rec.type === TYPE_ALERT) finish(buildProfile(host, serverHelloParsed, records));
      }
    });

    socket.once("error", () => finish(null));
    socket.once("close", () => finish(buildProfile(host, serverHelloParsed, records)));
  });
  // END_BLOCK_CAPTURE
}

// Best-effort: parse the ServerHello out of the most recent feed chunk that contained a 0x16 record.
function tryParseServerHelloFromFeed(chunk, rec) {
  if (rec.type !== TYPE_HANDSHAKE) return null;
  // The record may not be fully contained in this single chunk; find the 0x16 0x03 0x03 header.
  const idx = chunk.indexOf(Buffer.from([0x16, 0x03, 0x03]), 0);
  if (idx === -1) return null;
  const bodyStart = idx + TLS_REC_HDR;
  const body = chunk.subarray(bodyStart, bodyStart + rec.length);
  if (body.length < rec.length) return null; // incomplete in this chunk
  return parseServerHello(body);
}

function buildProfile(host, serverHelloParsed, records) {
  if (!records || records.length === 0) return null;
  let cipher = null;
  let alpn = null;
  if (serverHelloParsed) {
    cipher = serverHelloParsed.cipher;
    alpn = serverHelloParsed.alpn;
  }
  let ccsCount = 0;
  const appDataSizes = [];
  for (const r of records) {
    if (r.type === TYPE_CCS) ccsCount++;
    else if (r.type === TYPE_APPDATA) appDataSizes.push(r.length);
  }
  if (appDataSizes.length === 0) return null;
  // Heuristic: the largest 0x17 record in the first flight is usually the Certificate.
  const certLen = appDataSizes.reduce((a, b) => (b > a ? b : a), 0);
  // Trailing 0x17 records after the bulk are likely NewSessionTicket(s).
  const ticketSizes = appDataSizes.slice(-1)[0] < certLen / 2 ? appDataSizes.slice(-1) : [];
  // Inter-arrival delays between consecutive records in the first flight (ms), for doppelganger.
  const recordDelays = [];
  for (let i = 1; i < records.length; i++) {
    recordDelays.push(records[i].ts - records[i - 1].ts);
  }
  return {
    host,
    capturedAt: Date.now(),
    cipher,
    alpn,
    ccsCount,
    appDataSizes,
    ticketSizes,
    certLen,
    recordDelays,
  };
}

// START_CONTRACT: createProfileManager
//   PURPOSE: Cache a captured profile and refresh it on a timer
//   INPUTS: { host, port, refreshMs, timeoutMs, log }
//   OUTPUTS: { get(): Profile | null, start(): void, stop(): void, refresh(): Promise<void> }
//   SIDE_EFFECTS: schedules an unref'd refresh interval; performs outbound TCP captures
//   LINKS: M-TLS-PROFILE
// END_CONTRACT: createProfileManager
export function createProfileManager({ host, port = 443, refreshMs = 600_000, timeoutMs = 5000, log } = {}) {
  // START_BLOCK_MANAGER
  let profile = null;
  let timer = null;
  let inFlight = false;

  const refresh = async () => {
    if (inFlight) return;
    inFlight = true;
    try {
      const captured = await captureTlsProfile(host, port, { timeoutMs, log });
      if (captured) {
        profile = captured;
        log?.("tls_profile", "DF-TLS-PROFILE", host, {
          cipher: captured.cipher?.toString("hex"),
          alpn: captured.alpn,
          ccsCount: captured.ccsCount,
          appDataRecords: captured.appDataSizes.length,
        });
      } else {
        log?.("tls_profile", "DF-TLS-PROFILE", host, { status: "failed" });
      }
    } finally {
      inFlight = false;
    }
  };

  const start = () => {
    refresh();
    timer = setInterval(() => refresh(), refreshMs);
    if (typeof timer.unref === "function") timer.unref();
  };

  const stop = () => {
    if (timer !== null) clearInterval(timer);
    timer = null;
  };

  return { get: () => profile, start, stop, refresh };
  // END_BLOCK_MANAGER
}