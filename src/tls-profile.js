// FILE: src/tls-profile.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Capture a real TLS server-flight profile from a fronted domain and replay its structure
//   SCOPE: raw TCP TLS-1.3 capture (ClientHello build, record observer), profile cache + periodic refresh
//   DEPENDS: node:net, node:crypto, M-FAKETLS (genX25519PublicKey, buildAlpnExtension)
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

import net from "node:net";
import { randomBytes } from "node:crypto";
import { genX25519PublicKey, buildAlpnExtension } from "./faketls.js";

const TLS_REC_HDR = 5; // type(1) + version(2) + length(2)
const TYPE_HANDSHAKE = 0x16;
const TYPE_CCS = 0x14;
const TYPE_APPDATA = 0x17;
const TYPE_ALERT = 0x15;
const HANDSHAKE_SERVER_HELLO = 0x02;
const QUIET_READ_MS = 600; // no-new-byetes gap that ends the first-flight capture

// TLS 1.3 cipher suites we advertise in the probe ClientHello.
const CIPHERS = Buffer.from([
  0x00, 0x08, // 4 suites * 2 bytes
  0x13, 0x01, // TLS_AES_128_GCM_SHA256
  0x13, 0x02, // TLS_AES_256_GCM_SHA384
  0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
  0x13, 0x04, // TLS_AES_128_CCM_SHA256
]);

// START_CONTRACT: buildCaptureClientHello
//   PURPOSE: Build a TLS 1.3 ClientHello to probe an origin's server flight (no crypto needed)
//   INPUTS: { host: string - SNI hostname, alpn?: string[] - optional ALPN offer }
//   OUTPUTS: { Buffer - a full TLS record containing a ClientHello handshake message }
//   SIDE_EFFECTS: none
//   LINKS: M-TLS-PROFILE
// END_CONTRACT: buildCaptureClientHello
export function buildCaptureClientHello(host, alpn = ["h2", "http/1.1"]) {
  // START_BLOCK_CHLO
  const random = randomBytes(32);
  const sessionId = Buffer.alloc(32); // TLS 1.3 legacy_session_id
  const compression = Buffer.from([0x01, 0x00]); // legacy_compression_methods: null

  // Extensions: SNI, supported_versions (TLS 1.3), key_share (x25519), signature_algorithms,
  // supported_groups, ALPN, padding.
  const exts = [];
  exts.push(buildSniExtension(host));
  exts.push(Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])); // supported_versions = TLS 1.3
  const x25519 = genX25519PublicKey();
  exts.push(Buffer.concat([Buffer.from([0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]), x25519])); // key_share x25519
  exts.push(Buffer.from([0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01])); // signature_algorithms
  exts.push(Buffer.from([0x00, 0x2a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d])); // supported_groups: x25519
  if (alpn && alpn.length > 0) exts.push(buildAlpnExtension(alpn));

  const extBuf = Buffer.concat(exts);
  const extTotal = Buffer.alloc(2);
  extTotal.writeUInt16BE(extBuf.length, 0);

  const inner = Buffer.concat([
    Buffer.from([0x03, 0x03]), // legacy_version = TLS 1.2
    random,
    Buffer.from([sessionId.length]),
    sessionId,
    CIPHERS,
    compression,
    extTotal,
    extBuf,
  ]);

  // Pad to >= 512 bytes (some origins/DPI treat tiny ClientHellos as non-TLS).
  const target = 515;
  if (inner.length < target) {
    const padLen = target - inner.length;
    const padExt = Buffer.concat([Buffer.from([0x00, 0x15]), Buffer.alloc(2), Buffer.alloc(padLen)]);
    padExt.writeUInt16BE(padLen, 2);
    // Re-build extensions list length to include the padding extension.
    const extBuf2 = Buffer.concat([extBuf, padExt]);
    extTotal.writeUInt16BE(extBuf2.length, 0);
    const inner2 = Buffer.concat([
      Buffer.from([0x03, 0x03]),
      random,
      Buffer.from([sessionId.length]),
      sessionId,
      CIPHERS,
      compression,
      extTotal,
      extBuf2,
    ]);
    return wrapHandshakeRecord(0x01, inner2);
  }
  return wrapHandshakeRecord(0x01, inner);
  // END_BLOCK_CHLO
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
        records.push(rec);
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
  return {
    host,
    capturedAt: Date.now(),
    cipher,
    alpn,
    ccsCount,
    appDataSizes,
    ticketSizes,
    certLen,
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