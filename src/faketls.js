// FILE: src/faketls.js
// VERSION: 1.9.0
// START_MODULE_CONTRACT
//   PURPOSE: Fake-TLS (ee-secret) handshake validation, ServerHello construction, TLS record framing
//   SCOPE: ClientHello HMAC validation, fake ServerHello build, TLS 1.3 record read/write helpers,
//          ClientHello extent resolution (declared lengths, else ClientHello structure), and
//          HMAC-gated admission that picks the extent to answer from
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
//   extractSni - parse the SNI hostname from a TLS ClientHello (null if absent)
//   buildTlsAlert - build a TLS alert record (used for reject_handshake mode)
//   splitTlsRecords - split a byte stream into individual TLS records (doppelganger timing replay)
//   resolveClientHelloEnd - resolve where the ClientHello ends (0 = need more bytes), trusting the
//                           handshake-message length over an overstated TLS record length, then the
//                           ClientHello's own structure when both declared lengths overstate
//   resolveClientHelloStructuralEnd - resolve the ClientHello end by walking its TLS structure,
//                           ignoring the declared record/handshake length fields entirely
//   walkClientHelloLayout - walk those length-prefixed fields and REPORT where the walk stopped and
//                           the extensions offset the client declares, instead of collapsing every
//                           failure to the same 0
//   resolveFakeTlsClientHello - resolve AND authenticate a ClientHello: try the declared/structural
//                           extent, then the whole record, then everything received, admitting only
//                           the extent the client's HMAC confirms; reports resolved/foreign/incomplete
//   resolveFakeCertLen - fake-certificate length for the server flight (captured size, capped)
//   extractAlpn - first ALPN protocol the client offered (null when the extension is absent)
//   extractAlpnList - every ALPN protocol the client offered, in its own preference order
//   resolveReplayAlpn - which protocol the fake ServerHello must carry: replay the profile's,
//                       answer the client if it offered, mirror the origin's silence otherwise
//   resolveServerCipher - the cipher suite the ServerHello actually selects (profile.cipher only
//                          when offered; accepts Buffer / byte Array / hex string)
// END_MODULE_MAP

// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.9.0 - the fake ServerHello must ANSWER a client that offered ALPN, even when the
//                captured profile recorded that the origin negotiated none. alpnKnown=true made
//                buildServerHello omit the extension so the flight matches the fronted site, and a
//                client that sent ALPN and got silence aborted its MTProto stream. The proxy still
//                logged a successful fake-TLS handshake, so the failure surfaced much later and
//                looked like a network problem: we forwarded the client's bytes and the DC answered
//                nothing at all (bytes_out: 0, dc_replies: 0, first_dc_reply_ms: null). That is the
//                production signature this removes. RFC 7301 makes the answer mandatory anyway, so
//                origin fidelity now yields to a question the client actually asked — and only to
//                that: a client that offered nothing still gets the bare origin-shaped flight.
//                resolveReplayAlpn owns the rule and is exported so mtproto-server derives
//                `alpn_sent` from the SAME function the flight used; the log previously re-derived
//                it inline, which is precisely the drift that made this invisible.
//                extractAlpnList replaces the single-value extractAlpn internally: choosing between
//                the configured protocol and the client's own first preference needs the whole list.
//   PREVIOUS: v1.8.0 - walkClientHelloLayout: the structural walk returned 0 for every failure
//                alike, which is correct for a decision and useless for a diagnosis. The journal
//                could not tell "the extensions block has not landed yet" from "the extensions length
//                is a lie too", and those two support opposite conclusions about whether more bytes
//                would ever help — the exact ambiguity that left the 1298-byte client unexplained
//                across two deployed fixes. The walk now returns where it stopped (`why`) plus the
//                extensions offset the client DECLARES (`extEnd`); extEnd > bytes is the decisive
//                pair. resolveClientHelloStructuralEnd became a thin caller, pinned by a test to the
//                same extents it answered before, so a diagnostic refactor cannot quietly change
//                admission.
//   PREVIOUS: v1.7.0 - resolveFakeTlsClientHello: the 1298-byte client that survived v1.5.0's
//                structural fallback. That fix trusted the ClientHello's own length-prefixed fields,
//                but production showed a client inflating the INNERMOST one too — the extensions
//                block total — so the walk had nothing left to trust, resolveClientHelloEnd
//                correctly returned 0, and the client still got no ServerHello: bytes:1298,
//                recordLen/hsLen ~1784/1780, flight_bytes: 0, closed: false (it was alive, holding
//                the socket open, waiting). The remaining candidate with no declared length to
//                overstate is "everything received so far", and the client's own HMAC is what makes
//                it safe rather than a guess: a genuinely fragmented hello cannot produce a matching
//                signature, so it keeps waiting. Resolution is now ONE function that both finds and
//                authenticates the extent, instead of the server hand-rolling a second framing
//                retry inline, so the "keep reading" vs "mask this crawler" decision has a single
//                named owner — the mistake that first draft made was offering the received-extent
//                candidate even when a declared framing already existed, which swallowed the app
//                data a pipelining client sent in the same segment and turned every ordinary
//                wrong-secret connection into one held to the handshake timeout.
//   PREVIOUS: v1.6.0 - two parsers the journal needed and the code did not have. extractAlpn
//                returns the first ALPN protocol a ClientHello offered: when a captured profile
//                recorded no ALPN (alpnKnown=true) buildServerHello OMITS the extension to match the
//                fronted origin, so "client offered ALPN and we sent none" was indistinguishable
//                from "client offered nothing" — and a strict client aborting right after
//                ServerHello is exactly the production signature. locateExtensions factors out the
//                length-prefixed field walk that extractSni already did, so both share one parser
//                instead of two copies that can drift.
//                resolveServerCipher externalises the RFC 8446 offered-suite gate that buildServerHello
//                applied inline, so the journal can report the suite that REALLY went on the wire
//                rather than the captured profile value — which is frequently not what was sent.
//                It also fixes a latent trap: Buffer.from("1302") on a hex STRING yields 4 UTF-8
//                bytes that can never equal a 2-byte suite, so any hex-valued profile (which is how
//                every serialized form renders it) would have degraded to the default forever,
//                silently. Buffer, byte Array and hex string are all accepted now.
//   PREVIOUS: v1.5.0 - resolveClientHelloStructuralEnd: the v1.3.0 fallback only covered a TLS
//                record length that overstated while the handshake-message length stayed
//                accurate. Production showed the harder variant: 1298 bytes arrived while
//                recordLen AND hsLen agreed with each other (recordEnd == messageEnd) and both
//                described a ~1789-byte hello, so neither declared extent was reachable, the
//                client was never answered (flight_bytes: 0 on all 22 attempts in a 110-minute
//                window, both directions silent, every retry doomed), and 85% of that window's
//                connection attempts died this way. resolveClientHelloEnd now falls back to the
//                ClientHello's own length-prefixed structure — session_id, cipher_suites,
//                               compression_methods, extensions — whose fields describe what the
//                               client really wrote. Safe because acceptance stays gated on the
//                               HMAC in validateClientHello: the extent is confirmed by the client's
//                               own signature over exactly those bytes, never guessed, so a wrong
//                               walk cannot validate and no truncated hello can be answered. An
//                               extensions block that has not fully landed still returns 0.
//   PREVIOUS: v1.4.0 - resolveFakeCertLen(profile, cap): the fake certificate length is
//                resolved once, by the caller, so MTPROTO_FAKE_TLS_CERT_LEN_MAX can shrink the
//                ServerHello flight to fit a path MTU (a mobile link whose MTU is below the
//                captured 4091-byte certificate loses the flight tail and the client hangs in
//                "Connecting"), and the number reported in the journal is exactly what went on
//                the wire. buildServerHello takes the resolved length; cap 0 keeps the captured
//                size, so the default behaviour is unchanged.
//   PREVIOUS: v1.3.0 - resolveClientHelloEnd: the ClientHello extent now comes from the
//                handshake message's own 3-byte length (offset 6) and no longer requires the TLS
//                record length to be satisfiable. Prod 14:43: a client sent the same 1298 bytes on
//                every attempt and sat in phase="tls-hello" until the handshake timeout, because
//                the server waited for a record length the client never delivered — no validation,
//                no ServerHello, endless retries. validateClientHello correspondingly stops
//                treating an overstated record length as a structural failure (it is only a >=512
//                shape gate now); a truncated message still fails the HMAC. An incomplete message
//                still returns 0, so a genuinely fragmented hello keeps waiting.
//   PREVIOUS: v1.2.0 - ALPN fidelity under a captured profile: when the profile's ServerHello
//                was parsed and negotiated NO ALPN (profile.alpnKnown === true, alpn === null),
//                buildServerHello now OMITS the ALPN extension instead of injecting the
//                configured h2. Mirrors the fronted origin (rutube.ru negotiates no ALPN), so the
//                fake server flight stops carrying an ALPN the real host never sends.
//   PREVIOUS: v1.1.0 - FIX ServerHello cipher selection under a captured profile:
//                profile.cipher was replayed unconditionally, but RFC 8446 requires the
//                selected suite to be one the CLIENT offered — clients offering only
//                TLS_AES_128_GCM_SHA256 (0x1301) aborted right after ServerHello once
//                rutube's 0x1302 started being replayed. validateClientHello now extracts
//                the offered cipher suites; buildServerHello uses profile.cipher only when
//                the client offered it, else falls back to the default 0x1301.
// END_CHANGE_SUMMARY

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
// Real Telegram ClientHellos always exceed 512 bytes; anything smaller is not a client hello.
const CLIENT_HELLO_MIN_RECORD = 512;

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
//   INPUTS: { handshake: Buffer - ClientHello from 0x16 onward, framed by resolveClientHelloEnd
//             (the TLS record length is a >=512 shape gate only, never a completeness check),
//             secrets: Buffer[] }
//   OUTPUTS: { { secret, sessionId, digest, digestPrefix, ciphers: Buffer[] } | null -
//              ciphers = suites offered by the client (for profile-replay eligibility) }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-resolveClientHelloEnd
// END_CONTRACT: validateClientHello
export function validateClientHello(handshake, secrets) {
  // START_BLOCK_VALIDATE
  if (handshake.length < SESSION_ID_POS + 1) return null;
  if (handshake[0] !== 0x16 || handshake[1] !== 0x03 || handshake[2] !== 0x01) return null;
  const recordLen = handshake.readUInt16BE(3);
  if (recordLen < CLIENT_HELLO_MIN_RECORD) return null;
  // The record length is only a shape gate here, never a completeness requirement: the caller
  // hands over the ClientHello exactly as resolved by resolveClientHelloEnd (which may trust the
  // handshake-message length when the record length overstates the bytes received). Every field
  // read below is bounds-checked, and a truncated message simply fails the HMAC.
  if (handshake[5] !== 0x01) return null; // ClientHello handshake type

  const digest = handshake.subarray(DIGEST_POS, DIGEST_POS + DIGEST_LEN);
  const sidLen = handshake[SESSION_ID_LEN_POS];
  const sessionId = handshake.subarray(SESSION_ID_POS, SESSION_ID_POS + sidLen);
  if (sessionId.length !== sidLen) return null;

  // Offered cipher suites live right after the session id: len(2) + N*2 bytes. Extracted so
  // buildServerHello may replay a captured profile.cipher only when the client offered it.
  const csOff = SESSION_ID_POS + sidLen;
  if (csOff + 2 > handshake.length) return null;
  const csLen = handshake.readUInt16BE(csOff);
  if (csLen % 2 !== 0 || csOff + 2 + csLen > handshake.length) return null;
  const ciphers = [];
  for (let p = csOff + 2; p + 2 <= csOff + 2 + csLen; p += 2) {
    ciphers.push(handshake.subarray(p, p + 2));
  }

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
      ciphers,
    };
  }
  return null;
  // END_BLOCK_VALIDATE
}

// START_CONTRACT: resolveClientHelloEnd
//   PURPOSE: Resolve the offset at which a fake-TLS ClientHello ends inside the received buffer
//   INPUTS: { buf: Buffer - bytes received from the client, starting at 0x16 0x03 0x01 }
//   OUTPUTS: { number - end offset of the ClientHello, or 0 when more bytes are needed }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, M-MTPROTO-SERVER, fn-resolveClientHelloStructuralEnd
// END_CONTRACT: resolveClientHelloEnd
export function resolveClientHelloEnd(buf) {
  // START_BLOCK_CLIENT_HELLO_EXTENT
  if (buf.length < 5) return 0;
  if (buf[0] !== 0x16 || buf[1] !== 0x03 || buf[2] !== 0x01) return 0;
  const recordEnd = 5 + buf.readUInt16BE(3);
  // Without a parsable ClientHello handshake header the record framing is all there is.
  if (buf.length < 9 || buf[5] !== 0x01) return buf.length >= recordEnd ? recordEnd : 0;
  // The ClientHello handshake message carries its own 3-byte length at offset 6, and that is the
  // extent the HMAC covers. It is authoritative over the TLS record length, which fake-TLS
  // clients do not always fill exactly: a client that declared 64 bytes more than it wrote would
  // otherwise stall in phase="tls-hello" until the handshake timeout, never receiving a
  // ServerHello. An incomplete message still returns 0, so a genuinely fragmented hello keeps
  // waiting instead of being answered from partial bytes.
  const messageEnd = 9 + buf.readUIntBE(6, 3);
  if (messageEnd < 5 + CLIENT_HELLO_MIN_RECORD) {
    return buf.length >= recordEnd ? recordEnd : resolveClientHelloStructuralEnd(buf);
  }
  if (buf.length >= messageEnd) return messageEnd;
  // Both declared lengths can promise more than the client ever writes, and agree with each other
  // while doing it (prod: 1298 bytes received against a record AND handshake length that both
  // described ~1789 bytes, so neither declared extent was reachable). Trusting the structure
  // recovers those clients; the earlier fallback above only covered a record length that
  // overstated while the handshake length stayed accurate, which left these unanswered until the
  // handshake timeout (flight_bytes: 0 on every attempt, no ServerHello ever sent).
  const structural = resolveClientHelloStructuralEnd(buf);
  if (structural !== 0) return structural;
  return 0;
  // END_BLOCK_CLIENT_HELLO_EXTENT
}

// START_CONTRACT: walkClientHelloLayout
//   PURPOSE: Walk a ClientHello's length-prefixed fields and REPORT where the walk stopped and why,
//            instead of collapsing every failure to the same 0
//   INPUTS: { buf: Buffer - bytes received so far, starting at 0x16 0x03 0x01 }
//   OUTPUTS: { { why, sidLen, csLen, extLen, extEnd } - why is one of ok | short_header |
//              not_client_hello | no_handshake_header | short_cipher_suites | odd_cipher_suites_len |
//              short_compression | short_extensions_len | ext_beyond_buffer; extEnd is the offset the
//              client DECLARES the extensions block to end at, which is what distinguishes "still
//              arriving" (extEnd > bytes received) from "the extensions length also lies" }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-resolveClientHelloStructuralEnd, M-MTPROTO-SERVER
// END_CONTRACT: walkClientHelloLayout
export function walkClientHelloLayout(buf) {
  // START_BLOCK_CLIENT_HELLO_LAYOUT
  // Layout after the 9-byte prefix (record header + handshake type + 3-byte handshake length):
  // client_version(2) random(32) session_id_len(1) session_id(N) cipher_suites_len(2) suites(2N)
  // compression_len(1) compression(M) extensions_len(2) extensions(...). Every field is length-
  // prefixed, so the true end is reachable without believing any declared total — which is the
  // whole point: these clients inflate the totals and then send only what they really wrote.
  // `resolveClientHelloStructuralEnd` returns 0 for every one of these failures alike, which is right
  // for a decision but useless for a diagnosis: the journal could not tell "the extensions block has
  // not landed yet" from "the extensions length is a lie too", and those two call for opposite
  // conclusions about whether more bytes would ever help.
  const bail = (why, partial = {}) => ({ why, sidLen: null, csLen: null, extLen: null, extEnd: null, ...partial });
  if (buf.length < 5) return bail("short_header");
  if (buf[0] !== 0x16 || buf[1] !== 0x03 || buf[2] !== 0x01) return bail("not_client_hello");
  if (buf.length < 9 || buf[5] !== 0x01) return bail("no_handshake_header");
  const sidLen = buf[SESSION_ID_LEN_POS];
  let p = SESSION_ID_POS + sidLen;
  if (p + 2 > buf.length) return bail("short_cipher_suites", { sidLen });
  const csLen = buf.readUInt16BE(p);
  if (csLen % 2 !== 0) return bail("odd_cipher_suites_len", { sidLen, csLen });
  p += 2 + csLen;
  if (p + 1 > buf.length) return bail("short_compression", { sidLen, csLen });
  p += 1 + buf[p];
  if (p + 2 > buf.length) return bail("short_extensions_len", { sidLen, csLen });
  const extLen = buf.readUInt16BE(p);
  const extEnd = p + 2 + extLen;
  const info = { sidLen, csLen, extLen, extEnd };
  // Still arriving: the extensions block has not fully landed.
  return { ...info, why: extEnd > buf.length ? "ext_beyond_buffer" : "ok" };
  // END_BLOCK_CLIENT_HELLO_LAYOUT
}

// START_CONTRACT: resolveClientHelloStructuralEnd
//   PURPOSE: Resolve a ClientHello's true end by walking its own TLS structure instead of
//            trusting the declared record/handshake length fields
//   INPUTS: { buf: Buffer - bytes received from the client, starting at 0x16 0x03 0x01 }
//   OUTPUTS: { number - structural end offset, or 0 when the structure is unreadable, still
//              arriving, or too short to be a real ClientHello }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-resolveClientHelloEnd, fn-validateClientHello, fn-walkClientHelloLayout
// END_CONTRACT: resolveClientHelloStructuralEnd
export function resolveClientHelloStructuralEnd(buf) {
  // START_BLOCK_CLIENT_HELLO_STRUCTURE
  const layout = walkClientHelloLayout(buf);
  if (layout.why !== "ok") return 0;
  if (layout.extEnd < 5 + CLIENT_HELLO_MIN_RECORD) return 0;
  return layout.extEnd;
  // END_BLOCK_CLIENT_HELLO_STRUCTURE
}

// START_CONTRACT: resolveFakeTlsClientHello
//   PURPOSE: Resolve AND authenticate a fake-TLS ClientHello from the bytes received so far, trying
//            every plausible extent framing in order and admitting only the one the client's own HMAC
//            confirms
//   INPUTS: { buf: Buffer - bytes received so far, starting at 0x16 0x03 0x01; secrets: Buffer[] }
//   OUTPUTS: { { status: "resolved", helloEnd: number, validated: { secret, sessionId, digest,
//                digestPrefix, ciphers } }
//            | { status: "foreign", helloEnd: number } - a complete-looking hello no secret matched
//            | { status: "incomplete" } }              - no positive evidence yet; keep reading
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, M-MTPROTO-SERVER, fn-resolveClientHelloEnd, fn-validateClientHello
// END_CONTRACT: resolveFakeTlsClientHello
export function resolveFakeTlsClientHello(buf, secrets) {
  // START_BLOCK_CLIENT_HELLO_ADMISSION
  const candidates = [];
  // 1) whatever the declared or structural walk can prove. Zero means it could not: no declared
  //    extent is reachable AND the extensions block is declared longer than has arrived, so not
  //    even the structure agrees with what is on the wire.
  const declared = resolveClientHelloEnd(buf);
  if (declared !== 0) candidates.push(declared);
  // 2) the whole TLS record, for clients that sign the padding their record length promises.
  const recordEnd = buf.length >= 5 ? 5 + buf.readUInt16BE(3) : 0;
  if (recordEnd > 0 && buf.length >= recordEnd && !candidates.includes(recordEnd)) {
    candidates.push(recordEnd);
  }
  // 3) everything received so far — the only candidate with no declared length to overstate. This is
  //    what rescues the client still stalling in production after v1.5.0: it inflates the extensions
  //    block total too, so the structural walk has nothing left to trust and returns 0, yet the
  //    client signed the bytes it really wrote. The HMAC below is what makes that safe — a genuinely
  //    fragmented hello cannot produce a matching signature, so it keeps waiting rather than being
  //    answered from partial data. It is only ever offered when NOTHING else is plausible: when a
  //    declared framing did resolve, adding "everything received" would swallow the app data a
  //    pipelining client sent in the same segment, fail the HMAC, and turn every ordinary
  //    wrong-secret connection into an unanswered one held to the handshake timeout.
  //    Residual: a client that both inflates every length AND pipelines its post-hello records into
  //    the same segment still waits, because its signature covers only the hello. Production does
  //    not do this (bytes:1298, closed:false — the client held the socket open waiting for the
  //    ServerHello rather than sending on), and such a client was unanswered before v1.7.0 too.
  const receivedEnd = buf.length;
  const hasReceivedCandidate =
    candidates.length === 0 && receivedEnd >= 5 + CLIENT_HELLO_MIN_RECORD;
  if (hasReceivedCandidate) candidates.push(receivedEnd);

  for (const helloEnd of candidates) {
    const validated = validateClientHello(buf.subarray(0, helloEnd), secrets);
    if (validated) return { status: "resolved", helloEnd, validated };
  }
  // Nothing confirmed a signature. If the declared/structural walk could not prove an extent, we
  // never had a complete-looking ClientHello and there is no evidence of anything but a client that
  // is still sending — hold the connection and read more. Offering the whole record does NOT count
  // as such evidence: a client whose handshake and extensions lengths overstate still has a
  // reachable record length, and masking it would turn a merely slow client into a dropped one.
  if (declared === 0 || hasReceivedCandidate) return { status: "incomplete" };
  // The walk proved a complete, self-consistent ClientHello and no secret matched it, so this is a
  // crawler or a wrong key rather than a slow client: the caller masks it instead of holding the
  // slot to the timeout.
  return { status: "foreign", helloEnd: candidates[0] };
  // END_BLOCK_CLIENT_HELLO_ADMISSION
}

// START_CONTRACT: resolveFakeCertLen
//   PURPOSE: Resolve the byte length of the fake certificate in the ServerHello flight
//   INPUTS: { profile: { certLen } | null - captured profile, cap: number - 0/absent = no cap }
//   OUTPUTS: { number - fake certificate length in bytes }
//   SIDE_EFFECTS: reads Math.random only when no captured profile supplies certLen
//   LINKS: M-FAKETLS, M-MTPROTO-SERVER
// END_CONTRACT: resolveFakeCertLen
export function resolveFakeCertLen(profile, cap = 0) {
  const base = profile && profile.certLen ? profile.certLen : 1024 + Math.floor(Math.random() * 3072);
  // The captured size mirrors the fronted origin, which on a mobile path with a ~1300-byte MTU can
  // be larger than the whole flight may take; a cap trades that fidelity for reachability.
  return cap > 0 && base > cap ? cap : base;
}

// START_CONTRACT: buildServerHello
//   PURPOSE: Build the fake ServerHello + ChangeCipherSpec + ApplicationData response
//   INPUTS: { secret: Buffer(16), clientDigest: Buffer(32), sessionId: Buffer, alpn?: string,
//             profile?: { cipher, alpn, alpnKnown, ccsCount, appDataSizes, certLen } | null,
//             offeredCiphers?: Buffer[] - suites from validateClientHello (gate profile.cipher),
//             certLen?: number - explicit fake-certificate length; 0/omitted = derive via
//                         resolveFakeCertLen(profile) (callers apply cfg caps themselves),
//             offeredAlpn?: string[] - protocols the client offered (see resolveReplayAlpn) }
//   OUTPUTS: { Buffer - full response packet }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, M-TLS-PROFILE, fn-resolveFakeCertLen, fn-resolveReplayAlpn
// END_CONTRACT: buildServerHello
export function buildServerHello(secret, clientDigest, sessionId, alpn = null, profile = null, offeredCiphers = null, certLen = 0, offeredAlpn = []) {
  // START_BLOCK_BUILD
  const x25519 = genX25519PublicKey();
  // When a captured profile is available, replay its structure: the observed CCS count and
  // 0x17 app-data record sizes (random content — we replay the SHAPE, not the encrypted
  // bytes). The CIPHER, however, is replayed only when the client actually offered it:
  // RFC 8446 requires the selected suite to be one of the client's — answering a foreign
  // suite (e.g. rutube's 0x1302 to a 0x1301-only client) makes strict clients abort right
  // after ServerHello.
  //
  // ALPN fidelity, and the one place where fidelity has to yield: when the profile recorded a
  // protocol we replay it; when it recorded NONE we used to omit the extension so the flight matches
  // the fronted origin — but only for a client that never asked. resolveReplayAlpn owns that rule:
  // a client that OFFERED ALPN must be answered (RFC 7301), because a strict one aborts its MTProto
  // stream when the ServerHello declines, and we then forward bytes the DC silently ignores.
  const replayAlpn = resolveReplayAlpn({ profile, configuredAlpn: alpn, offeredAlpn });
  const cipher = resolveServerCipher(profile, offeredCiphers);
  const tlsExtensions = Buffer.concat([
    Buffer.from([0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]),
    x25519,
    Buffer.from([0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]),
    // ALPN extension (0x00 0x10): advertises the negotiated protocol, mirroring a real
    // TLS 1.3 server flight. Omitted entirely when no ALPN is configured (backward compatible).
    ...(replayAlpn ? [buildAlpnExtension([replayAlpn])] : []),
  ]);
  const srvHello = Buffer.concat([
    TLS_VERS,
    Buffer.alloc(DIGEST_LEN), // random placeholder, replaced by response digest
    Buffer.from([sessionId.length]),
    sessionId,
    cipher,
    Buffer.from([0x00]),
    tlsExtensions,
  ]);

  const recordLen = 4 + srvHello.length; // 1 (type) + 3 (hs length) + srvHello
  const recordLenBuf = Buffer.alloc(2);
  recordLenBuf.writeUInt16BE(recordLen, 0);
  const hsLenBuf = Buffer.alloc(3);
  hsLenBuf.writeUIntBE(srvHello.length, 0, 3);

  // Build the post-ServerHello flight: CCS record(s) + ONE 0x17 application-data record.
  // The fake-TLS protocol (mtprotoproxy-compatible) treats the FIRST 0x17 record as the fake
  // certificate and everything after it as the MTProto stream, so we must emit exactly one
  // fake-cert record. With a captured profile we size it to match the real origin's Certificate
  // record (profile.certLen) instead of a random 1024-4095 — a strong, stable fingerprint signal.
  const flightParts = [];
  const ccsCount = profile && profile.ccsCount ? profile.ccsCount : 1;
  for (let i = 0; i < ccsCount; i++) flightParts.push(TLS_CHANGE_CIPHER);

  const fakeCertLen = certLen > 0 ? certLen : resolveFakeCertLen(profile);
  const httpData = randomBytes(fakeCertLen);
  const httpLenBuf = Buffer.alloc(2);
  httpLenBuf.writeUInt16BE(httpData.length, 0);
  flightParts.push(TLS_APP_HDR, httpLenBuf, httpData);

  let helloPkt = Buffer.concat([
    Buffer.from([0x16, 0x03, 0x03]),
    recordLenBuf,
    Buffer.from([0x02]),
    hsLenBuf,
    srvHello,
    ...flightParts,
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

// START_CONTRACT: buildAlpnExtension
//   PURPOSE: Build a TLS ALPN extension (type 0x00 0x10) advertising the given protocols
//   INPUTS: { protocols: string[] - ordered list of ALPN protocol names }
//   OUTPUTS: { Buffer - extension bytes: type(2) + extLen(2) + listLen(2) + per-proto entries }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS
// END_CONTRACT: buildAlpnExtension
export function buildAlpnExtension(protocols) {
  // START_BLOCK_ALPN
  const listEntries = [];
  for (const p of protocols) {
    const name = Buffer.from(p, "latin1");
    listEntries.push(Buffer.from([name.length]), name);
  }
  const list = Buffer.concat(listEntries);
  const listLen = Buffer.alloc(2);
  listLen.writeUInt16BE(list.length, 0);
  const body = Buffer.concat([listLen, list]);
  const ext = Buffer.alloc(4);
  ext.writeUInt16BE(0x0010, 0); // extension type: ALPN
  ext.writeUInt16BE(body.length, 2);
  return Buffer.concat([ext, body]);
  // END_BLOCK_ALPN
}

// START_CONTRACT: locateExtensions
//   PURPOSE: Locate the extensions block of a ClientHello by walking its length-prefixed fields
//   INPUTS: { handshake: Buffer - full ClientHello from 0x16 onward }
//   OUTPUTS: { { start: number, end: number } | null - offsets of the extension block, null if
//              the handshake is not a ClientHello or any field overruns it }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-extractSni, fn-extractAlpn
// END_CONTRACT: locateExtensions
function locateExtensions(handshake) {
  // START_BLOCK_LOCATE_EXTENSIONS
  try {
    if (handshake.length < 5 || handshake[0] !== 0x16) return null;
    let off = 5; // skip 0x16 0x03 0x01 + record length(2)
    if (handshake[off] !== 0x01) return null; // not a ClientHello
    off += 1;
    if (off + 3 > handshake.length) return null;
    const hsLen = handshake.readUIntBE(off, 3);
    off += 3;
    const hsEnd = off + hsLen;
    if (hsEnd > handshake.length) return null;
    off += 2; // client version
    off += 32; // random
    if (off >= hsEnd) return null;
    off += 1 + handshake[off]; // session id (len byte + bytes)
    if (off + 2 > hsEnd) return null;
    off += 2 + handshake.readUInt16BE(off); // cipher suites (len + bytes)
    if (off + 1 > hsEnd) return null;
    off += 1 + handshake[off]; // compression methods (len byte + bytes)
    if (off + 2 > hsEnd) return null;
    const extLen = handshake.readUInt16BE(off);
    const start = off + 2;
    const end = start + extLen;
    if (end > hsEnd) return null;
    return { start, end };
  } catch {
    return null;
  }
  // END_BLOCK_LOCATE_EXTENSIONS
}

// Walk every extension in the block. `visit(extType, bodyStart, bodyEnd, blockEnd)` returning true
// stops the walk. A malformed extension body stops it too (the ClientHello is then untrustworthy,
// so no extension after it may be read).
function eachExtension(handshake, visit) {
  // START_BLOCK_EACH_EXTENSION
  const loc = locateExtensions(handshake);
  if (!loc) return false;
  let off = loc.start;
  while (off + 4 <= loc.end) {
    const extType = handshake.readUInt16BE(off);
    const eLen = handshake.readUInt16BE(off + 2);
    off += 4;
    if (off + eLen > loc.end) return false;
    if (visit(extType, off, off + eLen, loc.end)) return true;
    off += eLen;
  }
  return false;
  // END_BLOCK_EACH_EXTENSION
}

// START_CONTRACT: extractSni
//   PURPOSE: Parse the SNI hostname from a TLS ClientHello record (server_name extension)
//   INPUTS: { handshake: Buffer - full ClientHello from 0x16 onward }
//   OUTPUTS: { string | null - lowercased SNI hostname, or null if absent/unparseable }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-locateExtensions
// END_CONTRACT: extractSni
export function extractSni(handshake) {
  // START_BLOCK_SNI
  try {
    let host = null;
    eachExtension(handshake, (extType, start, end, blockEnd) => {
      if (extType !== 0x0000) return false; // server_name extension
      if (start + 2 > end) return true;
      const snListLen = handshake.readUInt16BE(start);
      let p = start + 2;
      const snListEnd = start + 2 + snListLen; // list bytes start after the 2-byte listLen field
      if (snListEnd > blockEnd) return true;
      while (p + 3 <= snListEnd) {
        const nameType = handshake[p];
        const nameLen = handshake.readUInt16BE(p + 1);
        p += 3;
        if (nameType === 0x00 && p + nameLen <= snListEnd) {
          host = handshake.subarray(p, p + nameLen).toString("latin1").toLowerCase();
          return true;
        }
        p += nameLen;
      }
      return true; // server_name present but carrying no hostname -> absent
    });
    return host;
  } catch {
    return null;
  }
  // END_BLOCK_SNI
}

// START_CONTRACT: extractAlpn
//   PURPOSE: Parse the FIRST ALPN protocol the client offered from a TLS ClientHello
//   INPUTS: { handshake: Buffer - full ClientHello from 0x16 onward }
//   OUTPUTS: { string | null - first offered protocol name, or null if the extension is absent }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-locateExtensions, fn-buildServerHello
// END_CONTRACT: extractAlpn
export function extractAlpn(handshake) {
  // START_BLOCK_ALPN_PARSE
  return extractAlpnList(handshake)[0] ?? null;
  // END_BLOCK_ALPN_PARSE
}

// START_CONTRACT: extractAlpnList
//   PURPOSE: List every ALPN protocol a ClientHello offered, in the client's own preference order
//   INPUTS: { handshake: Buffer - ClientHello from 0x16 onward }
//   OUTPUTS: { string[] - offered protocol names, empty when the extension is absent or unreadable }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-extractAlpn, fn-resolveReplayAlpn
// END_CONTRACT: extractAlpnList
export function extractAlpnList(handshake) {
  // Existence was always the diagnostic: when a captured profile recorded NO alpn
  // (alpnKnown=true, alpn=null) buildServerHello used to OMIT the extension to match the fronted
  // origin, so "client offered ALPN and we sent none" was indistinguishable from "client offered
  // nothing" — and it was exactly this. Production ran a client that OFFERED ALPN: the proxy logged a
  // successful fake-TLS handshake, then relayed the client's stream to the DC and received nothing
  // back (bytes_out: 0, dc_replies: 0). The strict client had aborted once the ServerHello declined
  // its offer. Deciding the answer needs the whole list, not just the first entry.
  try {
    const out = [];
    eachExtension(handshake, (extType, start, end, blockEnd) => {
      if (extType !== 0x0010) return false; // application_layer_protocol_negotiation
      if (start + 2 > end) return true;
      const listLen = handshake.readUInt16BE(start);
      let p = start + 2;
      const listEnd = start + 2 + listLen;
      if (listEnd > blockEnd) return true;
      while (p < listEnd) {
        const n = handshake[p];
        if (n > 0 && p + 1 + n <= listEnd) out.push(handshake.subarray(p + 1, p + 1 + n).toString("latin1"));
        p += 1 + n;
      }
      return true;
    });
    return out;
  } catch {
    return [];
  }
}

// START_CONTRACT: resolveReplayAlpn
//   PURPOSE: Decide which ALPN protocol (if any) the fake ServerHello must carry
//   INPUTS: { profile: { alpn, alpnKnown } | null, configuredAlpn: string | null,
//             offeredAlpn: string[] - what the CLIENT offered, in its preference order }
//   OUTPUTS: { string | null - protocol to advertise, null = omit the extension entirely }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-buildServerHello, fn-extractAlpnList, M-MTPROTO-SERVER
// END_CONTRACT: resolveReplayAlpn
export function resolveReplayAlpn({ profile, configuredAlpn, offeredAlpn }) {
  // START_BLOCK_ALPN_RESOLVE
  const offered = Array.isArray(offeredAlpn) ? offeredAlpn : [];
  // The origin negotiated one: replay it verbatim, that is the whole point of the profile.
  if (profile && profile.alpn) return profile.alpn;
  // The client ASKED. RFC 7301 says it must be answered, and a client that offered ALPN and then
  // received no extension treats the handshake as failed — the fake-TLS handshake "succeeds" here
  // while the client's MTProto stream dies, so the DC is then handed bytes it will never answer.
  // Origin fidelity cannot overrule a question the client actually asked.
  if (offered.length > 0) return offered.includes(configuredAlpn) ? configuredAlpn : offered[0];
  // Nobody asked, so mirroring the origin's silence costs nothing and keeps the flight shaped like
  // the fronted site — which is exactly what alpnKnown=true records.
  if (profile && profile.alpnKnown === true) return null;
  return configuredAlpn ?? null;
  // END_BLOCK_ALPN_RESOLVE
}

// START_CONTRACT: resolveServerCipher
//   PURPOSE: Resolve which cipher suite the fake ServerHello actually selects
//   INPUTS: { profile: { cipher } | null - captured profile; offeredCiphers: Buffer[] | null - suites
//             the client offered (from validateClientHello) }
//   OUTPUTS: { Buffer(2) - the selected suite: profile.cipher when the client offered it, else the
//              0x1301 default }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS, fn-buildServerHello, fn-validateClientHello
// END_CONTRACT: resolveServerCipher
export function resolveServerCipher(profile, offeredCiphers) {
  // START_BLOCK_SERVER_CIPHER
  // RFC 8446 requires the selected suite to be one the CLIENT offered: answering a foreign suite
  // (e.g. rutube's 0x1302 to a 0x1301-only client) makes strict clients abort right after
  // ServerHello. Exposed separately from buildServerHello so the journal can report the suite that
  // really went on the wire instead of the captured profile value, which is not always the one sent.
  const raw = profile && profile.cipher;
  // The captured profile carries the suite as a Buffer (tls-profile), tests and older callers pass
  // a plain byte Array, and every SERIALIZED form (metrics, journal, any future config load) renders
  // it as hex. Buffer.from(x) on a hex STRING yields its UTF-8 bytes — "1302" becomes 4 bytes —
  // which can never equal a 2-byte suite, so a hex-valued profile would silently degrade to the
  // default forever. Accept all three encodings; anything else falls back to the default.
  let profileCipher = null;
  if (typeof raw === "string") {
    if (/^[0-9a-fA-F]{4}$/.test(raw)) profileCipher = Buffer.from(raw, "hex");
  } else if (raw != null) {
    const asBuf = Buffer.from(raw);
    if (asBuf.length === 2) profileCipher = asBuf;
  }
  const profileCipherOffered =
    profileCipher !== null &&
    Array.isArray(offeredCiphers) &&
    offeredCiphers.some((c) => c.length === 2 && c.equals(profileCipher));
  return profileCipherOffered ? profileCipher : Buffer.from(TLS_CIPHERSUITE);
  // END_BLOCK_SERVER_CIPHER
}

// START_CONTRACT: splitTlsRecords
//   PURPOSE: Split a byte stream of concatenated TLS records into individual record buffers
//   INPUTS: { buf: Buffer - one or more TLS records back-to-back }
//   OUTPUTS: { Buffer[] - each element is exactly one TLS record (5-byte header + payload) }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS
// END_CONTRACT: splitTlsRecords
export function splitTlsRecords(buf) {
  // START_BLOCK_SPLIT
  const out = [];
  let off = 0;
  while (off + 5 <= buf.length) {
    const len = buf.readUInt16BE(off + 3);
    if (off + 5 + len > buf.length) break;
    out.push(buf.subarray(off, off + 5 + len));
    off += 5 + len;
  }
  return out;
  // END_BLOCK_SPLIT
}

// START_CONTRACT: buildTlsAlert
//   PURPOSE: Build a fatal TLS alert record (used for reject_handshake mode)
//   INPUTS: { description: number - TLS alert description code (e.g. 112 = unrecognized_name) }
//   OUTPUTS: { Buffer - 0x15 0x03 0x03 00 02 02 <description> }
//   SIDE_EFFECTS: none
//   LINKS: M-FAKETLS
// END_CONTRACT: buildTlsAlert
export function buildTlsAlert(description) {
  // START_BLOCK_ALERT
  return Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description & 0xff]);
  // END_BLOCK_ALERT
}