// FILE: src/auth.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Parse and verify Proxy-Authorization: Basic (pure logic, timing-safe)
//   SCOPE: header parsing, credential comparison
//   DEPENDS: node:crypto
//   LINKS: M-AUTH
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   parseBasicAuth - parse a Basic auth header into { user, pass } or null
//   checkAuth - verify a header against configured creds (or true when auth disabled)
// END_MODULE_MAP

import { timingSafeEqual } from "node:crypto";

const MAX_HEADER_LEN = 1024;

// START_CONTRACT: parseBasicAuth
//   PURPOSE: Parse a "Basic <base64>" Proxy-Authorization header into credentials
//   INPUTS: { header: string | undefined }
//   OUTPUTS: { { user: string, pass: string } | null }
//   SIDE_EFFECTS: none
//   LINKS: M-AUTH
// END_CONTRACT: parseBasicAuth
export function parseBasicAuth(header) {
  // START_BLOCK_PARSE
  if (typeof header !== "string" || header.length === 0 || header.length > MAX_HEADER_LEN) {
    return null;
  }
  const parts = header.split(" ");
  if (parts.length !== 2 || parts[0].toLowerCase() !== "basic") return null;

  let decoded;
  try {
    decoded = Buffer.from(parts[1], "base64").toString("utf8");
  } catch {
    return null;
  }
  const sep = decoded.indexOf(":");
  if (sep <= 0 || sep === decoded.length - 1) return null;

  return { user: decoded.slice(0, sep), pass: decoded.slice(sep + 1) };
  // END_BLOCK_PARSE
}

// START_CONTRACT: checkAuth
//   PURPOSE: Verify a header against configured creds; always true when creds are null (auth disabled)
//   INPUTS: { header: string | undefined, creds: { user: string, pass: string } | null }
//   OUTPUTS: { boolean }
//   SIDE_EFFECTS: none
//   LINKS: M-AUTH
// END_CONTRACT: checkAuth
export function checkAuth(header, creds) {
  // START_BLOCK_VERIFY
  if (creds === null) return true; // auth disabled
  const parsed = parseBasicAuth(header);
  if (parsed === null) return false;

  const userA = Buffer.from(parsed.user);
  const userB = Buffer.from(creds.user);
  const passA = Buffer.from(parsed.pass);
  const passB = Buffer.from(creds.pass);

  const userOk =
    userA.length === userB.length && timingSafeEqual(userA, userB);
  const passOk =
    passA.length === passB.length && timingSafeEqual(passA, passB);
  return userOk && passOk;
  // END_BLOCK_VERIFY
}
