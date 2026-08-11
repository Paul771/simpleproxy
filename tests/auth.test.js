// FILE: tests/auth.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-AUTH header parsing and credential verification
//   SCOPE: valid/invalid headers, auth disabled behavior
//   DEPENDS: M-AUTH
//   LINKS: V-M-AUTH
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseBasicAuth, checkAuth } from "../src/auth.js";

const basic = (user, pass) => "Basic " + Buffer.from(`${user}:${pass}`).toString("base64");

test("parseBasicAuth: valid header", () => {
  assert.deepEqual(parseBasicAuth(basic("alice", "secret")), { user: "alice", pass: "secret" });
  assert.deepEqual(parseBasicAuth(basic("u", "p")), { user: "u", pass: "p" });
});

test("parseBasicAuth: rejects malformed headers", () => {
  assert.equal(parseBasicAuth(undefined), null);
  assert.equal(parseBasicAuth(""), null);
  assert.equal(parseBasicAuth("Bearer abc"), null);
  assert.equal(parseBasicAuth("Basic"), null);
  assert.equal(parseBasicAuth("Basic "), null); // empty payload
  assert.equal(parseBasicAuth("Basic !!!notbase64!!!"), null); // invalid base64 -> empty user or garbage; may parse as empty -> sep check
  assert.equal(parseBasicAuth("Basic " + Buffer.from("nocolon").toString("base64")), null); // no colon
});

test("checkAuth: correct credentials pass", () => {
  const creds = { user: "alice", pass: "secret" };
  assert.equal(checkAuth(basic("alice", "secret"), creds), true);
});

test("checkAuth: wrong credentials fail", () => {
  const creds = { user: "alice", pass: "secret" };
  assert.equal(checkAuth(basic("alice", "wrong"), creds), false);
  assert.equal(checkAuth(basic("bob", "secret"), creds), false);
  assert.equal(checkAuth(undefined, creds), false);
  assert.equal(checkAuth(basic("", ""), creds), false);
});

test("checkAuth: auth disabled when creds are null", () => {
  assert.equal(checkAuth(undefined, null), true);
  assert.equal(checkAuth("", null), true);
  assert.equal(checkAuth("Basic garbage", null), true);
});
