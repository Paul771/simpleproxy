// FILE: tests/dc-fallback.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Unit tests for DC address candidate ordering (IPv4/IPv6 fallback)
//   SCOPE: getDcAddressCandidates ordering by preferIpv6, invalid idx, fallback completeness
//   DEPENDS: M-MTPROTO
//   LINKS: V-M-MTPROTO
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import { getDcAddress, getDcAddressCandidates } from "../src/mtproto.js";

test("candidates: preferIpv6=false orders IPv4 first, IPv6 second", () => {
  const list = getDcAddressCandidates(2, { preferIpv6: false });
  assert.equal(list.length, 2);
  assert.equal(list[0].host, "149.154.167.51"); // IPv4 DC2
  assert.equal(list[0].port, 443);
  assert.equal(list[1].host, "2001:b28:f23f:f002::a"); // IPv6 DC2 fallback
});

test("candidates: preferIpv6=true orders IPv6 first, IPv4 second", () => {
  const list = getDcAddressCandidates(1, { preferIpv6: true });
  assert.equal(list.length, 2);
  assert.equal(list[0].host, "2001:b28:f23d:f001::a"); // IPv6 DC1
  assert.equal(list[1].host, "149.154.175.50"); // IPv4 fallback
});

test("candidates: invalid dcIdx returns empty list", () => {
  assert.deepEqual(getDcAddressCandidates(0, {}), []);
  assert.deepEqual(getDcAddressCandidates(99, {}), []);
  assert.deepEqual(getDcAddressCandidates(-99, {}), []);
});

test("candidates: negative dc_idx resolves via abs (DC -2 -> DC2)", () => {
  const list = getDcAddressCandidates(-2, { preferIpv6: false });
  assert.equal(list.length, 2);
  assert.equal(list[0].host, "149.154.167.51");
});

test("getDcAddress: backward-compatible single-address resolver still works", () => {
  assert.deepEqual(getDcAddress(2, { preferIpv6: false }), { host: "149.154.167.51", port: 443 });
  assert.deepEqual(getDcAddress(2, { preferIpv6: true }), { host: "2001:b28:f23f:f002::a", port: 443 });
  assert.equal(getDcAddress(99, {}), null);
});