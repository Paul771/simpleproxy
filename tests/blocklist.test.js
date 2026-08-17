// FILE: tests/blocklist.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Unit tests for the client-IP blocklist (CIDR + bare IP, IPv4/IPv6)
//   SCOPE: parse entries, isBlocked matching, IPv4-mapped-IPv6 normalisation, invalid entry rejection
//   DEPENDS: M-BLOCKLIST, M-CONFIG
//   LINKS: V-M-BLOCKLIST
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { createBlocklist } from "../src/blocklist.js";
import { loadConfig } from "../src/config.js";
import { createMuxServer } from "../src/mux.js";
import { makeLog } from "../src/log.js";

test("isBlocked: bare IPv4 exact match", () => {
  const b = createBlocklist(["10.1.2.3"]);
  assert.equal(b.isBlocked("10.1.2.3"), true);
  assert.equal(b.isBlocked("10.1.2.4"), false);
});

test("isBlocked: IPv4 CIDR matches a range", () => {
  const b = createBlocklist(["10.0.0.0/8", "192.168.1.0/24"]);
  assert.equal(b.isBlocked("10.255.255.255"), true);
  assert.equal(b.isBlocked("10.0.0.1"), true);
  assert.equal(b.isBlocked("11.0.0.1"), false);
  assert.equal(b.isBlocked("192.168.1.50"), true);
  assert.equal(b.isBlocked("192.168.2.50"), false);
});

test("isBlocked: bare IPv6 exact match", () => {
  const b = createBlocklist(["2001:db8::1"]);
  assert.equal(b.isBlocked("2001:db8::1"), true);
  assert.equal(b.isBlocked("2001:db8::2"), false);
});

test("isBlocked: IPv6 CIDR matches a range", () => {
  const b = createBlocklist(["2001:db8::/32"]);
  assert.equal(b.isBlocked("2001:db8:1:2:3:4:5:6"), true);
  assert.equal(b.isBlocked("2001:db9::1"), false);
});

test("isBlocked: IPv4-mapped IPv6 (::ffff:) is normalised to IPv4", () => {
  const b = createBlocklist(["10.0.0.0/8"]);
  assert.equal(b.isBlocked("::ffff:10.5.5.5"), true);
  assert.equal(b.isBlocked("::ffff:11.5.5.5"), false);
});

test("isBlocked: empty blocklist blocks nothing", () => {
  const b = createBlocklist([]);
  assert.equal(b.isBlocked("1.2.3.4"), false);
  assert.equal(b.isBlocked("::1"), false);
});

test("isBlocked: null/undefined/empty ip is not blocked", () => {
  const b = createBlocklist(["10.0.0.0/8"]);
  assert.equal(b.isBlocked(null), false);
  assert.equal(b.isBlocked(undefined), false);
  assert.equal(b.isBlocked(""), false);
});

test("createBlocklist: invalid entry throws", () => {
  assert.throws(() => createBlocklist(["not-an-ip"]), /INVALID_ENV/);
  assert.throws(() => createBlocklist(["10.0.0.0/40"]), /INVALID_ENV/);
  assert.throws(() => createBlocklist(["10.0.0.0/-1"]), /INVALID_ENV/);
});

test("config: MTPROTO_BLOCKLIST parses into validated entry strings", () => {
  const cfg = loadConfig({
    MTPROTO_SECRET: "00000000000000000000000000000000",
    MTPROTO_BLOCKLIST: "10.0.0.0/8, 192.168.1.5",
  });
  assert.deepEqual(cfg.mtprotoBlocklist, ["10.0.0.0/8", "192.168.1.5"]);
  // The runtime object is built by index.js from these entries.
  const b = createBlocklist(cfg.mtprotoBlocklist);
  assert.equal(b.isBlocked("10.5.5.5"), true);
  assert.equal(b.isBlocked("8.8.8.8"), false);
  assert.equal(b.isBlocked("192.168.1.5"), true);
});

test("config: empty/absent MTPROTO_BLOCKLIST -> empty array", () => {
  const cfg = loadConfig({ MTPROTO_SECRET: "00000000000000000000000000000000" });
  assert.deepEqual(cfg.mtprotoBlocklist, []);
});

test("config: invalid MTPROTO_BLOCKLIST entry -> INVALID_ENV", () => {
  assert.throws(
    () => loadConfig({ MTPROTO_SECRET: "00000000000000000000000000000000", MTPROTO_BLOCKLIST: "garbage/xyz" }),
    /INVALID_ENV/,
  );
});

test("e2e: mux rejects a blocked client IP at the edge (no handler reached)", async () => {
  const log = makeLog();
  // Block 127.0.0.1 — all local test connections come from there.
  const blocklist = createBlocklist(["127.0.0.0/8"]);
  let handlerReached = false;
  const mux = createMuxServer(
    {
      "http-connect": () => { handlerReached = true; },
      "http-other": () => { handlerReached = true; },
      mtproto: () => { handlerReached = true; },
    },
    { isBlocked: (ip) => blocklist.isBlocked(ip), onBlocked: (ip) => log("blocklist_reject", "DF-BLOCK", ip) }
  );
  await new Promise((r) => mux.listen(0, "127.0.0.1", r));
  const port = mux.address().port;

  const closed = await new Promise((resolve) => {
    const sock = net.connect(port, "127.0.0.1", () => {
      // Provoke the peek — send a byte so the connection would route if not blocked.
      sock.write("CONNECT example.com:443 HTTP/1.1\r\n\r\n");
    });
    let got = "";
    sock.on("data", (c) => (got += c.toString()));
    sock.on("close", () => resolve({ closed: true, got }));
    sock.on("error", () => resolve({ closed: true, got }));
    setTimeout(() => resolve({ closed: false, got }), 1500);
  });

  mux.close();
  assert.equal(closed.closed, true, "blocked client is forcibly closed");
  assert.equal(closed.got, "", "no response bytes sent to a blocked client");
  assert.equal(handlerReached, false, "no handler was reached for a blocked IP");
});

test("e2e: mux lets a non-blocked client through to the handler", async () => {
  const blocklist = createBlocklist(["10.0.0.0/8"]); // does not include 127.0.0.1
  let handlerReached = false;
  const mux = createMuxServer(
    {
      "http-connect": (socket) => { handlerReached = true; socket.write("HTTP/1.1 200 OK\r\n\r\n"); socket.end(); },
      "http-other": () => {},
      mtproto: () => {},
    },
    { isBlocked: (ip) => blocklist.isBlocked(ip) }
  );
  await new Promise((r) => mux.listen(0, "127.0.0.1", r));
  const port = mux.address().port;

  const saw200 = await new Promise((resolve) => {
    const sock = net.connect(port, "127.0.0.1", () => {
      sock.write("CONNECT example.com:443 HTTP/1.1\r\n\r\n");
    });
    let buf = "";
    sock.on("data", (c) => { buf += c.toString(); if (buf.includes("200 OK")) { sock.destroy(); resolve(true); } });
    sock.on("error", () => resolve(false));
    sock.on("close", () => resolve(buf.includes("200 OK")));
    setTimeout(() => resolve(buf.includes("200 OK")), 1500);
  });

  mux.close();
  assert.equal(saw200, true, "non-blocked client reaches the handler and gets 200");
  assert.equal(handlerReached, true, "handler was reached for a non-blocked IP");
});