// FILE: tests/mux.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Verify M-MUX protocol classification and routing
//   SCOPE: classifyProtocol decisions, handler dispatch by first bytes
//   DEPENDS: M-MUX
//   LINKS: V-M-MUX
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { classifyProtocol, createMuxServer } from "../src/mux.js";

const CONNECT_HEAD = Buffer.from("CONNECT api.telegram.org:443 HTTP/1.1\r\nHost: api.telegram.org\r\n\r\n", "latin1");
const GET_HEAD = Buffer.from("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "latin1");
const MT_HANDSHAKE = Buffer.alloc(64, 0xab); // random-looking, not an HTTP method

test("classifyProtocol: routes correctly", () => {
  assert.equal(classifyProtocol(CONNECT_HEAD), "http-connect");
  assert.equal(classifyProtocol(GET_HEAD), "http-other");
  assert.equal(classifyProtocol(MT_HANDSHAKE), "mtproto");
  // Short heads (fewer than PEEK_LEN) default to mtproto until enough bytes arrive.
  assert.equal(classifyProtocol(Buffer.from("CONNECT")), "mtproto");
});

test("classifyProtocol: MTProto nonce that looks like HTTP method is not misrouted", () => {
  // Real clients avoid these prefixes; if one arrives we still treat it as mtproto.
  const head = Buffer.concat([Buffer.from("GET ", "latin1"), Buffer.alloc(60, 0x11)]);
  assert.equal(classifyProtocol(head), "http-other");
});

test("mux: dispatches CONNECT bytes to http-connect handler", async () => {
  const seen = { proto: null, head: null };
  const server = createMuxServer({
    "http-connect": (socket, head) => {
      seen.proto = "http-connect";
      seen.head = head;
      socket.end();
    },
    "http-other": () => {},
    "mtproto": () => {},
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  await new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(CONNECT_HEAD));
    s.on("end", resolve);
    s.on("error", reject);
  });
  server.close();
  assert.equal(seen.proto, "http-connect");
  assert.ok(seen.head.subarray(0, 8).toString("latin1") === "CONNECT ");
});

test("mux: dispatches GET bytes to http-other handler", async () => {
  const seen = { proto: null };
  const server = createMuxServer({
    "http-connect": () => {},
    "http-other": (socket) => {
      seen.proto = "http-other";
      socket.end();
    },
    "mtproto": () => {},
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  await new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(GET_HEAD));
    s.on("end", resolve);
    s.on("error", reject);
  });
  server.close();
  assert.equal(seen.proto, "http-other");
});

test("mux: dispatches MTProto bytes to mtproto handler", async () => {
  const seen = { proto: null, headLen: 0 };
  const server = createMuxServer({
    "http-connect": () => {},
    "http-other": () => {},
    "mtproto": (socket, head) => {
      seen.proto = "mtproto";
      seen.headLen = head.length;
      socket.end();
    },
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  await new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(MT_HANDSHAKE));
    s.on("end", resolve);
    s.on("error", reject);
  });
  server.close();
  assert.equal(seen.proto, "mtproto");
  assert.ok(seen.headLen >= 8, "handler receives at least the peeked head");
});
