// FILE: tests/tunnel.e2e.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: End-to-end verification of the proxy over real sockets
//   SCOPE: CONNECT handshake, byte tunneling, keep-alive, idle timeout, 403/407/503/405, stdout redaction
//   DEPENDS: M-PROXY, M-TUNNEL, M-LOG, M-ALLOW, M-AUTH
//   LINKS: V-M-TUNNEL, V-M-PROXY, V-M-LOG
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test, after } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import http from "node:http";
import { createConnectHandler } from "../src/proxy.js";
import { createMuxServer } from "../src/mux.js";
import { makeLog } from "../src/log.js";
import { isAllowed, normalizeTarget } from "../src/allow.js";
import { checkAuth } from "../src/auth.js";

// Capture stdout lines so we can assert redaction.
const out = [];
const origWrite = process.stdout.write;
process.stdout.write = (chunk, ...rest) => {
  out.push(String(chunk));
  return origWrite.call(process.stdout, chunk, ...rest);
};
after(() => {
  process.stdout.write = origWrite;
});

// START_BLOCK_FIXTURES
function startEchoServer() {
  const server = net.createServer((socket) => {
    socket.on("data", (data) => {
      socket.write(data); // echo
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

function startProxy(cfgOverrides = {}, allowImpl, authImpl) {
  const cfg = {
    port: 0,
    host: "127.0.0.1",
    maxTunnels: 32,
    idleTimeoutMs: 120_000,
    rules: [],
    ...cfgOverrides,
  };
  const log = makeLog();
  const allow = allowImpl || (() => true);
  const auth = authImpl || ((h) => checkAuth(h, cfg.creds || null));
  const httpHandlers = createConnectHandler(cfg, allow, auth, log);
  const handlers = {
    "http-connect": httpHandlers["http-connect"],
    "http-other": httpHandlers["http-other"],
    "mtproto": null,
  };
  const server = createMuxServer(handlers);
  return new Promise((resolve) => {
    server.listen(cfg.port, cfg.host, () => {
      resolve({ server, addr: server.address() });
    });
  });
}

function connectRaw(port, method, target, headers = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      const head = `${method} ${target} HTTP/1.1\r\nHost: ${target}\r\n${Object.entries(headers)
        .map(([k, v]) => `${k}: ${v}\r\n`)
        .join("")}\r\n`;
      socket.write(head);
    });
    socket.on("error", reject);
    resolve(socket);
  });
}

function readUntil(socket, marker, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error(`timeout waiting for "${marker}", got: ${JSON.stringify(buf)}`)), timeoutMs);
    socket.on("data", (d) => {
      buf += d.toString();
      if (buf.includes(marker)) {
        clearTimeout(timer);
        resolve(buf);
      }
    });
  });
}
// END_BLOCK_FIXTURES

test("e2e: CONNECT tunnel relays bytes end-to-end with byte counters", async () => {
  const echo = await startEchoServer();
  const { server, addr } = await startProxy({}, () => true);
  try {
    const echoAddr = echo.address();
    const target = `127.0.0.1:${echoAddr.port}`;
    const socket = await connectRaw(addr.port, "CONNECT", target);
    const resp = await readUntil(socket, "200");
    assert.match(resp, /200 Connection Established/);

    const payload = "GET /echo HTTP/1.1\r\nHost: localhost\r\nX-Probe: kept\r\n\r\n";
    const echoBack = new Promise((resolve) => {
      let buf = "";
      socket.on("data", (d) => {
        buf += d.toString();
        if (buf.length >= payload.length) resolve(buf);
      });
    });
    socket.write(payload);
    const received = await echoBack;
    assert.equal(received, payload); // byte-for-byte, headers untouched

    socket.end();
    await new Promise((r) => setTimeout(r, 50));
  } finally {
    server.close();
    echo.close();
  }
});

test("e2e: keep-alive — two sequential payloads over one tunnel", async () => {
  const echo = await startEchoServer();
  const { server, addr } = await startProxy({}, () => true);
  try {
    const echoAddr = echo.address();
    const socket = await connectRaw(addr.port, "CONNECT", `127.0.0.1:${echoAddr.port}`);
    await readUntil(socket, "200");

    const sendAndExpect = (payload) =>
      new Promise((resolve) => {
        let buf = "";
        const onData = (d) => {
          buf += d.toString();
          if (buf.length >= payload.length) {
            socket.off("data", onData);
            resolve(buf);
          }
        };
        socket.on("data", onData);
        socket.write(payload);
      });

    const first = "req-one\r\n";
    const second = "req-two\r\n";
    const got1 = await sendAndExpect(first);
    const got2 = await sendAndExpect(second);
    assert.equal(got1, first);
    assert.equal(got2, second);
    // Tunnel still open: a third round-trip proves the connection was reused.
    const got3 = await sendAndExpect("req-three\r\n");
    assert.equal(got3, "req-three\r\n");

    socket.end();
  } finally {
    server.close();
    echo.close();
  }
});

test("e2e: idle timeout destroys tunnel", async () => {
  const echo = await startEchoServer();
  const { server, addr } = await startProxy({ idleTimeoutMs: 100 }, () => true);
  try {
    const echoAddr = echo.address();
    const socket = await connectRaw(addr.port, "CONNECT", `127.0.0.1:${echoAddr.port}`);
    await readUntil(socket, "200");
    // No traffic -> idle timer should fire and destroy both ends.
    await new Promise((resolve) => {
      socket.on("close", resolve);
      setTimeout(resolve, 2000);
    });
    assert.ok(socket.destroyed);
  } finally {
    server.close();
    echo.close();
  }
});

test("e2e: long-poll pause does not kill tunnel (idle 120s default)", async () => {
  const echo = await startEchoServer();
  const { server, addr } = await startProxy({}, () => true);
  try {
    const echoAddr = echo.address();
    const socket = await connectRaw(addr.port, "CONNECT", `127.0.0.1:${echoAddr.port}`);
    await readUntil(socket, "200");
    // Pause shorter than default idle timeout; connection must survive.
    await new Promise((r) => setTimeout(r, 150));
    const payload = "still-alive\r\n";
    const got = await new Promise((resolve) => {
      let buf = "";
      socket.on("data", (d) => {
        buf += d.toString();
        if (buf.length >= payload.length) resolve(buf);
      });
      socket.write(payload);
    });
    assert.equal(got, payload);
    socket.end();
  } finally {
    server.close();
    echo.close();
  }
});

test("e2e: CONNECT to non-allowed host returns 403", async () => {
  const rules = [{ type: "suffix", host: ".telegram.org" }];
  const { server, addr } = await startProxy({ rules }, (raw) => isAllowed(normalizeTarget(raw), rules));
  try {
    const socket = await connectRaw(addr.port, "CONNECT", "example.com:443");
    const resp = await readUntil(socket, "403");
    assert.match(resp, /403 Forbidden/);
    socket.destroy();
  } finally {
    server.close();
  }
});

test("e2e: plain HTTP request returns 405", async () => {
  const { server, addr } = await startProxy();
  try {
    const res = await new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: addr.port, method: "GET", path: "/" }, resolve);
      req.on("error", reject);
      req.end();
    });
    assert.equal(res.statusCode, 405);
    res.resume();
  } finally {
    server.close();
  }
});

test("e2e: auth enabled — CONNECT without credentials returns 407", async () => {
  const { server, addr } = await startProxy(
    {},
    () => true,
    (h) => checkAuth(h, { user: "u", pass: "p" })
  );
  try {
    const socket = await connectRaw(addr.port, "CONNECT", "api.telegram.org:443");
    const resp = await readUntil(socket, "407");
    assert.match(resp, /407 Proxy Authentication Required/);
    socket.destroy();
  } finally {
    server.close();
  }
});

test("e2e: auth enabled — CONNECT with correct credentials opens tunnel", async () => {
  const echo = await startEchoServer();
  const { server, addr } = await startProxy(
    {},
    () => true,
    (h) => checkAuth(h, { user: "u", pass: "p" })
  );
  try {
    const echoAddr = echo.address();
    const socket = await connectRaw(addr.port, "CONNECT", `127.0.0.1:${echoAddr.port}`, {
      "Proxy-Authorization": "Basic " + Buffer.from("u:p").toString("base64"),
    });
    const resp = await readUntil(socket, "200");
    assert.match(resp, /200 Connection Established/);
    socket.end();
  } finally {
    server.close();
    echo.close();
  }
});

test("e2e: capacity limit returns 503 for maxTunnels+1", async () => {
  const echo = await startEchoServer();
  const { server, addr } = await startProxy({ maxTunnels: 1 }, () => true);
  try {
    const echoAddr = echo.address();
    const first = await connectRaw(addr.port, "CONNECT", `127.0.0.1:${echoAddr.port}`);
    await readUntil(first, "200");

    const second = await connectRaw(addr.port, "CONNECT", `127.0.0.1:${echoAddr.port}`);
    const resp = await readUntil(second, "503");
    assert.match(resp, /503 Service Unavailable/);
    second.destroy();
    first.destroy();
  } finally {
    server.close();
    echo.close();
  }
});

test("e2e: stdout redaction — no tokens, bodies, or credentials in logs", async () => {
  const echo = await startEchoServer();
  const { server, addr } = await startProxy({}, () => true);
  const marker = Math.random().toString(36).slice(2);
  try {
    const echoAddr = echo.address();
    const socket = await connectRaw(addr.port, "CONNECT", `127.0.0.1:${echoAddr.port}`, {
      "Proxy-Authorization": "Basic " + Buffer.from("supersecret:tok3n").toString("base64"),
    });
    await readUntil(socket, "200");
    const secretPayload = `LEAK-${marker}-SECRET-BODY`;
    socket.write(secretPayload);
    await new Promise((r) => setTimeout(r, 100));
    socket.end();
    await new Promise((r) => setTimeout(r, 50));

    const allLogs = out.join("");
    assert.ok(!allLogs.includes(marker), "tunnel payload leaked into logs");
    assert.ok(!allLogs.includes("supersecret"), "Proxy-Authorization leaked into logs");
    assert.ok(!allLogs.includes("tok3n"), "token leaked into logs");
  } finally {
    server.close();
    echo.close();
  }
});
