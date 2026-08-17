// FILE: tests/metrics.test.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Unit + e2e tests for the Prometheus metrics registry and /metrics server
//   SCOPE: counter/gauge accounting, Prometheus text-exposition format, HTTP scrape over a socket
//   DEPENDS: M-METRICS
//   LINKS: V-M-METRICS
//   ROLE: TEST
//   MAP_MODE: LOCALS
// END_MODULE_CONTRACT

import { test } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import { createMetrics, startMetricsServer } from "../src/metrics.js";
import { makeLog } from "../src/log.js";

test("metrics: counter starts at zero and increments", () => {
  const m = createMetrics();
  assert.equal(m.get("simpleproxy_http_connections_total"), 0);
  m.inc("simpleproxy_http_connections_total");
  m.inc("simpleproxy_http_connections_total", 2);
  assert.equal(m.get("simpleproxy_http_connections_total"), 3);
});

test("metrics: gauge stores last set value", () => {
  const m = createMetrics();
  m.set("simpleproxy_active_tunnels", 5);
  assert.equal(m.get("simpleproxy_active_tunnels"), 5);
  m.set("simpleproxy_active_tunnels", 3);
  assert.equal(m.get("simpleproxy_active_tunnels"), 3);
});

test("metrics: unknown metric reads as zero, never throws", () => {
  const m = createMetrics();
  assert.equal(m.get("simpleproxy_does_not_exist"), 0);
  // inc on an undefined def is a no-op (defensive: only known metrics are rendered).
  m.inc("simpleproxy_does_not_exist");
  assert.equal(m.get("simpleproxy_does_not_exist"), 0);
});

test("metrics: render produces Prometheus text exposition with HELP/TYPE", () => {
  const m = createMetrics();
  m.inc("simpleproxy_http_connections_total", 7);
  m.set("simpleproxy_active_tunnels", 2);
  m.inc("simpleproxy_replay_attacks_total");
  const text = m.render();
  const lines = text.split("\n");

  // HELP + TYPE lines for a counter.
  assert.ok(lines.some((l) => l.startsWith("# HELP simpleproxy_http_connections_total ")));
  assert.ok(lines.some((l) => l === "# TYPE simpleproxy_http_connections_total counter"));
  assert.ok(lines.some((l) => l === "simpleproxy_http_connections_total 7"));
  // gauge type for active tunnels.
  assert.ok(lines.some((l) => l === "# TYPE simpleproxy_active_tunnels gauge"));
  assert.ok(lines.some((l) => l === "simpleproxy_active_tunnels 2"));
  // replay counter line present.
  assert.ok(lines.some((l) => l === "simpleproxy_replay_attacks_total 1"));
});

test("metrics: render ends with a trailing newline", () => {
  const m = createMetrics();
  const text = m.render();
  assert.ok(text.endsWith("\n"));
});

test("e2e: startMetricsServer serves /metrics as text/plain over a real socket", async () => {
  const m = createMetrics();
  m.inc("simpleproxy_http_connections_total", 11);
  m.set("simpleproxy_active_mtproto", 4);

  const log = makeLog();
  const server = startMetricsServer({ port: 0, host: "127.0.0.1" }, m, log);

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();

  const body = await new Promise((resolve, reject) => {
    const sock = net.connect(addr.port, "127.0.0.1", () => {
      sock.write("GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    });
    let buf = "";
    sock.on("data", (c) => (buf += c.toString()));
    sock.on("end", () => resolve(buf));
    sock.on("error", reject);
  });

  server.close();

  assert.ok(body.startsWith("HTTP/1.1 200 OK\r\n"));
  assert.ok(body.includes("Content-Type: text/plain; version=0.0.4; charset=utf-8"));
  assert.ok(body.includes("# TYPE simpleproxy_http_connections_total counter"));
  assert.ok(body.includes("simpleproxy_http_connections_total 11"));
  assert.ok(body.includes("simpleproxy_active_mtproto 4"));
});

test("e2e: startMetricsServer rejects non-GET /metrics with 404", async () => {
  const m = createMetrics();
  const log = makeLog();
  const server = startMetricsServer({ port: 0, host: "127.0.0.1" }, m, log);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();

  const body = await new Promise((resolve, reject) => {
    const sock = net.connect(addr.port, "127.0.0.1", () => {
      sock.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    });
    let buf = "";
    sock.on("data", (c) => (buf += c.toString()));
    sock.on("end", () => resolve(buf));
    sock.on("error", reject);
  });
  server.close();

  assert.ok(body.startsWith("HTTP/1.1 404 Not Found\r\n"));
});