// FILE: src/metrics.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Prometheus text-exposition metrics registry + side-port /metrics HTTP server (zero deps)
//   SCOPE: counter/gauge accounting, Prometheus text rendering, minimal HTTP responder for /metrics
//   DEPENDS: node:net
//   LINKS: M-METRICS
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createMetrics - build a counter/gauge registry with a Prometheus render()
//   startMetricsServer - tiny HTTP server exposing /metrics on a side port
// END_MODULE_MAP

import net from "node:net";

// START_BLOCK_METRIC_DEFS
// Fixed catalogue of exposed metrics. Only these names are recognised by render();
// inc()/set() on an unknown name is a no-op (defensive: callers cannot invent metrics.
const METRIC_DEFS = [
  { name: "simpleproxy_http_connections_total", type: "counter", help: "Total HTTP CONNECT connections accepted" },
  { name: "simpleproxy_mtproto_connections_total", type: "counter", help: "Total MTProto connections accepted (DC relay established)" },
  { name: "simpleproxy_active_tunnels", type: "gauge", help: "Currently open HTTP CONNECT tunnels" },
  { name: "simpleproxy_active_mtproto", type: "gauge", help: "Currently open MTProto relay connections" },
  { name: "simpleproxy_pending_mtproto", type: "gauge", help: "MTProto sockets still in the handshake phase" },
  { name: "simpleproxy_bytes_in_total", type: "counter", help: "Bytes received from clients (both protocols)" },
  { name: "simpleproxy_bytes_out_total", type: "counter", help: "Bytes sent to clients (both protocols)" },
  { name: "simpleproxy_replay_attacks_total", type: "counter", help: "fake-TLS ClientHello digests rejected as replays" },
  { name: "simpleproxy_mask_splices_total", type: "counter", help: "Non-keyed/unknown-SNI clients spliced to mask_host" },
  { name: "simpleproxy_pending_caps_total", type: "counter", help: "Connections rejected by the pending-handshake cap" },
  { name: "simpleproxy_rejected_total", type: "counter", help: "Connections rejected by the active-connection cap" },
];
const KNOWN = new Set(METRIC_DEFS.map((d) => d.name));
// END_BLOCK_METRIC_DEFS

// START_CONTRACT: createMetrics
//   PURPOSE: Build a counter/gauge registry with a Prometheus text-exposition render()
//   INPUTS: { none }
//   OUTPUTS: { inc(name, n=1): void, set(name, v): void, get(name): number, render(): string }
//   SIDE_EFFECTS: maintains an internal Map of values (stateful)
//   LINKS: M-METRICS
// END_CONTRACT: createMetrics
export function createMetrics() {
  // START_BLOCK_REGISTRY
  const values = new Map(); // name -> number

  const inc = (name, n = 1) => {
    if (!KNOWN.has(name)) return;
    values.set(name, (values.get(name) ?? 0) + n);
  };
  const set = (name, v) => {
    if (!KNOWN.has(name)) return;
    values.set(name, v);
  };
  const get = (name) => (KNOWN.has(name) ? values.get(name) ?? 0 : 0);

  const render = () => {
    const parts = [];
    for (const def of METRIC_DEFS) {
      parts.push(`# HELP ${def.name} ${def.help}`);
      parts.push(`# TYPE ${def.name} ${def.type}`);
      parts.push(`${def.name} ${get(def.name)}`);
    }
    return parts.join("\n") + "\n";
  };

  return { inc, set, get, render };
  // END_BLOCK_REGISTRY
}

// START_CONTRACT: startMetricsServer
//   PURPOSE: Tiny HTTP server answering GET /metrics with the Prometheus text exposition
//   INPUTS: { opts: { port: number, host: string }, registry: Metrics, log: Log }
//   OUTPUTS: { net.Server - not yet listening; caller calls listen() }
//   SIDE_EFFECTS: creates a net.Server; caller binds it to a port
//   LINKS: M-METRICS
// END_CONTRACT: startMetricsServer
export function startMetricsServer({ port, host }, registry, log) {
  // START_BLOCK_METRICS_HTTP
  const body = () => registry.render();
  const server = net.createServer((socket) => {
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString("latin1");
      const end = buf.indexOf("\r\n\r\n");
      if (end === -1) return;
      socket.removeAllListeners("data");
      const head = buf.slice(0, end);
      const firstLine = head.split("\r\n")[0];
      const [method, path] = firstLine.split(" ");
      if (method === "GET" && path === "/metrics") {
        const text = body();
        socket.write(
          "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" +
            `Content-Length: ${Buffer.byteLength(text)}\r\n` +
            "Connection: close\r\n\r\n"
        );
        socket.end(text);
        return;
      }
      socket.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      socket.end();
    });
    socket.on("error", () => socket.destroy());
  });
  if (log) log("metrics_listen", "DF-METRICS", `${host}:${port}`);
  return server;
  // END_BLOCK_METRICS_HTTP
}