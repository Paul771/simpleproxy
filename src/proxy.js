// FILE: src/proxy.js
// VERSION: 1.1.0
// START_MODULE_CONTRACT
//   PURPOSE: HTTP CONNECT handling on raw sockets: parse CONNECT, auth -> allow -> cap -> tunnel
//   SCOPE: CONNECT request parsing, rejection of plain HTTP, tunnel capacity tracking
//   DEPENDS: M-CONFIG, M-ALLOW, M-AUTH, M-TUNNEL, M-LOG
//   LINKS: M-PROXY
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createConnectHandler - build the http-connect/http-other handlers for the mux server
//   start - listen and handle SIGTERM/SIGINT gracefully
// END_MODULE_MAP

import net from "node:net";
import { openTunnel } from "./tunnel.js";

const UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;
const MAX_HEADER_BYTES = 16 * 1024;
const CRLFCRLF = Buffer.from("\r\n\r\n", "latin1");

// START_CONTRACT: parseConnectRequest
//   PURPOSE: Parse "CONNECT host:port HTTP/1.1\r\n...headers..." from a byte buffer
//   INPUTS: { head: Buffer - buffered bytes including the full CONNECT header block }
//   OUTPUTS: { { target: string, proxyAuth: string | undefined } | null - null if incomplete/invalid }
//   SIDE_EFFECTS: none
//   LINKS: M-PROXY
// END_CONTRACT: parseConnectRequest
function parseConnectRequest(head) {
  // START_BLOCK_PARSE_CONNECT
  const end = head.indexOf(CRLFCRLF);
  if (end === -1) {
    if (head.length > MAX_HEADER_BYTES) return null;
    return { incomplete: true };
  }

  const headText = head.subarray(0, end).toString("latin1");
  const lines = headText.split("\r\n");
  const [method, target, version] = lines[0].split(" ");
  if (method !== "CONNECT" || !target || !version) return null;

  let proxyAuth;
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    if (name === "proxy-authorization") {
      proxyAuth = line.slice(colon + 1).trim();
    }
  }
  return { target, proxyAuth, headerLen: end + 4 };
  // END_BLOCK_PARSE_CONNECT
}

// START_CONTRACT: createConnectHandler
//   PURPOSE: Create protocol handlers (http-connect / http-other) for the mux server
//   INPUTS: { cfg: Config, allow: (raw: string) => boolean, auth: (h?: string) => boolean, log: Log }
//   OUTPUTS: { { "http-connect": (socket, head) => void, "http-other": (socket, head) => void } }
//   SIDE_EFFECTS: none
//   LINKS: M-PROXY
// END_CONTRACT: createConnectHandler
export function createConnectHandler(cfg, allow, auth, log) {
  let activeTunnels = 0;

  const rejectHttp = (socket, code, message) => {
    socket.write(`HTTP/1.1 ${code} ${message}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n`);
    socket.destroy();
  };

  // START_BLOCK_REJECT_HTTP
  const handleHttpOther = (socket, head) => {
    // Plain-HTTP forwarding is out of scope (UC-004): only CONNECT tunnels.
    log("reject_http", "UC-4", socket.remoteAddress, head.subarray(0, 16).toString("latin1"));
    rejectHttp(socket, 405, "Method Not Allowed");
  };
  // END_BLOCK_REJECT_HTTP

  // START_BLOCK_HANDLE_CONNECT
  const handleConnect = (socket, head) => {
    const parsed = parseConnectRequest(head);
    if (parsed === null) {
      rejectHttp(socket, 400, "Bad Request");
      return;
    }
    if (parsed.incomplete) {
      // Wait for the rest of the CONNECT header block.
      const onData = (chunk) => {
        head = Buffer.concat([head, chunk]);
        if (head.length > MAX_HEADER_BYTES) {
          socket.removeListener("data", onData);
          rejectHttp(socket, 400, "Bad Request");
          return;
        }
        const re = parseConnectRequest(head);
        if (re === null) {
          socket.removeListener("data", onData);
          rejectHttp(socket, 400, "Bad Request");
        } else if (!re.incomplete) {
          socket.removeListener("data", onData);
          finishConnect(socket, re, head);
        }
      };
      socket.on("data", onData);
      return;
    }
    finishConnect(socket, parsed, head);
  };

  const finishConnect = (socket, parsed, head) => {
    const target = parsed.target;

    // DF-1 step 2: authentication (UC-005)
    if (!auth(parsed.proxyAuth)) {
      log("auth_fail", "DF-1", socket.remoteAddress, target);
      socket.write(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
      );
      socket.destroy();
      return;
    }

    // DF-1 step 4: allowlist (UC-002)
    if (!allow(target)) {
      log("deny", "DF-1", socket.remoteAddress, target);
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    // DF-4: capacity limit (UC-003)
    if (activeTunnels >= cfg.maxTunnels) {
      log("cap_limit", "DF-4", socket.remoteAddress, target, { active: activeTunnels });
      socket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
      socket.destroy();
      return;
    }

    const [host, portStr] = target.split(":");
    const port = Number(portStr);

    // DF-1 step 6: open upstream connection
    const upstream = net.connect({ host, port });
    upstream.setTimeout(UPSTREAM_CONNECT_TIMEOUT_MS, () => {
      upstream.destroy(new Error("upstream connect timeout"));
    });

    upstream.once("connect", () => {
      upstream.setTimeout(0);
      activeTunnels += 1;
      log("connect", "DF-1", socket.remoteAddress, `${host}:${port}`);
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      openTunnel({
        clientSocket: socket,
        upstream,
        target: { host, port },
        cfg,
        log,
        onClose: () => {
          activeTunnels -= 1;
        },
      });
      // Forward any bytes pipelined after the CONNECT header block.
      const rest = head.subarray(parsed.headerLen);
      if (rest.length > 0) {
        upstream.write(rest);
      }
    });

    upstream.once("error", (err) => {
      log("upstream_error", "DF-1", `${host}:${port}`, err.code || err.message);
      socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      socket.destroy();
    });

    socket.once("error", () => {
      upstream.destroy();
    });
    // END_BLOCK_HANDLE_CONNECT
  };

  return {
    "http-connect": handleConnect,
    "http-other": handleHttpOther,
  };
}

// START_CONTRACT: start
//   PURPOSE: Listen on cfg.port and install graceful shutdown for SIGTERM/SIGINT
//   INPUTS: { server: net.Server, cfg: Config, log: Log }
//   OUTPUTS: { Promise<void> - resolves after server closes }
//   SIDE_EFFECTS: opens listening socket, registers signal handlers
//   LINKS: M-PROXY
// END_CONTRACT: start
export async function start(server, cfg, log) {
  server.listen(cfg.port, cfg.host, () => {
    log("listen", "start", `http://${cfg.host}:${cfg.port}`);
  });

  const shutdown = () => {
    // START_BLOCK_SHUTDOWN
    log("shutdown", "start", "closing");
    server.close(() => {
      process.exit(0);
    });
    // Force-exit if connections hang after grace period.
    setTimeout(() => process.exit(0), 5000).unref();
    // END_BLOCK_SHUTDOWN
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  await new Promise((resolve) => server.once("close", resolve));
}
