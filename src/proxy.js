// FILE: src/proxy.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: HTTP server: CONNECT handling (auth -> allow -> cap -> tunnel), reject plain HTTP, graceful start
//   SCOPE: connect event handling, request rejection, tunnel capacity tracking, server lifecycle
//   DEPENDS: M-CONFIG, M-ALLOW, M-AUTH, M-TUNNEL, M-LOG
//   LINKS: M-PROXY
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createProxy - create http.Server with connect/request handlers
//   start - listen and handle SIGTERM/SIGINT gracefully
// END_MODULE_MAP

import http from "node:http";
import net from "node:net";
import { openTunnel } from "./tunnel.js";

const UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;

// START_BLOCK_REJECT
function reject(res, code, message) {
  res.writeHead(code, { "Content-Type": "text/plain" });
  res.end(message + "\n");
}
// END_BLOCK_REJECT

// START_CONTRACT: createProxy
//   PURPOSE: Create an http.Server wired to CONNECT and plain-HTTP handlers
//   INPUTS: { cfg: Config, allow: (t: Target) => boolean, auth: (h?: string) => boolean, log: Log }
//   OUTPUTS: { http.Server }
//   SIDE_EFFECTS: none (server not listening until start())
//   LINKS: M-PROXY
// END_CONTRACT: createProxy
export function createProxy(cfg, allow, auth, log) {
  let activeTunnels = 0;

  const server = http.createServer((req, res) => {
    // START_BLOCK_REJECT_HTTP
    // Plain-HTTP forwarding is out of scope (UC-004): only CONNECT tunnels.
    log("reject_http", "UC-4", req.method, req.url);
    reject(res, 405, "Method Not Allowed");
    // END_BLOCK_REJECT_HTTP
  });

  server.on("connect", (req, clientSocket, head) => {
    // START_BLOCK_HANDLE_CONNECT
    const target = req.url;

    // DF-1 step 2: authentication (UC-005)
    if (!auth(req.headers["proxy-authorization"])) {
      log("auth_fail", "DF-1", clientSocket.remoteAddress, target);
      clientSocket.write(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n"
      );
      clientSocket.destroy();
      return;
    }

    // DF-1 step 4: allowlist (UC-002)
    if (!allow(target)) {
      log("deny", "DF-1", clientSocket.remoteAddress, target);
      clientSocket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      clientSocket.destroy();
      return;
    }

    // DF-4: capacity limit (UC-003)
    if (activeTunnels >= cfg.maxTunnels) {
      log("cap_limit", "DF-4", clientSocket.remoteAddress, target, { active: activeTunnels });
      clientSocket.write("HTTP/1.1 503 Service Unavailable\r\n\r\n");
      clientSocket.destroy();
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
      log("connect", "DF-1", clientSocket.remoteAddress, `${host}:${port}`);
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      openTunnel({
        clientSocket,
        upstream,
        target: { host, port },
        cfg,
        log,
        onClose: () => {
          activeTunnels -= 1;
        },
      });
      if (head && head.length > 0) {
        upstream.write(head);
      }
    });

    upstream.once("error", (err) => {
      log("upstream_error", "DF-1", `${host}:${port}`, err.code || err.message);
      clientSocket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      clientSocket.destroy();
    });

    clientSocket.once("error", () => {
      upstream.destroy();
    });
    // END_BLOCK_HANDLE_CONNECT
  });

  server.on("clientError", (err, socket) => {
    // START_BLOCK_CLIENT_ERROR
    if (err.code === "ECONNRESET") return;
    socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    // END_BLOCK_CLIENT_ERROR
  });

  return server;
}

// START_CONTRACT: start
//   PURPOSE: Listen on cfg.port and install graceful shutdown for SIGTERM/SIGINT
//   INPUTS: { server: http.Server, cfg: Config, log: Log }
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
