// FILE: src/mask.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Traffic masking: transparent TCP-splice of non-keyed/unknown-SNI clients to a real web server
//   SCOPE: connect to mask_host, forward buffered ClientHello, bidirectional splice with idle timer
//   DEPENDS: M-LOG
//   LINKS: M-MASK
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   maskConnection - splice a client socket (with buffered head) to mask_host:mask_port
// END_MODULE_MAP

import net from "node:net";

const MASK_CONNECT_TIMEOUT_MS = 10_000;

// Re-export SNI extraction so callers depend on M-MASK for the full masking surface.
export { extractSni } from "./faketls.js";

// START_CONTRACT: maskConnection
//   PURPOSE: Transparently splice a client to the configured mask upstream (real web server)
//   INPUTS: { opts: { clientSocket, head: Buffer, cfg, log, onOpen?: () => void, onClose?: () => void,
//                     capacity?: { active, max, onOver } } }
//   OUTPUTS: { void }
//   SIDE_EFFECTS: opens an upstream TCP connection; wires bidirectional pump; destroys both on end/error
//   LINKS: M-MASK
// END_CONTRACT: maskConnection
export function maskConnection({ clientSocket, head, cfg, log, onOpen = () => {}, onClose = () => {} }) {
  // START_BLOCK_MASK_CONNECT
  const host = cfg.mtprotoMaskHost;
  const port = cfg.mtprotoMaskPort || 443;

  const upstream = net.connect({ host, port });
  upstream.setTimeout(MASK_CONNECT_TIMEOUT_MS, () => {
    upstream.destroy(new Error("mask upstream connect timeout"));
  });

  let active = false;
  const teardown = (reason) => {
    if (active) return;
    active = true;
    upstream.destroy();
    clientSocket.destroy();
    onClose();
    log("mask_close", "DF-MASK", host, port, reason ? { reason } : undefined);
  };

  upstream.once("connect", () => {
    upstream.setTimeout(0);
    log("mask_connect", "DF-MASK", clientSocket.remoteAddress, `${host}:${port}`);
    onOpen();
    // Forward the buffered ClientHello (and any pipelined bytes) to the real server first.
    if (head.length > 0) upstream.write(head);
  });

  upstream.once("error", (err) => {
    log("mask_upstream_error", "DF-MASK", `${host}:${port}`, err.code || err.message);
    teardown("upstream_error");
  });

  // If the client closes before the upstream connects, abort the connect attempt.
  clientSocket.once("close", () => teardown("client_close"));
  clientSocket.once("error", () => teardown("client_error"));

  // Bidirectional splice with an idle timer (mirrors M-TUNNEL semantics, distinct markers).
  let idleTimer = null;
  const armIdle = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => teardown("idle_timeout"), cfg.idleTimeoutMs);
    if (typeof idleTimer.unref === "function") idleTimer.unref();
  };
  armIdle();

  upstream.on("data", (chunk) => {
    armIdle();
    if (!clientSocket.destroyed) clientSocket.write(chunk);
  });
  clientSocket.on("data", (chunk) => {
    armIdle();
    if (!upstream.destroyed) upstream.write(chunk);
  });
  upstream.on("end", () => {
    if (!clientSocket.destroyed) clientSocket.end();
  });
  clientSocket.on("end", () => {
    if (!upstream.destroyed) upstream.end();
  });
  upstream.on("close", () => teardown("upstream_close"));
  upstream.on("error", () => {});
  clientSocket.on("error", () => {});
  // END_BLOCK_MASK_CONNECT
}