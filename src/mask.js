// FILE: src/mask.js
// VERSION: 1.1.0
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
//
// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.1.0 - bounded masked sessions: total relayed bytes capped via
//                cfg.mtprotoMaskRelayMaxBytes (teardown reason "mask_relay_cap"; 0 = off)
//   v1.0.1 - abort upstream without splicing if the client is already gone
// END_CHANGE_SUMMARY

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

  if (clientSocket.destroyed) {
    onClose();
    log("mask_close", "DF-MASK", host, port, { reason: "client_close" });
    return;
  }

  const upstream = net.connect({ host, port });
  upstream.setTimeout(MASK_CONNECT_TIMEOUT_MS, () => {
    upstream.destroy(new Error("mask upstream connect timeout"));
  });

  let tornDown = false;
  let spliced = false;
  const teardown = (reason) => {
    if (tornDown) return;
    tornDown = true;
    upstream.destroy();
    if (!clientSocket.destroyed) clientSocket.destroy();
    onClose();
    log("mask_close", "DF-MASK", host, port, reason ? { reason } : undefined);
  };

  upstream.once("connect", () => {
    if (tornDown || clientSocket.destroyed) {
      upstream.destroy();
      return;
    }
    upstream.setTimeout(0);
    spliced = true;
    log("mask_connect", "DF-MASK", clientSocket.remoteAddress, `${host}:${port}`);
    onOpen();
    if (head.length > 0) upstream.write(head);
  });

  upstream.once("error", (err) => {
    log("mask_upstream_error", "DF-MASK", `${host}:${port}`, err.code || err.message);
    teardown("upstream_error");
  });

  clientSocket.once("close", () => {
    if (!spliced) {
      upstream.destroy();
    }
    teardown("client_close");
  });
  clientSocket.once("error", () => teardown("client_error"));

  // Bidirectional splice with an idle timer (mirrors M-TUNNEL semantics, distinct markers).
  let idleTimer = null;
  const armIdle = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => teardown("idle_timeout"), cfg.idleTimeoutMs);
    if (typeof idleTimer.unref === "function") idleTimer.unref();
  };
  armIdle();

  // START_BLOCK_MASK_RELAY_CAP
  // Total byte cap for the masked session (both directions combined). Non-keyed
  // clients are unauthenticated, so their relayed traffic must be bounded — a long
  // spliced session otherwise grows process memory for the benefit of a crawler
  // (telemt ships an analogous mask_relay_max_bytes default). 0 disables the cap.
  const maxBytes = cfg.mtprotoMaskRelayMaxBytes ?? 0;
  let relayBytes = 0;
  const chargeMaskBytes = (n) => {
    if (maxBytes <= 0) return true;
    relayBytes += n;
    if (relayBytes > maxBytes) {
      teardown("mask_relay_cap");
      return false;
    }
    return true;
  };
  // END_BLOCK_MASK_RELAY_CAP

  upstream.on("data", (chunk) => {
    armIdle();
    if (!chargeMaskBytes(chunk.length)) return;
    if (!clientSocket.destroyed) clientSocket.write(chunk);
  });
  clientSocket.on("data", (chunk) => {
    armIdle();
    if (!chargeMaskBytes(chunk.length)) return;
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