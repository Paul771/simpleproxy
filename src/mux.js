// FILE: src/mux.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Protocol multiplexer: single net.Server routes connections to HTTP CONNECT or MTProto handlers
//   SCOPE: peek first bytes, classify protocol, hand off with buffered head
//   DEPENDS: none (handlers injected)
//   LINKS: M-MUX
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createMuxServer - net.Server that routes by first bytes to handlers
//   classifyProtocol - decide HTTP vs MTProto from the initial bytes
// END_MODULE_MAP

import net from "node:net";

const PEEK_LEN = 8; // "CONNECT " is 8 bytes; MTProto handshakes are 64 bytes
const PEEK_TIMEOUT_MS = 10_000;

// HTTP methods we recognize to reject plain-HTTP with 405 (same as before).
const HTTP_METHODS = new Set(["GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"]);

// START_CONTRACT: classifyProtocol
//   PURPOSE: Classify the first bytes of a connection as HTTP CONNECT, other HTTP, or MTProto
//   INPUTS: { head: Buffer - first bytes of the connection }
//   OUTPUTS: { "http-connect" | "http-other" | "mtproto" }
//   SIDE_EFFECTS: none
//   LINKS: M-MUX
// END_CONTRACT: classifyProtocol
export function classifyProtocol(head) {
  // START_BLOCK_CLASSIFY
  if (head.length >= 8 && head.subarray(0, 8).toString("latin1") === "CONNECT ") {
    return "http-connect";
  }
  if (head.length >= 4) {
    const method = head.subarray(0, 4).toString("latin1").trimEnd();
    if (HTTP_METHODS.has(method) && head[method.length] === 0x20) {
      return "http-other";
    }
  }
  // Everything else is treated as MTProto. Real MTProto nonces never start with an
  // HTTP method (reserved prefixes), so this cannot misroute a valid client.
  return "mtproto";
  // END_BLOCK_CLASSIFY
}

// START_CONTRACT: createMuxServer
//   PURPOSE: Create a net.Server that reads the first bytes and routes to protocol handlers
//   INPUTS: { handlers: { "http-connect": (socket, head) => void, "http-other": (socket, head) => void,
//                         "mtproto": (socket, head) => void } }
//   OUTPUTS: { net.Server }
//   SIDE_EFFECTS: registers 'connection' listener
//   LINKS: M-MUX
// END_CONTRACT: createMuxServer
export function createMuxServer(handlers) {
  const server = net.createServer((socket) => {
    // START_BLOCK_PEEK
    let head = Buffer.alloc(0);
    let routed = false;

    const onData = (chunk) => {
      head = Buffer.concat([head, chunk]);
      if (routed || head.length < PEEK_LEN) return;

      routed = true;
      socket.pause();
      socket.removeListener("data", onData);
      clearTimeout(timer);

      const proto = classifyProtocol(head);
      const handler = handlers[proto];
      if (!handler) {
        socket.destroy();
        return;
      }
      // Hand off with the buffered head; handler owns the socket from here.
      handler(socket, head);
      socket.resume();
    };

    const timer = setTimeout(() => {
      socket.removeListener("data", onData);
      socket.destroy();
    }, PEEK_TIMEOUT_MS);
    timer.unref?.();

    socket.on("data", onData);
    socket.on("error", () => socket.destroy());
    // END_BLOCK_PEEK
  });
  return server;
}
