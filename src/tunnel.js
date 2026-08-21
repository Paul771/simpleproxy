// FILE: src/tunnel.js
// VERSION: 1.2.0
// START_MODULE_CONTRACT
//   PURPOSE: Byte tunnel between client and upstream sockets with byte counters and idle timer
//   SCOPE: bidirectional piping, idle timeout, socket error handling, close accounting
//   DEPENDS: M-LOG
//   LINKS: M-TUNNEL
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   openTunnel - start bidirectional pump for an established tunnel
// END_MODULE_MAP
//
// START_CHANGE_SUMMARY
//   LAST_CHANGE: v1.2.0 - single 'drain' listener per pump direction (paused guards):
//                bursts of failing writes no longer stack listeners on the sockets
// END_CHANGE_SUMMARY

// START_CONTRACT: openTunnel
//   PURPOSE: Pipe data both ways, track bytes, reset idle timer on any data, tear down on close/error
//   INPUTS: { opts: { clientSocket, upstream, target, cfg, log, onClose, metrics? } }
//   OUTPUTS: { void }
//   SIDE_EFFECTS: wires socket event handlers; destroys both sockets on termination
//   LINKS: M-TUNNEL
// END_CONTRACT: openTunnel
export function openTunnel({ clientSocket, upstream, target, cfg, log, onClose = () => {}, metrics = null }) {
  let bytesIn = 0; // client -> upstream
  let bytesOut = 0; // upstream -> client
  const startedAt = Date.now();

  // START_BLOCK_IDLE_TIMER
  let idleTimer = null;
  const armIdle = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      log("idle_timeout", "DF-3", target.host, target.port, cfg.idleTimeoutMs);
      clientSocket.destroy();
      upstream.destroy();
    }, cfg.idleTimeoutMs);
    if (typeof idleTimer.unref === "function") idleTimer.unref();
  };
  const resetIdle = () => {
    if (idleTimer) armIdle();
  };
  armIdle();
  // END_BLOCK_IDLE_TIMER

  let tornDown = false;
  const teardown = () => {
    // START_BLOCK_TEARDOWN
    if (tornDown) return;
    tornDown = true;
    clearTimeout(idleTimer);
    onClose();
    log("close", "DF-2", target.host, target.port, {
      bytes_in: bytesIn,
      bytes_out: bytesOut,
      duration_ms: Date.now() - startedAt,
    });
    // END_BLOCK_TEARDOWN
  };

  // START_BLOCK_PUMP
  // Backpressure: pause the source socket when the destination's write buffer is
  // full, resume on 'drain' — bounds buffering during large transfers.
  // Paused guards: keep at most one 'drain' listener per direction (a burst of
  // failing writes in one tick must not stack listeners on the socket).
  let upstreamPaused = false;
  clientSocket.on("data", (chunk) => {
    bytesIn += chunk.length;
    if (metrics) metrics.inc("simpleproxy_bytes_in_total", chunk.length);
    resetIdle();
    const ok = upstream.write(chunk);
    if (!ok && !upstreamPaused) {
      upstreamPaused = true;
      clientSocket.pause();
      upstream.once("drain", () => {
        upstreamPaused = false;
        clientSocket.resume();
      });
    }
  });

  let clientPaused = false;
  upstream.on("data", (chunk) => {
    bytesOut += chunk.length;
    if (metrics) metrics.inc("simpleproxy_bytes_out_total", chunk.length);
    resetIdle();
    const ok = clientSocket.write(chunk);
    if (!ok && !clientPaused) {
      clientPaused = true;
      upstream.pause();
      clientSocket.once("drain", () => {
        clientPaused = false;
        upstream.resume();
      });
    }
  });

  const onClientEnd = () => {
    upstream.end();
  };
  const onUpstreamEnd = () => {
    clientSocket.end();
  };

  clientSocket.on("end", onClientEnd);
  upstream.on("end", onUpstreamEnd);

  // No-op error handlers: never crash the process on ECONNRESET etc.
  clientSocket.on("error", () => {});
  upstream.on("error", () => {});

  const finish = () => teardown();
  clientSocket.on("close", finish);
  upstream.on("close", finish);
  // END_BLOCK_PUMP
}
