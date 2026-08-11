// FILE: src/allow.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Strict authority parser and allowlist check (pure logic, no IO)
//   SCOPE: parsing CONNECT authority, matching targets against rules
//   DEPENDS: none
//   LINKS: M-ALLOW
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   normalizeTarget - parse CONNECT authority into { host, port } or null
//   isAllowed - check a target against allowlist rules
// END_MODULE_MAP

const HOST_CHARS = /^[a-z0-9.-]+$/;

// START_CONTRACT: normalizeTarget
//   PURPOSE: Parse a CONNECT authority string ("host:port") into a normalized target
//   INPUTS: { raw: string - authority from req.url, e.g. "api.telegram.org:443" }
//   OUTPUTS: { Target | null - { host, port } or null when malformed }
//   SIDE_EFFECTS: none
//   LINKS: M-ALLOW
// END_CONTRACT: normalizeTarget
export function normalizeTarget(raw) {
  // START_BLOCK_PARSE_TARGET
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 255) return null;

  // Reject userinfo, extra colons, IPv6 brackets in non-allow positions.
  if (raw.includes("@")) return null;
  if (raw.startsWith("[") || raw.includes("]")) return null;
  if ((raw.match(/:/g) || []).length !== 1) return null;

  const idx = raw.lastIndexOf(":");
  if (idx <= 0 || idx === raw.length - 1) return null;

  const host = raw.slice(0, idx).toLowerCase();
  const portStr = raw.slice(idx + 1);

  // Lowercase + trailing-dot cleanup happens before charset check.
  if (!HOST_CHARS.test(host)) return null;
  if (!/^[0-9]+$/.test(portStr)) return null;

  const port = Number(portStr);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;

  return { host: host.replace(/\.$/, ""), port };
  // END_BLOCK_PARSE_TARGET
}

// START_CONTRACT: isAllowed
//   PURPOSE: Check a target against allowlist rules; port must be exactly 443
//   INPUTS: { target: Target, rules: Rule[] - [{ type: "exact"|"suffix", host }] }
//   OUTPUTS: { boolean - true when target matches a rule on port 443 }
//   SIDE_EFFECTS: none
//   LINKS: M-ALLOW
// END_CONTRACT: isAllowed
export function isAllowed(target, rules) {
  if (!target) return false;
  if (target.port !== 443) return false;

  return rules.some((rule) => {
    if (rule.type === "exact") return target.host === rule.host;
    if (rule.type === "suffix") return target.host.endsWith(rule.host);
    return false;
  });
}
