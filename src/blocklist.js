// FILE: src/blocklist.js
// VERSION: 1.0.0
// START_MODULE_CONTRACT
//   PURPOSE: Client-IP blocklist (IPv4/IPv6 CIDR + bare IP) for rejecting blocked clients at the edge
//   SCOPE: parse + validate entries, isBlocked(ip) with IPv4-mapped-IPv6 normalisation
//   DEPENDS: node:net (BlockList for family-aware CIDR matching)
//   LINKS: M-BLOCKLIST
//   ROLE: RUNTIME
//   MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
//
// START_MODULE_MAP
//   createBlocklist - validate entries and build an isBlocked(ip) predicate
// END_MODULE_MAP

import net from "node:net";

// START_CONTRACT: createBlocklist
//   PURPOSE: Build an isBlocked(ip) predicate from a list of CIDR / bare-IP entries
//   INPUTS: { entries: string[] - e.g. ["10.0.0.0/8", "192.168.1.5", "2001:db8::/32"] }
//   OUTPUTS: { isBlocked(ip: string|null|undefined): boolean }
//   SIDE_EFFECTS: none (pure predicate over precompiled rules)
//   LINKS: M-BLOCKLIST
// END_CONTRACT: createBlocklist
export function createBlocklist(entries = []) {
  // START_BLOCK_RULES
  // One BlockList per family — node:net.BlockList.check() needs the family argument for IPv6,
  // so we keep families separate and pass the family explicitly on every add/check.
  const v4 = new net.BlockList();
  const v6 = new net.BlockList();
  let v4Count = 0;
  let v6Count = 0;

  for (const raw of entries) {
    const entry = String(raw).trim();
    if (entry === "") throw new Error(`INVALID_ENV: MTPROTO_BLOCKLIST has an empty entry`);
    const slash = entry.indexOf("/");
    let ipPart = entry, prefix = null;
    if (slash !== -1) {
      ipPart = entry.slice(0, slash);
      const p = Number(entry.slice(slash + 1));
      if (!Number.isInteger(p) || p < 0) {
        throw new Error(`INVALID_ENV: MTPROTO_BLOCKLIST prefix must be a non-negative integer, got "${entry}"`);
      }
      prefix = p;
    }
    const fam = familyOf(ipPart);
    const maxPrefix = fam === "ipv6" ? 128 : 32;
    if (prefix !== null && prefix > maxPrefix) {
      throw new Error(`INVALID_ENV: MTPROTO_BLOCKLIST prefix /${prefix} exceeds ${fam} max /${maxPrefix}, got "${entry}"`);
    }
    const block = fam === "ipv6" ? v6 : v4;
    try {
      if (prefix !== null) block.addSubnet(ipPart, prefix, fam);
      else block.addAddress(ipPart, fam);
    } catch (err) {
      throw new Error(`INVALID_ENV: MTPROTO_BLOCKLIST entry "${entry}" is invalid (${err.message})`);
    }
    if (fam === "ipv6") v6Count += 1; else v4Count += 1;
  }

  const isBlocked = (ip) => {
    if (!ip || typeof ip !== "string") return false;
    const norm = stripV4Mapped(ip);
    const fam = familyOf(norm);
    if (fam === "ipv6") {
      return v6Count > 0 ? v6.check(norm, "ipv6") : false;
    }
    return v4Count > 0 ? v4.check(norm, "ipv4") : false;
  };

  return { isBlocked };
  // END_BLOCK_RULES
}

// Detect the address family so add/check pick the right parser.
function familyOf(ip) {
  return ip.includes(":") ? "ipv6" : "ipv4";
}

// Strip the IPv4-mapped IPv6 prefix "::ffff:" so a v4 rule matches a v4-in-v6 remote address.
function stripV4Mapped(ip) {
  const lower = ip.toLowerCase();
  if (lower.startsWith("::ffff:")) return ip.slice(7);
  return ip;
}