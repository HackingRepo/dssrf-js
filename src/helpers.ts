//! This module is an internal module, not intended to be imported all public apis in utils

import * as ipaddr from "ipaddr.js";
import CIDR from "ip-cidr";
const got = require("got").default;
const DEBUG = false;
const DSSRF_MAKE_REQUEST = process.env.DSSRF_MAKE_REQUEST;


/// This is a helper function used by dssrf for block ipv6 address
export function is_ipv6(ip: string): boolean {
    try {
        return ipaddr.IPv6.isValid(ip);
    } catch (e) {
        return false;
    }
}


const BAD_RANGE_USED_IN_SSRF: CIDR[] = [
    new CIDR("0.0.0.0/8"),
    new CIDR("10.0.0.0/8"),
    new CIDR("127.0.0.0/8"),
    new CIDR("169.254.0.0/16"),
    new CIDR("172.16.0.0/12"),
    new CIDR("192.168.0.0/16"),
    new CIDR("100.64.0.0/10"),
    new CIDR("192.0.0.0/24"),
    new CIDR("192.0.2.0/24"),
    new CIDR("198.18.0.0/15"),
    new CIDR("198.51.100.0/24"),
    new CIDR("203.0.113.0/24"),
    new CIDR("224.0.0.0/4"),
    new CIDR("240.0.0.0/4"),
];

function compareIPs(a: ipaddr.IPv4 | ipaddr.IPv6, b: ipaddr.IPv4 | ipaddr.IPv6): number {
    const ab = a.toByteArray();
    const bb = b.toByteArray();

    for (let i = 0; i < ab.length; i++) {
        if (ab[i] < bb[i]) return -1;
        if (ab[i] > bb[i]) return 1;
    }
    return 0;
}




export function is_range_not_internal(ipr: CIDR): boolean {
    const start = ipaddr.parse(ipr.start());
    const end = ipaddr.parse(ipr.end());

    for (const bad of BAD_RANGE_USED_IN_SSRF) {
        const badStart = ipaddr.parse(bad.start());
        const badEnd = ipaddr.parse(bad.end());

        const overlaps =
            compareIPs(start, badEnd) <= 0 &&
            compareIPs(end, badStart) >= 0;

        if (overlaps) {
            return false;
        }
    }

    return true;
}

/// An internal helper to convert octal ip to normal ip
export function octal_ip_to_normal_ip(octal: string) {
    const parts = octal.split(".");

    if (parts.length !== 4) {
        throw new Error("Invalid IPv4 address format.");
    }

    const decimalParts = parts.map((part) => {
        if (part.length === 0) {
            throw new Error("Invalid empty octet");
        }

        if (!/^[0-7]+$/.test(part)) {
            throw new Error(`Invalid octal digit in '${part}'`);
        }

        const value = parseInt(part, 8);

        if (value < 0 || value > 255) {
            throw new Error(`Octet out of range after conversion: '${part}' -> ${value}`);
        }

        return String(value);
    });

    return decimalParts.join(".");
}

/// An internal helper to convert hex ip to normal ip
export function hex_ip_to_normal_ip(hex: string): string {
    const cleaned = hex.toLowerCase().startsWith("0x")
        ? hex.slice(2)
        : hex;


    if (!/^[0-9a-f]{8}$/.test(cleaned)) {
        throw new Error(`Invalid hex IPv4 address: '${hex}'`);
    }

    const num = parseInt(cleaned, 16);

    const o1 = (num >> 24) & 0xFF;
    const o2 = (num >> 16) & 0xFF;
    const o3 = (num >> 8) & 0xFF;
    const o4 = num & 0xFF;

    return `${o1}.${o2}.${o3}.${o4}`;

}



/// An internal helper to convert bin ip to normal ip
export function bin_ip_to_normal_ip(bin: string): string {
    let cleaned = bin.trim();

    if (cleaned.toLowerCase().startsWith("0b")) {
        cleaned = cleaned.slice(2);
    }

    if (cleaned.includes(".")) {
        const parts = cleaned.split(".");
        if (parts.length !== 4) {
            throw new Error(`Invalid binary IPv4 address: '${bin}'`);
        }

        const octets = parts.map(p => {
            if (!/^[01]{8}$/.test(p)) {
                throw new Error(`Invalid binary IPv4 octet: '${p}' in '${bin}'`);
            }
            return parseInt(p, 2);
        });

        return `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}`;
    }

    if (!/^[01]{32}$/.test(cleaned)) {
        throw new Error(`Invalid binary IPv4 address: '${bin}'`);
    }

    const num = parseInt(cleaned, 2);

    const o1 = (num >> 24) & 0xFF;
    const o2 = (num >> 16) & 0xFF;
    const o3 = (num >> 8) & 0xFF;
    const o4 = num & 0xFF;

    return `${o1}.${o2}.${o3}.${o4}`;
}


/// An internal helper to convert decimal ip to normal ip
export function decimal_ip_to_normal_ip(decimal: string): string {
    if (!/^\d+$/.test(decimal)) {
        throw new Error(`Invalid decimal IPv4: '${decimal}'`);
    }

    const num = Number(decimal);

    if (!Number.isInteger(num) || num < 0 || num > 0xFFFFFFFF) {
        throw new Error(`Decimal IPv4 out of range: '${decimal}'`);
    }

    const a = (num >>> 24) & 0xFF;
    const b = (num >>> 16) & 0xFF;
    const c = (num >>> 8) & 0xFF;
    const d = num & 0xFF;

    return `${a}.${b}.${c}.${d}`;
}


interface IPv6WithMethods extends ipaddr.IPv6 {
    isLoopback(): boolean;
    isIPv4MappedAddress(): boolean;
    toIPv4Address(): ipaddr.IPv4;
}



export function normalize_ipv4(ip: string): string {
    const trimmed = ip.trim();

    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
        throw new Error(`Unsupported IPv4 encoding: '${ip}'`);
    }

    const parts = trimmed.split(".");
    const normalizedParts: string[] = [];

    for (const part of parts) {
        if (!/^\d+$/.test(part)) {
            throw new Error(`Invalid IPv4 octet: '${part}' in '${ip}'`);
        }

        if (part.length > 1 && part.startsWith("0")) {
            throw new Error(`IPv4 octet with leading zeros is not allowed: '${part}' in '${ip}'`);
        }

        const value = Number(part);
        if (value < 0 || value > 255) {
            throw new Error(`IPv4 octet out of range: '${part}' in '${ip}'`);
        }

        normalizedParts.push(String(value));
    }

    return normalizedParts.join(".");
}



export function is_ip_internal(ip: string): boolean {
    if (!ipaddr.isValid(ip)) return false;

    const parsed = ipaddr.parse(ip);

    if (parsed.kind() === "ipv4") {
        return parsed.range() !== "unicast";
    }

    if (parsed.kind() === "ipv6") {
        const range = parsed.range();
        return (
            range === "loopback" ||
            range === "linkLocal" ||
            range === "uniqueLocal"
        );
    }

    return false;
}




import { promises as dns } from "dns";

async function resolve_all_records(host: string) {
    const A = await dns.resolve4(host).catch(() => []);
    const AAAA = await dns.resolve6(host).catch(() => []);
    const CNAME = await dns.resolveCname(host).catch(() => []);

    return {
        A,
        AAAA,
        CNAME
    };
}






function classify_ips_allow_global_ipv6(ips: string[]): boolean {
    for (const ip of ips) {
        if (!ipaddr.isValid(ip)) continue;

        const parsed = ipaddr.parse(ip);

        if (parsed.kind() === "ipv6") {
            if (is_ip_internal(parsed.toString())) return true;
            continue;
        }

        if (is_ip_internal(parsed.toString())) return true;
    }
    return false;
}





/// Fixed dns rebinding protection timing window to be strong against complex dns rebinding attacks
export async function is_hostname_resolve_to_internal_ip(hostname: string): Promise<boolean> {
    const host = hostname.trim();

    // Direct IP check
    if (ipaddr.isValid(host)) {
        const parsed = ipaddr.parse(host);
        return is_ip_internal(parsed.toString());
    }

    // Helper to resolve with retries
    async function resolveWithDelay(host: string, attempts: number): Promise<string[]> {
        const results: string[][] = [];
        for (let i = 0; i < attempts; i++) {
            const r = await resolve_all_records(host);
            const ips = [...r.A, ...r.AAAA];
            results.push(ips);

            if (i < attempts - 1) {
                const delay = 100 + Math.floor(Math.random() * 200);
                await new Promise(r => setTimeout(r, delay));
            }
        }
        return results.flat();
    }

    const ips1 = await resolveWithDelay(host, 2);

    if (ips1.length === 0) return false;
    if (classify_ips_allow_global_ipv6(ips1)) return true;

    // Re‑resolve with adaptive strategy
    const ips2 = await resolveWithDelay(host, 2);

    if (ips2.length === 0) return false;
    if (classify_ips_allow_global_ipv6(ips2)) return true;

    // Compare sets to detect rebinding
    const set1 = new Set(ips1);
    const set2 = new Set(ips2);

    const changed = (
        set1.size !== set2.size ||
        [...set1].some(ip => !set2.has(ip))
    );

    if (changed) {
        if (classify_ips_allow_global_ipv6([...set1, ...set2])) {
            return true;
        }
    }

    // Check CNAME records across both resolutions
    const r1 = await resolve_all_records(host);
    const r2 = await resolve_all_records(host);
    for (const cname of [...r1.CNAME, ...r2.CNAME]) {
        if (ipaddr.isValid(cname)) {
            const parsed = ipaddr.parse(cname);
            if (is_ip_internal(parsed.toString())) return true;
        }
    }

    return false;
}





export function replace_backslash_with_slash_in_string(s: string): string {
    if (!s) return "";

    let u = s.replace(/\\/g, "/");

    u = u.replace(/([^:])\/{2,}/g, "$1/");

    return u;
}


export function remove_at_symbol_in_string(s: string): string {
    return s.replace(/@/g, "");
}

export function normalize_schema(u: string): string {
    try {
        const parsed = new URL(u);
        return parsed.protocol;
    } catch {
        return "";
    }
}



export function replace_two_slashes_url_to_normal_url(url: string): string {
    if (!url) return "";

    let u = url.trim();

    if (u.startsWith("//")) {
        return "http:" + u;
    }

    u = u.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/(?!\/)/, "$1://");

    u = u.replace(/([^:])\/{2,}/g, "$1/");

    return u;
}



const ALLOWED_PROTOCOLS: string[] = [
    "https",
    "http"
];

export function is_proto_safe(url: string): boolean {
    if (!url) return false;

    const u = url.trim().toLowerCase();

    const match = u.match(/^([a-z0-9+.-]+):/);
    if (!match) {
        return false;
    }

    const scheme = match[1];

    if (!ALLOWED_PROTOCOLS.includes(scheme)) {
        return false;
    }

    if (scheme === "http") return true;
    if (scheme === "https") return true;

    return false;
}



export async function is_redirect_safe(url: string): Promise<boolean> {
  try {
    let normalized = replace_backslash_with_slash_in_string(url);
    normalized = remove_at_symbol_in_string(normalized);

    let current = new URL(normalized);

    const MAX_REDIRECTS = 5;
    for (let i = 0; i < MAX_REDIRECTS; i++) {
      if (!is_proto_safe(current.protocol)) return false;
      if (await is_hostname_resolve_to_internal_ip(current.hostname)) return false;

      const res = await got(current.toString(), {
        method: "HEAD",
        followRedirect: false,
        throwHttpErrors: false,
        timeout: { request: 3000 }
      });

      const loc = res.headers.location;
      if (!loc) {
        return true;
      }

      try {
        current = new URL(loc, current.toString());
      } catch {
        return false;
      }
    }

    return false;
  } catch {
    return false;
  }
}










export function normalize_unicode(input: string): string {
    if (!input) return "";
    return input.normalize("NFKC");
}



export async function is_url_safe(url: string): Promise<boolean> {
  try {
    let u = normalize_unicode(url);

    u = replace_backslash_with_slash_in_string(u);
    u = replace_two_slashes_url_to_normal_url(u);
    u = remove_at_symbol_in_string(u);

    const schema = normalize_schema(u);
    if (!is_proto_safe(schema)) return false;

    const parsed = new URL(u);
    const hostname = parsed.hostname;

    // IPv4 validation
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      try {
        normalize_ipv4(hostname);
      } catch {
        return false;
      }
    }

    if (is_ipv6(hostname)) {
      if (is_ip_internal(hostname)) return false;
    }

    if (await is_hostname_resolve_to_internal_ip(hostname)) return false;

    if (process.env.DSSRF_CHECK_REDIRECTS === "1") {
      const redirectSafe = await is_redirect_safe(u);
      if (!redirectSafe) return false;
    }

    return true;
  } catch {
    return false;
  }
}


/// FIXME(): The debug version do not match is_url_safe, We'wll fix it later but for now keep it as is.
export async function is_url_safe_debug(url: string): Promise<boolean> { try { console.log("STEP 1 input:", url); let u = normalize_unicode(url); console.log("STEP 2 unicode:", u); u = replace_backslash_with_slash_in_string(u); console.log("STEP 3 slashes:", u); u = replace_two_slashes_url_to_normal_url(u); console.log("STEP 4 normalize slashes:", u); u = remove_at_symbol_in_string(u); console.log("STEP 5 remove @:", u); const schema = normalize_schema(u); if (!is_proto_safe(schema)) return false; console.log("STEP 6 schema:", schema); if (!is_proto_safe(u)) { console.log("STEP 7 proto unsafe"); return false; } console.log("STEP 7 proto safe"); const parsed = new URL(u); const hostname = parsed.hostname; console.log("STEP 8 hostname:", hostname); if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { try { normalize_ipv4(hostname); } catch { console.log("STEP 9 ipv4 invalid"); return false; } } if (is_ipv6(hostname)) { if (is_ip_internal(hostname)) { console.log("STEP 10 ipv6 internal"); return false; } } const isInternal = await is_hostname_resolve_to_internal_ip(hostname); console.log("STEP 11 internal?", isInternal); if (isInternal) { return false; } const redirectSafe = await is_redirect_safe(u); console.log("STEP 12 redirect safe?", redirectSafe); if (!redirectSafe) { return false; } console.log("STEP 13 final: true"); return true; } catch (e) { console.log("ERROR:", e); return false; } }


