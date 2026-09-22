//! Internal module. The public surface is re-exported from utils.

import * as ipaddr from "ipaddr.js";
import { promises as dns } from "node:dns";
import * as net from "node:net";

// SSRF ranges list, includes no RFC, ones
const BAD_RANGE_USED_IN_SSRF: string[] = [
    "0.0.0.0/8",          // this network            RFC 1122
    "10.0.0.0/8",         // private                 RFC 1918
    "100.64.0.0/10",      // carrier-grade NAT       RFC 6598
    "127.0.0.0/8",        // loopback                RFC 1122
    "169.254.0.0/16",     // link-local + metadata   RFC 3927
    "172.16.0.0/12",      // private                 RFC 1918
    "192.0.0.0/24",       // IETF protocol assignm.  RFC 6890
    "192.0.2.0/24",       // TEST-NET-1              RFC 5737
    "192.31.196.0/24",    // AS112-v4                RFC 7535
    "192.52.193.0/24",    // AMT                     RFC 7450
    "192.88.99.0/24",     // 6to4 relay anycast      RFC 7526
    "192.168.0.0/16",     // private                 RFC 1918
    "192.175.48.0/24",    // direct delegation AS112 RFC 7534
    "198.18.0.0/15",      // benchmarking            RFC 2544
    "198.51.100.0/24",    // TEST-NET-2              RFC 5737
    "203.0.113.0/24",     // TEST-NET-3              RFC 5737
    "224.0.0.0/4",        // multicast               RFC 5771
    "240.0.0.0/4",        // reserved + broadcast    RFC 1112
    "168.63.129.16/32",   // Azure wire server
    "100.100.100.200/32", // Alibaba Cloud metadata
];

// Same as below but for IPv6
const BAD_RANGE_IPV6: string[] = [
    "64:ff9b:1::/48",     // NAT64 local-use         RFC 8215
    "5f00::/16",          // SRv6 SIDs               RFC 9602
    "3fff::/20",          // documentation           RFC 9637
    "fec0::/10",          // deprecated site-local
    "100::/64",           // discard-only            RFC 6666
];

const PARSED_BAD_V4 = BAD_RANGE_USED_IN_SSRF.map(c => ipaddr.parseCIDR(c));
const PARSED_BAD_V6 = BAD_RANGE_IPV6.map(c => ipaddr.parseCIDR(c));

/// This is a helper function used by dssrf for block ipv6 address
export function is_ipv6(ip: string): boolean {
    try {
        return ipaddr.IPv6.isValid(ip);
    } catch (e) {
        return false;
    }
}

/**
 * IPv4-mapped (`::ffff:0:0/96`) is the one IPv6 form that is a legitimate way
 * to write an IPv4 address, so it must classify as the address it carries.
 * Returns the address, or null.
 */
function mapped_ipv4(addr: ipaddr.IPv6): string | null {
    const b = addr.toByteArray();
    for (let i = 0; i < 10; i++) if (b[i] !== 0) return null;
    if (b[10] !== 0xff || b[11] !== 0xff) return null;
    return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
}

// Determines if a given IPv6 address belongs to a known transition mechanism.
function is_transition_prefix(addr: ipaddr.IPv6): boolean {
    const b = addr.toByteArray();
    const zero = (from: number, to: number) => {
        for (let i = from; i < to; i++) if (b[i] !== 0) return false;
        return true;
    };
    if (zero(0, 12)) return true;                                                     // ::/96           IPv4-compatible
    if (zero(0, 8) && b[8] === 0xff && b[9] === 0xff && zero(10, 12)) return true;     // ::ffff:0:0:0/96 RFC 6145
    if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return true; // 64:ff9b::/32    NAT64 (well-known + local-use)
    if (b[0] === 0x20 && b[1] === 0x02) return true;                                   // 2002::/16       6to4
    return false;
}

function matches(addr: ipaddr.IPv4 | ipaddr.IPv6, list: ReturnType<typeof ipaddr.parseCIDR>[]): boolean {
    for (const [range, bits] of list) {
        if (range.kind() !== addr.kind()) continue;
        try {
            // @ts-ignore - match() is family-checked above
            if (addr.match(range, bits)) return true;
        } catch { /* family mismatch */ }
    }
    return false;
}

// Check is a raw ip is internal or no
export function is_ip_internal(ip: string): boolean {
    let parsed: ipaddr.IPv4 | ipaddr.IPv6;
    try {
        if (!ipaddr.isValid(ip)) return true;   // unparseable, refuse
        parsed = ipaddr.parse(ip);
    } catch {
        return true;
    }

    if (parsed.kind() === "ipv6") {
        const v6 = parsed as ipaddr.IPv6;
        // IPv4-mapped is a real way to write an IPv4 address, classify it as one.
        const mapped = mapped_ipv4(v6);
        if (mapped !== null) return is_ip_internal(mapped);
        // Every other transition prefix is refused outright.
        if (is_transition_prefix(v6)) return true;
        if (v6.range() !== "unicast") return true;
        return matches(v6, PARSED_BAD_V6);
    }

    const v4 = parsed as ipaddr.IPv4;
    if (v4.range() !== "unicast") return true;
    return matches(v4, PARSED_BAD_V4);
}

// That function compares two ip addresses
function compareIPs(a: ipaddr.IPv4 | ipaddr.IPv6, b: ipaddr.IPv4 | ipaddr.IPv6): number {
    const ab = a.toByteArray();
    const bb = b.toByteArray();

    if (ab.length !== bb.length) return ab.length < bb.length ? -1 : 1;
    for (let i = 0; i < ab.length; i++) {
        if (ab[i] < bb[i]) return -1;
        if (ab[i] > bb[i]) return 1;
    }
    return 0;
}

interface CidrLike { start(): string; end(): string }

// Check an ip or cidr like object is not internal
export function is_range_not_internal(ipr: string | CidrLike): boolean {
    let startStr: string;
    let endStr: string;
    try {
        if (typeof ipr === "string") {
            const [addr, bits] = ipaddr.parseCIDR(ipr);
            const bytes = addr.toByteArray();
            const width = bytes.length * 8;
            const host = width - bits;
            const startB = bytes.slice();
            const endB = bytes.slice();
            for (let i = 0; i < host; i++) {
                const idx = bytes.length - 1 - (i >> 3);
                startB[idx] &= ~(1 << (i & 7)) & 0xff;
                endB[idx] |= (1 << (i & 7)) & 0xff;
            }
            const build = (arr: number[]) => (bytes.length === 4
                ? ipaddr.fromByteArray(arr).toString()
                : ipaddr.fromByteArray(arr).toString());
            startStr = build(startB);
            endStr = build(endB);
        } else {
            startStr = ipr.start();
            endStr = ipr.end();
        }
    } catch {
        return false;   // unparseable, treat as internal
    }

    let start: ipaddr.IPv4 | ipaddr.IPv6;
    let end: ipaddr.IPv4 | ipaddr.IPv6;
    try {
        start = ipaddr.parse(startStr);
        end = ipaddr.parse(endStr);
    } catch {
        return false;
    }

    const bad = start.kind() === "ipv4" ? BAD_RANGE_USED_IN_SSRF : BAD_RANGE_IPV6;
    for (const cidr of bad) {
        let badStart: ipaddr.IPv4 | ipaddr.IPv6;
        let badEnd: ipaddr.IPv4 | ipaddr.IPv6;
        try {
            const [a, bits] = ipaddr.parseCIDR(cidr);
            if (a.kind() !== start.kind()) continue;
            const bytes = a.toByteArray();
            const host = bytes.length * 8 - bits;
            const s = bytes.slice();
            const e = bytes.slice();
            for (let i = 0; i < host; i++) {
                const idx = bytes.length - 1 - (i >> 3);
                s[idx] &= ~(1 << (i & 7)) & 0xff;
                e[idx] |= (1 << (i & 7)) & 0xff;
            }
            badStart = ipaddr.fromByteArray(s);
            badEnd = ipaddr.fromByteArray(e);
        } catch { continue; }

        if (compareIPs(start, badEnd) <= 0 && compareIPs(end, badStart) >= 0) return false;
    }

    // A range of IPv6 unicast space still has to clear the per-address rules.
    if (start.kind() === "ipv6" && (is_ip_internal(startStr) || is_ip_internal(endStr))) return false;
    return true;
}

/// An internal helper to convert octal ip to normal ip
export function octal_ip_to_normal_ip(octal: string) {
    const parts = octal.split(".");
    if (parts.length !== 4) throw new Error("Invalid IPv4 address format.");
    const decimalParts = parts.map((part) => {
        if (part.length === 0) throw new Error("Invalid empty octet");
        if (!/^[0-7]+$/.test(part)) throw new Error(`Invalid octal digit in '${part}'`);
        const value = parseInt(part, 8);
        if (value < 0 || value > 255) throw new Error(`Octet out of range after conversion: '${part}' -> ${value}`);
        return String(value);
    });
    return decimalParts.join(".");
}

/// An internal helper to convert hex ip to normal ip
export function hex_ip_to_normal_ip(hex: string): string {
    const cleaned = hex.toLowerCase().startsWith("0x") ? hex.slice(2) : hex;
    if (!/^[0-9a-f]{8}$/.test(cleaned)) throw new Error(`Invalid hex IPv4 address: '${hex}'`);
    const num = parseInt(cleaned, 16);
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
}

/// An internal helper to convert bin ip to normal ip
export function bin_ip_to_normal_ip(bin: string): string {
    let cleaned = bin.trim();
    if (cleaned.toLowerCase().startsWith("0b")) cleaned = cleaned.slice(2);
    if (cleaned.includes(".")) {
        const parts = cleaned.split(".");
        if (parts.length !== 4) throw new Error(`Invalid binary IPv4 address: '${bin}'`);
        const octets = parts.map(p => {
            if (!/^[01]{8}$/.test(p)) throw new Error(`Invalid binary IPv4 octet: '${p}' in '${bin}'`);
            return parseInt(p, 2);
        });
        return `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}`;
    }
    if (!/^[01]{32}$/.test(cleaned)) throw new Error(`Invalid binary IPv4 address: '${bin}'`);
    const num = parseInt(cleaned, 2);
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
}

/// An internal helper to convert decimal ip to normal ip
export function decimal_ip_to_normal_ip(decimal: string): string {
    if (!/^\d+$/.test(decimal)) throw new Error(`Invalid decimal IPv4: '${decimal}'`);
    const num = Number(decimal);
    if (!Number.isInteger(num) || num < 0 || num > 0xFFFFFFFF) throw new Error(`Decimal IPv4 out of range: '${decimal}'`);
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
}

export function normalize_ipv4(ip: string): string {
    const trimmed = ip.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) throw new Error(`Unsupported IPv4 encoding: '${ip}'`);
    const parts = trimmed.split(".");
    const normalizedParts: string[] = [];
    for (const part of parts) {
        if (!/^\d+$/.test(part)) throw new Error(`Invalid IPv4 octet: '${part}' in '${ip}'`);
        if (part.length > 1 && part.startsWith("0")) {
            throw new Error(`IPv4 octet with leading zeros is not allowed: '${part}' in '${ip}'`);
        }
        const value = Number(part);
        if (value < 0 || value > 255) throw new Error(`IPv4 octet out of range: '${part}' in '${ip}'`);
        normalizedParts.push(String(value));
    }
    return normalizedParts.join(".");
}

/// Resolution type alias
export type Resolution =
    /** Addresses were observed. */
    | { kind: "addresses"; addresses: string[] }
    /** The name genuinely does not exist. A client would fail identically. */
    | { kind: "nxdomain" }
    /** The resolver could not answer. We do not know. */
    | { kind: "unknown"; code: string };

/// That function classifies a dns error, to nxdomain or unknown
function classifyDnsError(code: string | undefined): "nxdomain" | "unknown" {

    return code === "ENOTFOUND" || code === "EAI_NONAME" ? "nxdomain" : "unknown";
}


/// A function that resolves a hostname and returns a Resolution promise
export async function resolve_host(hostname: string): Promise<Resolution> {
    const host = hostname.trim();
    const errors: string[] = [];
    const push = (e: any) => { errors.push(e?.code || "UNKNOWN"); return [] as string[]; };

    const [lookup, a, aaaa] = await Promise.all([
        dns.lookup(host, { all: true }).then(r => r.map(e => e.address), push),
        dns.resolve4(host).catch(push),
        dns.resolve6(host).catch(push),
    ]);

    const addresses = [...new Set([...lookup, ...a, ...aaaa])];
    if (addresses.length > 0) return { kind: "addresses", addresses };

    // Every path failed. Only a genuine NXDOMAIN from every path is safe to
    // treat as "does not exist".
    const allNx = errors.length > 0 && errors.every(c => classifyDnsError(c) === "nxdomain");
    return allNx ? { kind: "nxdomain" } : { kind: "unknown", code: errors[0] || "UNKNOWN" };
}

/// Check is a hostname resolve to an internal ip
export async function is_hostname_resolve_to_internal_ip(hostname: string): Promise<boolean> {
    const host = hostname.trim();

    if (ipaddr.isValid(host)) return is_ip_internal(ipaddr.parse(host).toString());

    const res = await resolve_host(host);
    if (res.kind === "unknown") return true;      // could not check, refuse
    if (res.kind === "nxdomain") return false;    // does not exist, the fetch fails on its own
    return res.addresses.some(ip => is_ip_internal(ip));
}

/// Replace backslash with slash, in a string
export function replace_backslash_with_slash_in_string(s: string): string {
    if (!s) return "";
    let u = s.replace(/\\/g, "/");
    u = u.replace(/([^:])\/{2,}/g, "$1/");
    return u;
}

/// Remove at symbol in a string
export function remove_at_symbol_in_string(s: string): string {
    return s.replace(/@/g, "");
}

/// Normalizes a schema, if it cannot it returns nothing
export function normalize_schema(u: string): string {
    try {
        return new URL(u).protocol;
    } catch {
        return "";
    }
}

/// Replaces a two slashes url to a normal url
export function replace_two_slashes_url_to_normal_url(url: string): string {
    if (!url) return "";
    let u = url.trim();
    if (u.startsWith("//")) return "http:" + u;
    u = u.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/(?!\/)/, "$1://");
    u = u.replace(/([^:])\/{2,}/g, "$1/");
    return u;
}

/// Protocol whitelist list
const ALLOWED_PROTOCOLS: string[] = ["https", "http"];

/// Check is a proto safe, or no
export function is_proto_safe(url: string): boolean {
    if (!url) return false;
    const match = String(url).trim().toLowerCase().match(/^([a-z0-9+.-]+):/);
    return match ? ALLOWED_PROTOCOLS.includes(match[1]) : false;
}

/// Check is a hostname is ascii
function is_ascii_host(hostname: string): boolean {
    return /^[\x00-\x7F]*$/.test(hostname);
}

/// Parse the target url, if failed return null
export function parse_target(url: unknown): URL | null {
    // Only a string or a URL is a URL. Coercing anything else would turn
    // ["http://x"] into a real target and send us resolving it.
    if (url instanceof URL) return url;
    if (typeof url !== "string") return null;
    try {
        let u = replace_backslash_with_slash_in_string(url);
        u = replace_two_slashes_url_to_normal_url(u);
        return new URL(u);
    } catch {
        return null;
    }
}

/// Check is the parsed url safe, or no
async function is_parsed_url_safe(parsed: URL): Promise<boolean> {
    if (!is_proto_safe(parsed.protocol)) return false;
    if (parsed.username !== "" || parsed.password !== "") return false;
    // WHATWG URL includes brackets in .hostname for IPv6 (e.g. "[::1]"); strip them
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
    if (hostname === "") return false;
    if (!is_ascii_host(hostname)) return false;
    if (await is_hostname_resolve_to_internal_ip(hostname)) return false;
    return true;
}

/// An interface of a redirect, containing status and opentially a location
interface HeadResult { status: number; location?: string }

function probe(target: URL, method: string, timeoutMs: number): Promise<HeadResult> {
    return new Promise((resolve, reject) => {
        const mod = target.protocol === "https:" ? require("node:https") : require("node:http");
        const req = mod.request({
            protocol: target.protocol,
            hostname: target.hostname.replace(/^\[|\]$/g, ""),
            port: target.port || (target.protocol === "https:" ? 443 : 80),
            path: target.pathname + target.search,
            method,
        }, (res: any) => {
            res.resume();
            resolve({ status: res.statusCode, location: res.headers.location });
        });
        req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
        req.on("error", reject);
        req.end();
    });
}

/// Walk a redirect and check is the redirect safe or no, only if it is allowed
export async function is_redirect_safe(url: string, options: { makeRequest?: boolean } = {}): Promise<boolean> {
    const allowed = options.makeRequest ?? (process.env.DSSRF_MAKE_REQUEST === "1");
    try {
        let current = parse_target(url);
        if (!current) return false;

        const MAX_REDIRECTS = 5;
        for (let i = 0; i < MAX_REDIRECTS; i++) {
            if (!await is_parsed_url_safe(current)) return false;
            if (!allowed) return true;   // first hop verified; no outbound probing requested

            const res = await probe(current, "GET", 3000);
            const redirecting = res.status >= 300 && res.status < 400;
            if (!redirecting) return true;
            if (!res.location) return false;   // 3xx without Location: cannot verify
            current = new URL(res.location, current.toString());
        }
        return false;
    } catch {
        return false;
    }
}

/// Check is the URL safe or no
export async function is_url_safe(url: string): Promise<boolean> {
    try {
        const parsed = parse_target(url);
        if (!parsed) return false;
        if (!await is_parsed_url_safe(parsed)) return false;

        if (process.env.DSSRF_MAKE_REQUEST === "1") {
            if (!await is_redirect_safe(parsed.toString(), { makeRequest: true })) return false;
        }
        return true;
    } catch {
        return false;
    }
}
