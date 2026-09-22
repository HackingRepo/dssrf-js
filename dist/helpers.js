"use strict";
//! Internal module. The public surface is re-exported from utils.
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.is_ipv6 = is_ipv6;
exports.is_ip_internal = is_ip_internal;
exports.is_range_not_internal = is_range_not_internal;
exports.octal_ip_to_normal_ip = octal_ip_to_normal_ip;
exports.hex_ip_to_normal_ip = hex_ip_to_normal_ip;
exports.bin_ip_to_normal_ip = bin_ip_to_normal_ip;
exports.decimal_ip_to_normal_ip = decimal_ip_to_normal_ip;
exports.normalize_ipv4 = normalize_ipv4;
exports.resolve_host = resolve_host;
exports.is_hostname_resolve_to_internal_ip = is_hostname_resolve_to_internal_ip;
exports.replace_backslash_with_slash_in_string = replace_backslash_with_slash_in_string;
exports.remove_at_symbol_in_string = remove_at_symbol_in_string;
exports.normalize_schema = normalize_schema;
exports.replace_two_slashes_url_to_normal_url = replace_two_slashes_url_to_normal_url;
exports.is_proto_safe = is_proto_safe;
exports.parse_target = parse_target;
exports.is_redirect_safe = is_redirect_safe;
exports.is_url_safe = is_url_safe;
const ipaddr = __importStar(require("ipaddr.js"));
const node_dns_1 = require("node:dns");
// SSRF ranges list, includes no RFC, ones
const BAD_RANGE_USED_IN_SSRF = [
    "0.0.0.0/8", // this network            RFC 1122
    "10.0.0.0/8", // private                 RFC 1918
    "100.64.0.0/10", // carrier-grade NAT       RFC 6598
    "127.0.0.0/8", // loopback                RFC 1122
    "169.254.0.0/16", // link-local + metadata   RFC 3927
    "172.16.0.0/12", // private                 RFC 1918
    "192.0.0.0/24", // IETF protocol assignm.  RFC 6890
    "192.0.2.0/24", // TEST-NET-1              RFC 5737
    "192.31.196.0/24", // AS112-v4                RFC 7535
    "192.52.193.0/24", // AMT                     RFC 7450
    "192.88.99.0/24", // 6to4 relay anycast      RFC 7526
    "192.168.0.0/16", // private                 RFC 1918
    "192.175.48.0/24", // direct delegation AS112 RFC 7534
    "198.18.0.0/15", // benchmarking            RFC 2544
    "198.51.100.0/24", // TEST-NET-2              RFC 5737
    "203.0.113.0/24", // TEST-NET-3              RFC 5737
    "224.0.0.0/4", // multicast               RFC 5771
    "240.0.0.0/4", // reserved + broadcast    RFC 1112
    "168.63.129.16/32", // Azure wire server
    "100.100.100.200/32", // Alibaba Cloud metadata
];
// Same as below but for IPv6
const BAD_RANGE_IPV6 = [
    "64:ff9b:1::/48", // NAT64 local-use         RFC 8215
    "5f00::/16", // SRv6 SIDs               RFC 9602
    "3fff::/20", // documentation           RFC 9637
    "fec0::/10", // deprecated site-local
    "100::/64", // discard-only            RFC 6666
];
const PARSED_BAD_V4 = BAD_RANGE_USED_IN_SSRF.map(c => ipaddr.parseCIDR(c));
const PARSED_BAD_V6 = BAD_RANGE_IPV6.map(c => ipaddr.parseCIDR(c));
/// This is a helper function used by dssrf for block ipv6 address
function is_ipv6(ip) {
    try {
        return ipaddr.IPv6.isValid(ip);
    }
    catch (e) {
        return false;
    }
}
/**
 * IPv4-mapped (`::ffff:0:0/96`) is the one IPv6 form that is a legitimate way
 * to write an IPv4 address, so it must classify as the address it carries.
 * Returns the address, or null.
 */
function mapped_ipv4(addr) {
    const b = addr.toByteArray();
    for (let i = 0; i < 10; i++)
        if (b[i] !== 0)
            return null;
    if (b[10] !== 0xff || b[11] !== 0xff)
        return null;
    return `${b[12]}.${b[13]}.${b[14]}.${b[15]}`;
}
// Determines if a given IPv6 address belongs to a known transition mechanism.
function is_transition_prefix(addr) {
    const b = addr.toByteArray();
    const zero = (from, to) => {
        for (let i = from; i < to; i++)
            if (b[i] !== 0)
                return false;
        return true;
    };
    if (zero(0, 12))
        return true; // ::/96           IPv4-compatible
    if (zero(0, 8) && b[8] === 0xff && b[9] === 0xff && zero(10, 12))
        return true; // ::ffff:0:0:0/96 RFC 6145
    if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b)
        return true; // 64:ff9b::/32    NAT64 (well-known + local-use)
    if (b[0] === 0x20 && b[1] === 0x02)
        return true; // 2002::/16       6to4
    return false;
}
function matches(addr, list) {
    for (const [range, bits] of list) {
        if (range.kind() !== addr.kind())
            continue;
        try {
            // @ts-ignore - match() is family-checked above
            if (addr.match(range, bits))
                return true;
        }
        catch { /* family mismatch */ }
    }
    return false;
}
// Check is a raw ip is internal or no
function is_ip_internal(ip) {
    let parsed;
    try {
        if (!ipaddr.isValid(ip))
            return true; // unparseable, refuse
        parsed = ipaddr.parse(ip);
    }
    catch {
        return true;
    }
    if (parsed.kind() === "ipv6") {
        const v6 = parsed;
        // IPv4-mapped is a real way to write an IPv4 address, classify it as one.
        const mapped = mapped_ipv4(v6);
        if (mapped !== null)
            return is_ip_internal(mapped);
        // Every other transition prefix is refused outright.
        if (is_transition_prefix(v6))
            return true;
        if (v6.range() !== "unicast")
            return true;
        return matches(v6, PARSED_BAD_V6);
    }
    const v4 = parsed;
    if (v4.range() !== "unicast")
        return true;
    return matches(v4, PARSED_BAD_V4);
}
// That function compares two ip addresses
function compareIPs(a, b) {
    const ab = a.toByteArray();
    const bb = b.toByteArray();
    if (ab.length !== bb.length)
        return ab.length < bb.length ? -1 : 1;
    for (let i = 0; i < ab.length; i++) {
        if (ab[i] < bb[i])
            return -1;
        if (ab[i] > bb[i])
            return 1;
    }
    return 0;
}
// Check an ip or cidr like object is not internal
function is_range_not_internal(ipr) {
    let startStr;
    let endStr;
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
            const build = (arr) => (bytes.length === 4
                ? ipaddr.fromByteArray(arr).toString()
                : ipaddr.fromByteArray(arr).toString());
            startStr = build(startB);
            endStr = build(endB);
        }
        else {
            startStr = ipr.start();
            endStr = ipr.end();
        }
    }
    catch {
        return false; // unparseable, treat as internal
    }
    let start;
    let end;
    try {
        start = ipaddr.parse(startStr);
        end = ipaddr.parse(endStr);
    }
    catch {
        return false;
    }
    const bad = start.kind() === "ipv4" ? BAD_RANGE_USED_IN_SSRF : BAD_RANGE_IPV6;
    for (const cidr of bad) {
        let badStart;
        let badEnd;
        try {
            const [a, bits] = ipaddr.parseCIDR(cidr);
            if (a.kind() !== start.kind())
                continue;
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
        }
        catch {
            continue;
        }
        if (compareIPs(start, badEnd) <= 0 && compareIPs(end, badStart) >= 0)
            return false;
    }
    // A range of IPv6 unicast space still has to clear the per-address rules.
    if (start.kind() === "ipv6" && (is_ip_internal(startStr) || is_ip_internal(endStr)))
        return false;
    return true;
}
/// An internal helper to convert octal ip to normal ip
function octal_ip_to_normal_ip(octal) {
    const parts = octal.split(".");
    if (parts.length !== 4)
        throw new Error("Invalid IPv4 address format.");
    const decimalParts = parts.map((part) => {
        if (part.length === 0)
            throw new Error("Invalid empty octet");
        if (!/^[0-7]+$/.test(part))
            throw new Error(`Invalid octal digit in '${part}'`);
        const value = parseInt(part, 8);
        if (value < 0 || value > 255)
            throw new Error(`Octet out of range after conversion: '${part}' -> ${value}`);
        return String(value);
    });
    return decimalParts.join(".");
}
/// An internal helper to convert hex ip to normal ip
function hex_ip_to_normal_ip(hex) {
    const cleaned = hex.toLowerCase().startsWith("0x") ? hex.slice(2) : hex;
    if (!/^[0-9a-f]{8}$/.test(cleaned))
        throw new Error(`Invalid hex IPv4 address: '${hex}'`);
    const num = parseInt(cleaned, 16);
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
}
/// An internal helper to convert bin ip to normal ip
function bin_ip_to_normal_ip(bin) {
    let cleaned = bin.trim();
    if (cleaned.toLowerCase().startsWith("0b"))
        cleaned = cleaned.slice(2);
    if (cleaned.includes(".")) {
        const parts = cleaned.split(".");
        if (parts.length !== 4)
            throw new Error(`Invalid binary IPv4 address: '${bin}'`);
        const octets = parts.map(p => {
            if (!/^[01]{8}$/.test(p))
                throw new Error(`Invalid binary IPv4 octet: '${p}' in '${bin}'`);
            return parseInt(p, 2);
        });
        return `${octets[0]}.${octets[1]}.${octets[2]}.${octets[3]}`;
    }
    if (!/^[01]{32}$/.test(cleaned))
        throw new Error(`Invalid binary IPv4 address: '${bin}'`);
    const num = parseInt(cleaned, 2);
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
}
/// An internal helper to convert decimal ip to normal ip
function decimal_ip_to_normal_ip(decimal) {
    if (!/^\d+$/.test(decimal))
        throw new Error(`Invalid decimal IPv4: '${decimal}'`);
    const num = Number(decimal);
    if (!Number.isInteger(num) || num < 0 || num > 0xFFFFFFFF)
        throw new Error(`Decimal IPv4 out of range: '${decimal}'`);
    return `${(num >>> 24) & 0xFF}.${(num >>> 16) & 0xFF}.${(num >>> 8) & 0xFF}.${num & 0xFF}`;
}
function normalize_ipv4(ip) {
    const trimmed = ip.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed))
        throw new Error(`Unsupported IPv4 encoding: '${ip}'`);
    const parts = trimmed.split(".");
    const normalizedParts = [];
    for (const part of parts) {
        if (!/^\d+$/.test(part))
            throw new Error(`Invalid IPv4 octet: '${part}' in '${ip}'`);
        if (part.length > 1 && part.startsWith("0")) {
            throw new Error(`IPv4 octet with leading zeros is not allowed: '${part}' in '${ip}'`);
        }
        const value = Number(part);
        if (value < 0 || value > 255)
            throw new Error(`IPv4 octet out of range: '${part}' in '${ip}'`);
        normalizedParts.push(String(value));
    }
    return normalizedParts.join(".");
}
/// That function classifies a dns error, to nxdomain or unknown
function classifyDnsError(code) {
    return code === "ENOTFOUND" || code === "EAI_NONAME" ? "nxdomain" : "unknown";
}
/// A function that resolves a hostname and returns a Resolution promise
async function resolve_host(hostname) {
    const host = hostname.trim();
    const errors = [];
    const push = (e) => { errors.push(e?.code || "UNKNOWN"); return []; };
    const [lookup, a, aaaa] = await Promise.all([
        node_dns_1.promises.lookup(host, { all: true }).then(r => r.map(e => e.address), push),
        node_dns_1.promises.resolve4(host).catch(push),
        node_dns_1.promises.resolve6(host).catch(push),
    ]);
    const addresses = [...new Set([...lookup, ...a, ...aaaa])];
    if (addresses.length > 0)
        return { kind: "addresses", addresses };
    // Every path failed. Only a genuine NXDOMAIN from every path is safe to
    // treat as "does not exist".
    const allNx = errors.length > 0 && errors.every(c => classifyDnsError(c) === "nxdomain");
    return allNx ? { kind: "nxdomain" } : { kind: "unknown", code: errors[0] || "UNKNOWN" };
}
/// Check is a hostname resolve to an internal ip
async function is_hostname_resolve_to_internal_ip(hostname) {
    const host = hostname.trim();
    if (ipaddr.isValid(host))
        return is_ip_internal(ipaddr.parse(host).toString());
    const res = await resolve_host(host);
    if (res.kind === "unknown")
        return true; // could not check, refuse
    if (res.kind === "nxdomain")
        return false; // does not exist, the fetch fails on its own
    return res.addresses.some(ip => is_ip_internal(ip));
}
/// Replace backslash with slash, in a string
function replace_backslash_with_slash_in_string(s) {
    if (!s)
        return "";
    let u = s.replace(/\\/g, "/");
    u = u.replace(/([^:])\/{2,}/g, "$1/");
    return u;
}
/// Remove at symbol in a string
function remove_at_symbol_in_string(s) {
    return s.replace(/@/g, "");
}
/// Normalizes a schema, if it cannot it returns nothing
function normalize_schema(u) {
    try {
        return new URL(u).protocol;
    }
    catch {
        return "";
    }
}
/// Replaces a two slashes url to a normal url
function replace_two_slashes_url_to_normal_url(url) {
    if (!url)
        return "";
    let u = url.trim();
    if (u.startsWith("//"))
        return "http:" + u;
    u = u.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/(?!\/)/, "$1://");
    u = u.replace(/([^:])\/{2,}/g, "$1/");
    return u;
}
/// Protocol whitelist list
const ALLOWED_PROTOCOLS = ["https", "http"];
/// Check is a proto safe, or no
function is_proto_safe(url) {
    if (!url)
        return false;
    const match = String(url).trim().toLowerCase().match(/^([a-z0-9+.-]+):/);
    return match ? ALLOWED_PROTOCOLS.includes(match[1]) : false;
}
/// Check is a hostname is ascii
function is_ascii_host(hostname) {
    return /^[\x00-\x7F]*$/.test(hostname);
}
/// Parse the target url, if failed return null
function parse_target(url) {
    // Only a string or a URL is a URL. Coercing anything else would turn
    // ["http://x"] into a real target and send us resolving it.
    if (url instanceof URL)
        return url;
    if (typeof url !== "string")
        return null;
    try {
        let u = replace_backslash_with_slash_in_string(url);
        u = replace_two_slashes_url_to_normal_url(u);
        return new URL(u);
    }
    catch {
        return null;
    }
}
/// Check is the parsed url safe, or no
async function is_parsed_url_safe(parsed) {
    if (!is_proto_safe(parsed.protocol))
        return false;
    if (parsed.username !== "" || parsed.password !== "")
        return false;
    // WHATWG URL includes brackets in .hostname for IPv6 (e.g. "[::1]"); strip them
    const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
    if (hostname === "")
        return false;
    if (!is_ascii_host(hostname))
        return false;
    if (await is_hostname_resolve_to_internal_ip(hostname))
        return false;
    return true;
}
function probe(target, method, timeoutMs) {
    return new Promise((resolve, reject) => {
        const mod = target.protocol === "https:" ? require("node:https") : require("node:http");
        const req = mod.request({
            protocol: target.protocol,
            hostname: target.hostname.replace(/^\[|\]$/g, ""),
            port: target.port || (target.protocol === "https:" ? 443 : 80),
            path: target.pathname + target.search,
            method,
        }, (res) => {
            res.resume();
            resolve({ status: res.statusCode, location: res.headers.location });
        });
        req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
        req.on("error", reject);
        req.end();
    });
}
/// Walk a redirect and check is the redirect safe or no, only if it is allowed
async function is_redirect_safe(url, options = {}) {
    const allowed = options.makeRequest ?? (process.env.DSSRF_MAKE_REQUEST === "1");
    try {
        let current = parse_target(url);
        if (!current)
            return false;
        const MAX_REDIRECTS = 5;
        for (let i = 0; i < MAX_REDIRECTS; i++) {
            if (!await is_parsed_url_safe(current))
                return false;
            if (!allowed)
                return true; // first hop verified; no outbound probing requested
            const res = await probe(current, "GET", 3000);
            const redirecting = res.status >= 300 && res.status < 400;
            if (!redirecting)
                return true;
            if (!res.location)
                return false; // 3xx without Location: cannot verify
            current = new URL(res.location, current.toString());
        }
        return false;
    }
    catch {
        return false;
    }
}
/// Check is the URL safe or no
async function is_url_safe(url) {
    try {
        const parsed = parse_target(url);
        if (!parsed)
            return false;
        if (!await is_parsed_url_safe(parsed))
            return false;
        if (process.env.DSSRF_MAKE_REQUEST === "1") {
            if (!await is_redirect_safe(parsed.toString(), { makeRequest: true }))
                return false;
        }
        return true;
    }
    catch {
        return false;
    }
}
