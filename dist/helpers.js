"use strict";
//! This module is an internal module, not intended to be imported all public apis in utils
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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.is_ipv6 = is_ipv6;
exports.is_range_not_internal = is_range_not_internal;
exports.octal_ip_to_normal_ip = octal_ip_to_normal_ip;
exports.hex_ip_to_normal_ip = hex_ip_to_normal_ip;
exports.bin_ip_to_normal_ip = bin_ip_to_normal_ip;
exports.decimal_ip_to_normal_ip = decimal_ip_to_normal_ip;
exports.normalize_ipv4 = normalize_ipv4;
exports.is_ip_internal = is_ip_internal;
exports.is_hostname_resolve_to_internal_ip = is_hostname_resolve_to_internal_ip;
exports.replace_backslash_with_slash_in_string = replace_backslash_with_slash_in_string;
exports.remove_at_symbol_in_string = remove_at_symbol_in_string;
exports.normalize_schema = normalize_schema;
exports.replace_two_slashes_url_to_normal_url = replace_two_slashes_url_to_normal_url;
exports.is_proto_safe = is_proto_safe;
exports.is_redirect_safe = is_redirect_safe;
exports.normalize_unicode = normalize_unicode;
exports.is_url_safe = is_url_safe;
exports.is_url_safe_debug = is_url_safe_debug;
const ipaddr = __importStar(require("ipaddr.js"));
const ip_cidr_1 = __importDefault(require("ip-cidr"));
const got = require("got").default;
const DEBUG = false;
const DSSRF_MAKE_REQUEST = process.env.DSSRF_MAKE_REQUEST;
/// This is a helper function used by dssrf for block ipv6 address
function is_ipv6(ip) {
    try {
        return ipaddr.IPv6.isValid(ip);
    }
    catch (e) {
        return false;
    }
}
const BAD_RANGE_USED_IN_SSRF = [
    new ip_cidr_1.default("0.0.0.0/8"),
    new ip_cidr_1.default("10.0.0.0/8"),
    new ip_cidr_1.default("127.0.0.0/8"),
    new ip_cidr_1.default("169.254.0.0/16"),
    new ip_cidr_1.default("172.16.0.0/12"),
    new ip_cidr_1.default("192.168.0.0/16"),
    new ip_cidr_1.default("100.64.0.0/10"),
    new ip_cidr_1.default("192.0.0.0/24"),
    new ip_cidr_1.default("192.0.2.0/24"),
    new ip_cidr_1.default("198.18.0.0/15"),
    new ip_cidr_1.default("198.51.100.0/24"),
    new ip_cidr_1.default("203.0.113.0/24"),
    new ip_cidr_1.default("224.0.0.0/4"),
    new ip_cidr_1.default("240.0.0.0/4"),
];
function compareIPs(a, b) {
    const ab = a.toByteArray();
    const bb = b.toByteArray();
    for (let i = 0; i < ab.length; i++) {
        if (ab[i] < bb[i])
            return -1;
        if (ab[i] > bb[i])
            return 1;
    }
    return 0;
}
function is_range_not_internal(ipr) {
    const start = ipaddr.parse(ipr.start());
    const end = ipaddr.parse(ipr.end());
    for (const bad of BAD_RANGE_USED_IN_SSRF) {
        const badStart = ipaddr.parse(bad.start());
        const badEnd = ipaddr.parse(bad.end());
        const overlaps = compareIPs(start, badEnd) <= 0 &&
            compareIPs(end, badStart) >= 0;
        if (overlaps) {
            return false;
        }
    }
    return true;
}
/// An internal helper to convert octal ip to normal ip
function octal_ip_to_normal_ip(octal) {
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
function hex_ip_to_normal_ip(hex) {
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
function bin_ip_to_normal_ip(bin) {
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
function decimal_ip_to_normal_ip(decimal) {
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
function normalize_ipv4(ip) {
    const trimmed = ip.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
        throw new Error(`Unsupported IPv4 encoding: '${ip}'`);
    }
    const parts = trimmed.split(".");
    const normalizedParts = [];
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
function is_ip_internal(ip) {
    if (!ipaddr.isValid(ip))
        return false;
    const parsed = ipaddr.parse(ip);
    if (parsed.kind() === "ipv4") {
        return parsed.range() !== "unicast";
    }
    if (parsed.kind() === "ipv6") {
        const range = parsed.range();
        return (range === "loopback" ||
            range === "linkLocal" ||
            range === "uniqueLocal");
    }
    return false;
}
const dns_1 = require("dns");
async function resolve_all_records(host) {
    const A = await dns_1.promises.resolve4(host).catch(() => []);
    const AAAA = await dns_1.promises.resolve6(host).catch(() => []);
    const CNAME = await dns_1.promises.resolveCname(host).catch(() => []);
    return {
        A,
        AAAA,
        CNAME
    };
}
function classify_ips_allow_global_ipv6(ips) {
    for (const ip of ips) {
        if (!ipaddr.isValid(ip))
            continue;
        const parsed = ipaddr.parse(ip);
        if (parsed.kind() === "ipv6") {
            if (is_ip_internal(parsed.toString()))
                return true;
            continue;
        }
        if (is_ip_internal(parsed.toString()))
            return true;
    }
    return false;
}
/// Fixed dns rebinding protection timing window to be strong against complex dns rebinding attacks
async function is_hostname_resolve_to_internal_ip(hostname) {
    const host = hostname.trim();
    // Direct IP check
    if (ipaddr.isValid(host)) {
        const parsed = ipaddr.parse(host);
        return is_ip_internal(parsed.toString());
    }
    // Helper to resolve with retries
    async function resolveWithDelay(host, attempts) {
        const results = [];
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
    if (ips1.length === 0)
        return false;
    if (classify_ips_allow_global_ipv6(ips1))
        return true;
    // Re‑resolve with adaptive strategy
    const ips2 = await resolveWithDelay(host, 2);
    if (ips2.length === 0)
        return false;
    if (classify_ips_allow_global_ipv6(ips2))
        return true;
    // Compare sets to detect rebinding
    const set1 = new Set(ips1);
    const set2 = new Set(ips2);
    const changed = (set1.size !== set2.size ||
        [...set1].some(ip => !set2.has(ip)));
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
            if (is_ip_internal(parsed.toString()))
                return true;
        }
    }
    return false;
}
function replace_backslash_with_slash_in_string(s) {
    if (!s)
        return "";
    let u = s.replace(/\\/g, "/");
    u = u.replace(/([^:])\/{2,}/g, "$1/");
    return u;
}
function remove_at_symbol_in_string(s) {
    return s.replace(/@/g, "");
}
function normalize_schema(u) {
    try {
        const parsed = new URL(u);
        return parsed.protocol;
    }
    catch {
        return "";
    }
}
function replace_two_slashes_url_to_normal_url(url) {
    if (!url)
        return "";
    let u = url.trim();
    if (u.startsWith("//")) {
        return "http:" + u;
    }
    u = u.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/(?!\/)/, "$1://");
    u = u.replace(/([^:])\/{2,}/g, "$1/");
    return u;
}
const ALLOWED_PROTOCOLS = [
    "https",
    "http"
];
function is_proto_safe(url) {
    if (!url)
        return false;
    const u = url.trim().toLowerCase();
    const match = u.match(/^([a-z0-9+.-]+):/);
    if (!match) {
        return false;
    }
    const scheme = match[1];
    if (!ALLOWED_PROTOCOLS.includes(scheme)) {
        return false;
    }
    if (scheme === "http")
        return true;
    if (scheme === "https")
        return true;
    return false;
}
async function is_redirect_safe(url) {
    try {
        let normalized = replace_backslash_with_slash_in_string(url);
        normalized = remove_at_symbol_in_string(normalized);
        let current = new URL(normalized);
        const MAX_REDIRECTS = 5;
        for (let i = 0; i < MAX_REDIRECTS; i++) {
            if (!is_proto_safe(current.protocol))
                return false;
            if (await is_hostname_resolve_to_internal_ip(current.hostname))
                return false;
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
            }
            catch {
                return false;
            }
        }
        return false;
    }
    catch {
        return false;
    }
}
function normalize_unicode(input) {
    if (!input)
        return "";
    return input.normalize("NFKC");
}
async function is_url_safe(url) {
    try {
        let u = normalize_unicode(url);
        u = replace_backslash_with_slash_in_string(u);
        u = replace_two_slashes_url_to_normal_url(u);
        u = remove_at_symbol_in_string(u);
        const schema = normalize_schema(u);
        if (!is_proto_safe(schema))
            return false;
        const parsed = new URL(u);
        const hostname = parsed.hostname;
        // IPv4 validation
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
            try {
                normalize_ipv4(hostname);
            }
            catch {
                return false;
            }
        }
        if (is_ipv6(hostname)) {
            if (is_ip_internal(hostname))
                return false;
        }
        if (await is_hostname_resolve_to_internal_ip(hostname))
            return false;
        if (process.env.DSSRF_CHECK_REDIRECTS === "1") {
            const redirectSafe = await is_redirect_safe(u);
            if (!redirectSafe)
                return false;
        }
        return true;
    }
    catch {
        return false;
    }
}
/// FIXME(): The debug version do not match is_url_safe, We'wll fix it later but for now keep it as is.
async function is_url_safe_debug(url) { try {
    console.log("STEP 1 input:", url);
    let u = normalize_unicode(url);
    console.log("STEP 2 unicode:", u);
    u = replace_backslash_with_slash_in_string(u);
    console.log("STEP 3 slashes:", u);
    u = replace_two_slashes_url_to_normal_url(u);
    console.log("STEP 4 normalize slashes:", u);
    u = remove_at_symbol_in_string(u);
    console.log("STEP 5 remove @:", u);
    const schema = normalize_schema(u);
    if (!is_proto_safe(schema))
        return false;
    console.log("STEP 6 schema:", schema);
    if (!is_proto_safe(u)) {
        console.log("STEP 7 proto unsafe");
        return false;
    }
    console.log("STEP 7 proto safe");
    const parsed = new URL(u);
    const hostname = parsed.hostname;
    console.log("STEP 8 hostname:", hostname);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        try {
            normalize_ipv4(hostname);
        }
        catch {
            console.log("STEP 9 ipv4 invalid");
            return false;
        }
    }
    if (is_ipv6(hostname)) {
        if (is_ip_internal(hostname)) {
            console.log("STEP 10 ipv6 internal");
            return false;
        }
    }
    const isInternal = await is_hostname_resolve_to_internal_ip(hostname);
    console.log("STEP 11 internal?", isInternal);
    if (isInternal) {
        return false;
    }
    const redirectSafe = await is_redirect_safe(u);
    console.log("STEP 12 redirect safe?", redirectSafe);
    if (!redirectSafe) {
        return false;
    }
    console.log("STEP 13 final: true");
    return true;
}
catch (e) {
    console.log("ERROR:", e);
    return false;
} }
