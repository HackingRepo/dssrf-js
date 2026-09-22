"use strict";
//! The new IP Pinning module, the `is_url_safe` still kept for compability, read README.md
//! It is recommended to switch to the `safe_fetch`
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
exports.SsrfRefused = void 0;
exports.resolve_and_pin = resolve_and_pin;
exports.safe_fetch = safe_fetch;
const http = __importStar(require("node:http"));
const https = __importStar(require("node:https"));
const net = __importStar(require("node:net"));
const helpers_1 = require("./helpers");
/// A class indicating an ssrf attempt error
/// or a user mistake, like passing hostname as an allow list
class SsrfRefused extends Error {
    code = "DSSRF_REFUSED";
    reason;
    constructor(reason, detail) {
        super(`dssrf: refused -- ${reason}${detail ? ` (${detail})` : ""}`);
        this.name = "SsrfRefused";
        this.reason = reason;
    }
}
exports.SsrfRefused = SsrfRefused;
/// Allowed Ports by default
const DEFAULT_PORTS = new Set([80, 443]);
/// Check allow entries. is they are ip or port, if hostname refuse, instead of successing silently
function normaliseAllow(allow) {
    const out = new Set();
    for (const entry of allow || []) {
        if (!/:\d+$/.test(entry)) {
            throw new SsrfRefused("allow-entry-needs-port", `"${entry}", use "addr:port"; a bare address permits every port on that host`);
        }
        out.add(entry);
    }
    return out;
}
/// Resolve once the target and pin the IP
async function resolve_and_pin(input, options = {}) {
    const url = (0, helpers_1.parse_target)(input);
    if (!url)
        throw new SsrfRefused("unparseable-url");
    if (!(0, helpers_1.is_proto_safe)(url.protocol))
        throw new SsrfRefused("scheme-not-allowed", url.protocol);
    if (url.username !== "" || url.password !== "")
        throw new SsrfRefused("userinfo-present");
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    if (hostname === "")
        throw new SsrfRefused("empty-host");
    if (!/^[\x00-\x7F]*$/.test(hostname))
        throw new SsrfRefused("non-ascii-host");
    const port = Number(url.port) || (url.protocol === "https:" ? 443 : 80);
    const allowed = new Set([...DEFAULT_PORTS, ...(options.ports || [])]);
    if (!allowed.has(port))
        throw new SsrfRefused("port-not-allowed", String(port));
    let addresses;
    if (net.isIP(hostname)) {
        addresses = [hostname];
    }
    else {
        const res = await (0, helpers_1.resolve_host)(hostname);
        if (res.kind === "nxdomain")
            throw new SsrfRefused("host-not-found", hostname);
        if (res.kind === "unknown")
            throw new SsrfRefused("resolution-failed", res.code);
        addresses = res.addresses;
    }
    // Validate EVERY address. Happy Eyeballs attack (autoSelectFamily, on by default
    // since Node 20) may use any member, so checking only the first would leave
    // the rest as a bypass, We must loop trought them.
    const allow = normaliseAllow(options.allow);
    for (const address of addresses) {
        if (allow.has(`${address}:${port}`))
            continue;
        if ((0, helpers_1.is_ip_internal)(address))
            throw new SsrfRefused("internal-address", `${hostname} -> ${address}`);
    }
    return {
        url, hostname, port, addresses,
        servername: url.protocol === "https:" && !net.isIP(hostname) ? hostname : null,
    };
}
/// Get the host header
function hostHeader(hostname, port, protocol) {
    const dflt = protocol === "https:" ? 443 : 80;
    const h = hostname.includes(":") ? `[${hostname}]` : hostname;
    return port === dflt ? h : `${h}:${port}`;
}
function oneHop(pin, o) {
    return new Promise((resolve, reject) => {
        const isTls = pin.url.protocol === "https:";
        const mod = isTls ? https : http;
        const address = pin.addresses[0];
        const req = mod.request({
            host: address, // connect to the pinned ADDRESS
            port: pin.port,
            method: o.method,
            path: pin.url.pathname + pin.url.search,
            agent: new mod.Agent({ keepAlive: false, maxSockets: 1 }),
            headers: { ...o.headers, host: hostHeader(pin.hostname, pin.port, pin.url.protocol) },
            ...(isTls && pin.servername ? { servername: pin.servername } : {}),
        }, (res) => {
            const chunks = [];
            let seen = 0;
            res.on("data", (c) => {
                seen += c.length;
                if (seen > o.maxBytes) {
                    req.destroy();
                    reject(new SsrfRefused("response-too-large"));
                    return;
                }
                chunks.push(c);
            });
            res.on("end", () => resolve({
                status: res.statusCode || 0,
                headers: res.headers,
                body: Buffer.concat(chunks).toString("utf8"),
            }));
        });
        req.setTimeout(o.timeout, () => req.destroy(new SsrfRefused("timeout")));
        req.on("error", reject);
        req.end();
    });
}
/// That is the public function and entrypoint of the new safe fetch
async function safe_fetch(input, options = {}) {
    const o = {
        method: options.method ?? "GET",
        headers: options.headers ?? {},
        timeout: options.timeout ?? 10000,
        maxBytes: options.maxBytes ?? 8 * 1024 * 1024,
    };
    const maxRedirects = options.maxRedirects ?? 5;
    // Without a total budget the worst case is maxRedirects x timeout, which an
    // attacker controls by chaining slow hops.
    const deadline = Date.now() + (options.totalTimeout ?? 30000);
    let current = input;
    const chain = [];
    for (let hop = 0; hop <= maxRedirects; hop++) {
        const remaining = deadline - Date.now();
        if (remaining <= 0)
            throw new SsrfRefused("deadline-exceeded");
        const pin = await resolve_and_pin(current, options);
        chain.push({ url: pin.url.toString(), address: pin.addresses[0] });
        const res = await oneHop(pin, { ...o, timeout: Math.min(o.timeout, remaining) });
        const redirecting = res.status >= 300 && res.status < 400;
        if (!redirecting)
            return { ...res, url: pin.url.toString(), chain };
        if (!res.headers.location)
            throw new SsrfRefused("redirect-without-location");
        try {
            current = new URL(res.headers.location, pin.url);
        }
        catch {
            throw new SsrfRefused("unparseable-redirect", String(res.headers.location));
        }
    }
    throw new SsrfRefused("too-many-redirects");
}
