//! The new IP Pinning module, the `is_url_safe` still kept for compability, read README.md
//! It is recommended to switch to the `safe_fetch`

import * as http from "node:http";
import * as https from "node:https";
import * as net from "node:net";
import { is_ip_internal, is_proto_safe, resolve_host, parse_target } from "./helpers";

/// A class indicating an ssrf attempt error
/// or a user mistake, like passing hostname as an allow list
export class SsrfRefused extends Error {
    readonly code = "DSSRF_REFUSED";
    readonly reason: string;
    constructor(reason: string, detail?: string) {
        super(`dssrf: refused -- ${reason}${detail ? ` (${detail})` : ""}`);
        this.name = "SsrfRefused";
        this.reason = reason;
    }
}

/// An interface containing a Pinned object
export interface Pin {
    url: URL;
    hostname: string;
    port: number;
    addresses: string[];
    /** Present for https to a named host: connect by address, verify by name. */
    servername: string | null;
}

/// Allowed Ports by default
const DEFAULT_PORTS = new Set([80, 443]);

/// Options to be passed when the operator use `safe_fetch`, that represent them as a TS interface
export interface PinOptions {
    /** Ports permitted in addition to 80 and 443. */
    ports?: number[];
    allow?: string[];
    /** Total budget for a whole redirect chain, in ms. */
    totalTimeout?: number;
}

/// Check allow entries. is they are ip or port, if hostname refuse, instead of successing silently
function normaliseAllow(allow: string[] | undefined): Set<string> {
    const out = new Set<string>();
    for (const entry of allow || []) {
        if (!/:\d+$/.test(entry)) {
            throw new SsrfRefused("allow-entry-needs-port",
                `"${entry}", use "addr:port"; a bare address permits every port on that host`);
        }
        out.add(entry);
    }
    return out;
}

/// Resolve once the target and pin the IP
export async function resolve_and_pin(input: string | URL, options: PinOptions = {}): Promise<Pin> {
    const url = parse_target(input);
    if (!url) throw new SsrfRefused("unparseable-url");

    if (!is_proto_safe(url.protocol)) throw new SsrfRefused("scheme-not-allowed", url.protocol);
    if (url.username !== "" || url.password !== "") throw new SsrfRefused("userinfo-present");

    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    if (hostname === "") throw new SsrfRefused("empty-host");
    if (!/^[\x00-\x7F]*$/.test(hostname)) throw new SsrfRefused("non-ascii-host");

    const port = Number(url.port) || (url.protocol === "https:" ? 443 : 80);
    const allowed = new Set([...DEFAULT_PORTS, ...(options.ports || [])]);
    if (!allowed.has(port)) throw new SsrfRefused("port-not-allowed", String(port));

    let addresses: string[];
    if (net.isIP(hostname)) {
        addresses = [hostname];
    } else {
        const res = await resolve_host(hostname);
        if (res.kind === "nxdomain") throw new SsrfRefused("host-not-found", hostname);
        if (res.kind === "unknown") throw new SsrfRefused("resolution-failed", res.code);
        addresses = res.addresses;
    }

    // Validate EVERY address. Happy Eyeballs attack (autoSelectFamily, on by default
    // since Node 20) may use any member, so checking only the first would leave
    // the rest as a bypass, We must loop trought them.
    const allow = normaliseAllow(options.allow);
    for (const address of addresses) {
        if (allow.has(`${address}:${port}`)) continue;
        if (is_ip_internal(address)) throw new SsrfRefused("internal-address", `${hostname} -> ${address}`);
    }

    return {
        url, hostname, port, addresses,
        servername: url.protocol === "https:" && !net.isIP(hostname) ? hostname : null,
    };
}

/// Get the host header
function hostHeader(hostname: string, port: number, protocol: string): string {
    const dflt = protocol === "https:" ? 443 : 80;
    const h = hostname.includes(":") ? `[${hostname}]` : hostname;
    return port === dflt ? h : `${h}:${port}`;
}

/// That is the options that the user can pass, like PinOptions, but with more
export interface FetchOptions extends PinOptions {
    method?: string;
    headers?: Record<string, string>;
    maxRedirects?: number;
    timeout?: number;
    /** Cap on the response body, in bytes, To prevent resource exhaustation attacks. */
    maxBytes?: number;
}

/// The fetch result interface
export interface FetchResult {
    status: number;
    headers: http.IncomingHttpHeaders;
    body: string;
    url: string;
    /** Every hop, with the address actually connected to. */
    chain: { url: string; address: string }[];
}


function oneHop(pin: Pin, o: Required<Pick<FetchOptions, "method" | "headers" | "timeout" | "maxBytes">>): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
    return new Promise((resolve, reject) => {
        const isTls = pin.url.protocol === "https:";
        const mod: any = isTls ? https : http;
        const address = pin.addresses[0];

        const req = mod.request({
            host: address,                       // connect to the pinned ADDRESS
            port: pin.port,
            method: o.method,
            path: pin.url.pathname + pin.url.search,
            agent: new mod.Agent({ keepAlive: false, maxSockets: 1 }),
            headers: { ...o.headers, host: hostHeader(pin.hostname, pin.port, pin.url.protocol) },
            ...(isTls && pin.servername ? { servername: pin.servername } : {}),
        }, (res: http.IncomingMessage) => {
            const chunks: Buffer[] = [];
            let seen = 0;
            res.on("data", (c: Buffer) => {
                seen += c.length;
                if (seen > o.maxBytes) { req.destroy(); reject(new SsrfRefused("response-too-large")); return; }
                chunks.push(c);
            });
            res.on("end", () => resolve({
                status: res.statusCode || 0,
                headers: res.headers,
                body: Buffer.concat(chunks as unknown as Uint8Array[]).toString("utf8"),
            }));
        });
        req.setTimeout(o.timeout, () => req.destroy(new SsrfRefused("timeout")));
        req.on("error", reject);
        req.end();
    });
}

/// That is the public function and entrypoint of the new safe fetch
export async function safe_fetch(input: string | URL, options: FetchOptions = {}): Promise<FetchResult> {
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

    let current: string | URL = input;
    const chain: { url: string; address: string }[] = [];

    for (let hop = 0; hop <= maxRedirects; hop++) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new SsrfRefused("deadline-exceeded");
        const pin = await resolve_and_pin(current, options);
        chain.push({ url: pin.url.toString(), address: pin.addresses[0] });
        const res = await oneHop(pin, { ...o, timeout: Math.min(o.timeout, remaining) });

        const redirecting = res.status >= 300 && res.status < 400;
        if (!redirecting) return { ...res, url: pin.url.toString(), chain };
        if (!res.headers.location) throw new SsrfRefused("redirect-without-location");

        try {
            current = new URL(res.headers.location, pin.url);
        } catch {
            throw new SsrfRefused("unparseable-redirect", String(res.headers.location));
        }
    }
    throw new SsrfRefused("too-many-redirects");
}
