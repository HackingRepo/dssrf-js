import * as http from "node:http";
export declare class SsrfRefused extends Error {
    readonly code = "DSSRF_REFUSED";
    readonly reason: string;
    constructor(reason: string, detail?: string);
}
export interface Pin {
    url: URL;
    hostname: string;
    port: number;
    addresses: string[];
    /** Present for https to a named host: connect by address, verify by name. */
    servername: string | null;
}
export interface PinOptions {
    /** Ports permitted in addition to 80 and 443. */
    ports?: number[];
    allow?: string[];
    /** Total budget for a whole redirect chain, in ms. */
    totalTimeout?: number;
}
export declare function resolve_and_pin(input: string | URL, options?: PinOptions): Promise<Pin>;
export interface FetchOptions extends PinOptions {
    method?: string;
    headers?: Record<string, string>;
    maxRedirects?: number;
    timeout?: number;
    /** Cap on the response body, in bytes, To prevent resource exhaustation attacks. */
    maxBytes?: number;
}
export interface FetchResult {
    status: number;
    headers: http.IncomingHttpHeaders;
    body: string;
    url: string;
    /** Every hop, with the address actually connected to. */
    chain: {
        url: string;
        address: string;
    }[];
}
export declare function safe_fetch(input: string | URL, options?: FetchOptions): Promise<FetchResult>;
