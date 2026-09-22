export declare function is_ipv6(ip: string): boolean;
export declare function is_ip_internal(ip: string): boolean;
interface CidrLike {
    start(): string;
    end(): string;
}
export declare function is_range_not_internal(ipr: string | CidrLike): boolean;
export declare function octal_ip_to_normal_ip(octal: string): string;
export declare function hex_ip_to_normal_ip(hex: string): string;
export declare function bin_ip_to_normal_ip(bin: string): string;
export declare function decimal_ip_to_normal_ip(decimal: string): string;
export declare function normalize_ipv4(ip: string): string;
export type Resolution = 
/** Addresses were observed. */
{
    kind: "addresses";
    addresses: string[];
}
/** The name genuinely does not exist. A client would fail identically. */
 | {
    kind: "nxdomain";
}
/** The resolver could not answer. We do not know. */
 | {
    kind: "unknown";
    code: string;
};
export declare function resolve_host(hostname: string): Promise<Resolution>;
export declare function is_hostname_resolve_to_internal_ip(hostname: string): Promise<boolean>;
export declare function replace_backslash_with_slash_in_string(s: string): string;
export declare function remove_at_symbol_in_string(s: string): string;
export declare function normalize_schema(u: string): string;
export declare function replace_two_slashes_url_to_normal_url(url: string): string;
export declare function is_proto_safe(url: string): boolean;
export declare function parse_target(url: unknown): URL | null;
export declare function is_redirect_safe(url: string, options?: {
    makeRequest?: boolean;
}): Promise<boolean>;
export declare function is_url_safe(url: string): Promise<boolean>;
export {};
