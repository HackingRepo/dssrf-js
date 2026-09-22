//! A module contain all utilities for SSRF mitigation

export {
    is_ipv6,
    bin_ip_to_normal_ip,
    decimal_ip_to_normal_ip,
    hex_ip_to_normal_ip,
    is_hostname_resolve_to_internal_ip,
    is_ip_internal,
    is_proto_safe,
    is_range_not_internal,
    is_redirect_safe,
    normalize_ipv4,
    normalize_schema,
    octal_ip_to_normal_ip,
    remove_at_symbol_in_string,
    replace_backslash_with_slash_in_string,
    replace_two_slashes_url_to_normal_url,
    resolve_host,
    is_url_safe
} from "./helpers";

export type { Resolution } from "./helpers";

// Pinning new functions exported
export {
    resolve_and_pin,
    safe_fetch,
    SsrfRefused
} from "./pin";

export type { Pin, PinOptions, FetchOptions, FetchResult } from "./pin";
