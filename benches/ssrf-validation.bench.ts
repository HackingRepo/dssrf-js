import { bench, describe } from "vitest";
import {
  is_url_safe,
  is_ipv6,
  normalize_ipv4,
  normalize_unicode,
  is_proto_safe,
  replace_backslash_with_slash_in_string,
  remove_at_symbol_in_string,
  normalize_schema,
  octal_ip_to_normal_ip,
  hex_ip_to_normal_ip,
  decimal_ip_to_normal_ip,
  bin_ip_to_normal_ip,
} from "../src/utils";

describe("URL Safety Validation", () => {
  bench("is_url_safe - valid HTTPS URL", async () => {
    await is_url_safe("https://example.com/api/endpoint");
  });

  bench("is_url_safe - valid HTTP URL", async () => {
    await is_url_safe("http://example.com");
  });

  bench("is_url_safe - URL with path and query", async () => {
    await is_url_safe("https://api.example.com/v1/users?id=123");
  });

  bench("is_url_safe - suspicious URL with internal IP", async () => {
    await is_url_safe("http://127.0.0.1:8080/admin");
  });

  bench("is_url_safe - URL with unicode normalization", async () => {
    await is_url_safe("https://\uff45xample.com");
  });
});

describe("IPv6 Detection", () => {
  bench("is_ipv6 - valid IPv6", () => {
    is_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
  });

  bench("is_ipv6 - compressed IPv6", () => {
    is_ipv6("2001:db8::1");
  });

  bench("is_ipv6 - invalid input", () => {
    is_ipv6("192.168.1.1");
  });

  bench("is_ipv6 - malformed string", () => {
    is_ipv6("not-an-ip");
  });
});

describe("IPv4 Normalization", () => {
  bench("normalize_ipv4 - standard IP", () => {
    normalize_ipv4("192.168.1.1");
  });

  bench("normalize_ipv4 - IP with leading zeros rejection", () => {
    try {
      normalize_ipv4("192.168.001.1");
    } catch (e) {
      // Expected to throw
    }
  });

  bench("normalize_ipv4 - loopback address", () => {
    normalize_ipv4("127.0.0.1");
  });

  bench("normalize_ipv4 - boundary values", () => {
    normalize_ipv4("255.255.255.255");
  });
});

describe("Unicode Normalization", () => {
  bench("normalize_unicode - ASCII text", () => {
    normalize_unicode("https://example.com");
  });

  bench("normalize_unicode - NFKC normalization", () => {
    normalize_unicode("\uff45xample.com");
  });

  bench("normalize_unicode - mixed characters", () => {
    normalize_unicode("test\u00e9\u0301.com");
  });

  bench("normalize_unicode - empty string", () => {
    normalize_unicode("");
  });
});

describe("Protocol Safety", () => {
  bench("is_proto_safe - HTTPS", () => {
    is_proto_safe("https://example.com");
  });

  bench("is_proto_safe - HTTP", () => {
    is_proto_safe("http://example.com");
  });

  bench("is_proto_safe - file protocol", () => {
    is_proto_safe("file:///etc/passwd");
  });

  bench("is_proto_safe - ftp protocol", () => {
    is_proto_safe("ftp://example.com");
  });

  bench("is_proto_safe - javascript protocol", () => {
    is_proto_safe("javascript:alert(1)");
  });
});

describe("String Normalization", () => {
  bench("replace_backslash_with_slash - URL with backslashes", () => {
    replace_backslash_with_slash_in_string("http://example.com\\api\\endpoint");
  });

  bench("replace_backslash_with_slash - normal URL", () => {
    replace_backslash_with_slash_in_string("http://example.com/api/endpoint");
  });

  bench("replace_backslash_with_slash - multiple backslashes", () => {
    replace_backslash_with_slash_in_string("http://example.com\\\\\\api");
  });

  bench("remove_at_symbol - URL with @ symbol", () => {
    remove_at_symbol_in_string("http://user@example.com");
  });

  bench("remove_at_symbol - multiple @ symbols", () => {
    remove_at_symbol_in_string("http://user@@evil.com@example.com");
  });

  bench("normalize_schema - HTTPS URL", () => {
    normalize_schema("https://example.com");
  });

  bench("normalize_schema - HTTP URL", () => {
    normalize_schema("http://example.com");
  });

  bench("normalize_schema - invalid URL", () => {
    normalize_schema("not-a-url");
  });
});

describe("IP Encoding Conversions", () => {
  bench("octal_ip_to_normal_ip - standard conversion", () => {
    octal_ip_to_normal_ip("0300.0250.0001.0001");
  });

  bench("hex_ip_to_normal_ip - 0x prefix", () => {
    hex_ip_to_normal_ip("0x7f000001");
  });

  bench("hex_ip_to_normal_ip - no prefix", () => {
    hex_ip_to_normal_ip("c0a80001");
  });

  bench("decimal_ip_to_normal_ip - loopback", () => {
    decimal_ip_to_normal_ip("2130706433");
  });

  bench("decimal_ip_to_normal_ip - common IP", () => {
    decimal_ip_to_normal_ip("3232235777");
  });

  bench("bin_ip_to_normal_ip - full binary", () => {
    bin_ip_to_normal_ip("11000000101010000000000100000001");
  });

  bench("bin_ip_to_normal_ip - dotted binary", () => {
    bin_ip_to_normal_ip("11000000.10101000.00000001.00000001");
  });
});
