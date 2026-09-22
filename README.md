# dssrf — SSRF defense for Node.js

[![npm version](https://img.shields.io/npm/v/dssrf)](https://www.npmjs.com/package/dssrf) 
[![npm downloads](https://img.shields.io/npm/dm/dssrf)](https://www.npmjs.com/package/dssrf) 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) 
[![Security](https://img.shields.io/badge/security-SSRF%20defense-critical)](#warning) 
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![Maintainability](https://img.shields.io/codeclimate/maintainability/relunsec/dssrf)](https://codeclimate.com/github/HackingRepo/dssrf-js) 
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-blue.svg)](#contributions)
[![Snyk Security](https://snyk.io/test/github/HackingRepo/dssrf-js/badge.svg)](https://snyk.io/test/github/HackingRepo/dssrf-js)
[![SLSA Level](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/HackingRepo/dssrf-js)
[![Install size](https://packagephobia.com/badge?p=dssrf)](https://packagephobia.com/result?p=dssrf)
[![Open Source Helpers](https://www.codetriage.com/hackingrepo/dssrf-js/badges/users.svg)](https://www.codetriage.com/hackingrepo/dssrf-js)
[![Contributors](https://img.shields.io/github/contributors/HackingRepo/dssrf-js)](https://github.com/HackingRepo/dssrf-js/graphs/contributors)
[![CodeQL](https://github.com/HackingRepo/dssrf-js/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/HackingRepo/dssrf-js/actions/workflows/github-code-scanning/codeql)
[![CodeQL Advanced](https://github.com/HackingRepo/dssrf-js/actions/workflows/codeql.yml/badge.svg)](https://github.com/HackingRepo/dssrf-js/actions/workflows/codeql.yml)
[![DevSkim](https://github.com/HackingRepo/dssrf-js/actions/workflows/devskim.yml/badge.svg)](https://github.com/HackingRepo/dssrf-js/actions/workflows/devskim.yml)
[![Node.js CI](https://github.com/HackingRepo/dssrf-js/actions/workflows/node.js.yml/badge.svg)](https://github.com/HackingRepo/dssrf-js/actions/workflows/node.js.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`dssrf` validates untrusted URLs before your application fetches them, and, as of 2.0.0, can perform the fetch
itself with every hop pinned to an address it has already checked.

**One runtime dependency** (`ipaddr.js`). No native addon, no install scripts.

Also the package moved from `dssrf` to a scope, please update for anyone your package.json, to use `@insitetechjp/dssrf`, other releases are not republished, however it is recommended to update to that release

---

## Two ways to use it

### `safe_fetch()`, recommended

Resolves once, validates every address, and connects **by address**. The hostname never reaches a connect call, so
there is no second resolution for a DNS rebinding attack to poison. Redirects are followed manually and each hop
re-enters the same checks, so an open redirect into `169.254.169.254` is refused on the hop that reaches it.

```js
const { safe_fetch, SsrfRefused } = require("@insitetechjp/dssrf");

const userUrl = "https://169.254.169.254/metadata"

try {
  const res = await safe_fetch(userUrl);
  console.log(res.status, res.body, res.chain);   // chain shows every hop and the address used
} catch (err) {
  if (err instanceof SsrfRefused) {
    // err.reason distinguishes a policy block from a no reachable url
  }
}
```

### `is_url_safe()`, unchanged, for existing code

```js
const { is_url_safe } = require("@insitetechjp/dssrf");

const userUrl = "https://169.254.169.254/metadata"

if (!await is_url_safe(userUrl)) {
  throw new Error("This URL cannot be fetched.");
}
```

That is the classical function, kept for compability reasons. It validates a *string*; your HTTP client then resolves the hostname
again when it connects. That gap is the reason `safe_fetch()` exists, and it cannot be closed by a function that
returns a boolean, that why we recommend migrating from it.

CRITICAL: The `is_url_safe` function is vulnerable to DoS, that cannot be patched, meaning a malicious server that hangs forever, an attacker can freeze your app, besides that the dns rebinding protection, that design we choosed
before is wrong, and can be bypassed via sophisticated dns rebinding attacks anyway, We recommend migrating to `safe_fetch`

---

## Refusing is not accusing

`safe_fetch` throws `SsrfRefused` with a `reason`, so an application can tell a security event from a typo:

| `reason` | Meaning | Show the user |
| --- | --- | --- |
| `host-not-found` | The name does not exist | "We couldn't reach that address." **Not an attack, That is a legitimate user typo or the url is not available anymore.** |
| `resolution-failed` | The resolver could not answer | **Try again shortly.** |
| `internal-address` | Resolved into blocked space | **An SSRF Attempt Blocked** |
| `scheme-not-allowed`, `userinfo-present`, `port-not-allowed` | Policy | **That is an attempt to escalating SSRF** |
| `redirect-without-location`, `too-many-redirects`, `response-too-large`, `timeout` | Transport | **Normal but unusual, it common to see in broken non compliant servers, if it is 304 it is expected** |

A single boolean cannot make this distinction, which is why a UI built on `is_url_safe()` tends to accuse people
who mistyped a domain.



## API

| Function | Notes |
| --- | --- |
| `safe_fetch(url, options?)` | Pinned fetch. It supports the following options `ports`, `allow`, `method`, `headers`, `maxRedirects`, `timeout`, `totalTimeout`, `maxBytes` |
| `resolve_and_pin(url, options?)` | Resolve + validate only; returns `{ url, hostname, port, addresses, servername }` for use with your own client |
| `is_url_safe(url)` | The legacy ssrf boolean function |
| `is_redirect_safe(url, options?)` | Walks a redirect chain. Probes with **GET** and only when `DSSRF_MAKE_REQUEST=1` or the config `{ makeRequest: true }` |
| `is_hostname_resolve_to_internal_ip(host)` | True when the host must not be reached |
| `resolve_host(host)` | `{ kind: "addresses" \| "nxdomain" \| "unknown" }`, That is a new api |
| `is_ip_internal(ip)` | That API is present to check is a literal ip internal |
| `is_range_not_internal(cidr)` | Accepts a CIDR string or any `{ start(), end() }` object |
| `is_ipv6`, `normalize_ipv4`, `normalize_schema`, `is_proto_safe`, **Essential utilities, kept**

Ports default to 80 and 443 in `safe_fetch`; widen with `ports: [8080]`. `allow: ["10.2.0.7:5432"]` is an explicit
carve-out for your own services and should never be built from user input. Entries **must name a port number**, just a bare
address would permit every port on that host, and the allowlist applies to each redirect hop, so a redirect could
then reach any of them. `totalTimeout` (default 30s) bounds a whole redirect chain, not just each hop.

`safe_fetch` sets the `Host` header from the pinned target and ignores a caller-supplied `host`, so the Host cannot
be decoupled from the address that was validated.

## Limits

Stated plainly, because a security library that hides them is worse than none.

- **`is_url_safe()` still has a check-to-connect gap.** It is kept for compatibility. Please Use `safe_fetch()`, That function have security risks, that you must consider.
- **`is_redirect_safe()` does not inspect redirects by default.** It validates the first hop and returns unless
  `DSSRF_MAKE_REQUEST=1` or `{ makeRequest: true }` is passed.
- **Public destinations are not restricted.** An attacker can still point you at any *public* host. Destination
  allowlisting is a separate control, as we saw in [sandssrf](https://github.com/HackingRepo/sandssrf-js) that is another problem.
- **Only http and https.** For other protocols use `resolve_and_pin()` and connect yourself, and note that
  protocol-level redirection, Raw sockets not supported unlike [sandssrf](https://github.com/HackingRepo/sandssrf-js) which have a raw socket connect.
- **Proxies defeat pinning.** `safe_fetch` connects directly and ignores `HTTP_PROXY`. If your egress requires a
  proxy, the proxy resolves the hostname and the pin is meaningless.
- **The range list still matters.** Classification is total over the ranges it is given; those follow the IANA
  special-purpose registries and need to be kept current.
- **No connection reuse.** A fresh agent per request, because a pooled socket performs no connect for anything to
  check.
- **Parsing Flaws**: While we do'nt discover anything at the moment, but they a lot develop and exist, That why we created [sandssrf](https://github.com/HackingRepo/sandssrf-js), to solve the problem

## Reporting

See [SECURITY.md](SECURITY.md) for report a vuln, for security researchers.

