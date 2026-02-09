# dssrf — Safe‑by‑Construction SSRF Defense for Node.js

[![npm version](https://img.shields.io/npm/v/dssrf)](https://www.npmjs.com/package/dssrf) 
[![npm downloads](https://img.shields.io/npm/dm/dssrf)](https://www.npmjs.com/package/dssrf) 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) 
[![Security](https://img.shields.io/badge/security-SSRF%20defense-critical)](#warning) 
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)
[![Maintainability](https://img.shields.io/codeclimate/maintainability/relunsec/dssrf)](https://codeclimate.com/github/HackingRepo/dssrf-js) 
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json)](https://codspeed.io/HackingRepo/dssrf-js?utm_source=badge) 
[![Contributions welcome](https://img.shields.io/badge/contributions-welcome-blue.svg)](#contributions)
[![Snyk Security](https://snyk.io/test/github/HackingRepo/dssrf-js/badge.svg)](https://snyk.io/test/github/HackingRepo/dssrf-js)
[![SLSA Level](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/HackingRepo/dssrf-js)
[![Install size](https://packagephobia.com/badge?p=dssrf)](https://packagephobia.com/result?p=dssrf)
[![Open Source Helpers](https://www.codetriage.com/hackingrepo/dssrf-js/badges/users.svg)](https://www.codetriage.com/hackingrepo/dssrf-js)
[![Contributors](https://img.shields.io/github/contributors/HackingRepo/dssrf-js)](https://github.com/HackingRepo/dssrf-js/graphs/contributors)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11908/badge)](https://www.bestpractices.dev/projects/11908)

`dssrf` is a priotized security‑first URL and network validation library designed to eliminate entire classes of SSRF vulnerabilities - from basic bypasses to extremely advanced bypass techniques used in real‑world attacks.

It provides a small set of **strict, deterministic, safe‑by‑construction** functions that developers can use to validate untrusted URLs before making outbound requests.

If you only use the global function **`is_url_safe()`**, your application benefit all of those SSRF protections by default.

---

## Features

- **Unicode normalization (NFKC)** to prevent homoglyph attacks.
- **Strict IPv4 validation**  
  - exactly 4 octets  
  - no leading zeros  
  - no short forms  
  - no decimal/hex/octal/binary encodings  
- **IPv6 Denied completly**
- **Backslash and slash normalization**
- **Userinfo the at symbol stripped**
- **Scheme normalization and allowlisting**
- **DNS resolution with internal IP detection and DNS Rebiding detection**
- **Redirect safety**

---

## Installation and Usage

```bash
npm install dssrf
```

And in your web js app add

```js
import { is_url_safe } from "dssrf";

const url = await is_url_safe("https://example.com");

if (!url) {
  throw new Error("SSRF attempt Detected.");
}
```

or for CommonJS style

```js
const dssrf = require("dssrf");

const url = await dssrf.is_url_safe("https://example.com");

if (!url) {
  throw new Error("SSRF attempt Detected.");
}
```

## Contributions

All contributions are welcome under the MIT license to me. 

## Warning

- **Redirect Safety** By default, `is_redirect_safe()` will **not** make outbound requests unless you explicitly enable it with the environment variable `DSSRF_MAKE_REQUEST=1`. - When disabled, You loose redirect safety. - When enabled, `dssrf` performs controlled HTTP requests (HEAD with `followRedirect: false`) to inspect `Location` headers hop‑by‑hop. - This ensures accurate redirect validation but may expose your server's IP address and timing externally. Use only in environments where outbound validation traffic is acceptable, I recommend disabling it becauses expose your server ip and can cause slowdown and also port scanning/service discovery instead disable following redirects in your http client.

## Support DSSRF

DSSRF has reached **12K downloads** and is trusted by the community (OWASP listed, starred by BitBuilder Cloud, verified clean by Snyk).  
If you find DSSRF useful, consider sponsoring to help sustain development:  

- [Patreon](https://patreon.com/RelunSec)  
- [OpenCollective](https://opencollective.com/relunsec)  
- [Ko‑fi](https://ko-fi.com/relunsec)  

### Support DSSRF with Bitcoin

DSSRF has reached **12K downloads** and is trusted by the community (OWASP listed, starred by BitBuilder Cloud, verified clean by Snyk).  
If you’d like to support development with Bitcoin, you can send donations to:

**BTC Addresses (SegWit bech32):**
- bc1qeqct6n3kncynvdjls4yv9r6patpfcufp24gvk3

- bc1q6k2mfrd3qsttw43zg5dnuvlmdscfa8pgvkxw9f

- bc1qvgqnfr3znuqyaatm06ggftjxn0zx3unw5taa3h

- bc1qclj339c45s67w2q8ljwasef27qfcla9tdnmt07

*(More addresses available on request — these are derived from the project’s wallet for rotation and privacy.)*

You can also use bitcoin Lightning Network payment link `lnurlp://mainnet.demo.btcpayserver.org/BTC/UILNURL/2EYDhcF83tdF1Uadtr269Kn88Mxm1P4DpCSACspNasst/pay?currency=USD`.

Or via scan the qr code, in your mobile app via

![BTC Qr Code](https://github.com/user-attachments/assets/cba56b04-a1de-4431-b08e-17bd4db8c8cd)
