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
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/689b3017ed47440386ac9903369969a5)](https://app.codacy.com/gh/HackingRepo/dssrf-js/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

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

