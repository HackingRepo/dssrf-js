# dssrf — Safe‑by‑Construction SSRF Defense for Node.js

`dssrf` is a priotized security‑first URL and network validation library designed to eliminate entire classes of SSRF vulnerabilities - from basic bypasses to extremely advanced bypass techniques used in real‑world attacks.

It provides a small set of **strict, deterministic, safe‑by‑construction** functions that developers can use to validate untrusted URLs before making outbound requests.

If you only use the global function **`is_url_safe()`**, your application becomes SSRF‑resistant by default.

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

---



# Contributions
All contributions are welcome under the MIT license to me. 
