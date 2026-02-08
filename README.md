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

## Support DSSRF with Bitcoin

DSSRF has reached **12K downloads** and is trusted by the community (OWASP listed, starred by BitBuilder Cloud, verified clean by Snyk).  
If you’d like to support development with Bitcoin, you can send donations to:

**BTC Addresses (SegWit bech32):**
- bc1qeqct6n3kncynvdjls4yv9r6patpfcufp24gvk3

- bc1q6k2mfrd3qsttw43zg5dnuvlmdscfa8pgvkxw9f

- bc1qvgqnfr3znuqyaatm06ggftjxn0zx3unw5taa3h

- bc1qclj339c45s67w2q8ljwasef27qfcla9tdnmt07

*(More addresses available on request — these are derived from the project’s wallet for rotation and privacy.)*
`
You can also use bitcoin Lightning Network payment link `lnurlp://mainnet.demo.btcpayserver.org/BTC/UILNURL/2EYDhcF83tdF1Uadtr269Kn88Mxm1P4DpCSACspNasst/pay?currency=USD`.

and also you can use qr code.

[!Lighting qr](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEACAYAAABccqhmAAAQAElEQVR4AeyYwa7lNg5EG9kN8v+fGmQ509UdAx6m6CteWbZkn8Gw71O5RFJHARf646+//v4vAQP+G3jnfwN//OB/EIDAawkwAF579RwcAj9+MAD4rwACLyWgYzMARIGAwEsJMABeevEcGwIikA6AP//8z48ZQ027GNGrqyOtUkv+GNn+6NPaeaW3htsvrXX/1T711hOj+nU9ZbWcdwbN9ZsOAGdGgwAEnkFgOwUDYCPBLwReSIAB8MJL58gQ2AgwADYS/ELghQRKA+Cvv/7+cWVU7qO1ryyn23+G1z3+ZHlbdZcz09y5pGX+Xr33DOqtJ1rrH/kcA9fTUY74ze0fqcX6+/X+79IA2G/kbwhAYH0CDID175ATQOBrAgyAr9GxEQLrE2AArH+HnAACzQSikQEQibCGwIsInDIA3KtpRbuSd/byWunXebMzuHqZtzWvyynN5XU5pckfw+2XFn1Ha/ljqF6M6Dlax73frI/y3/ntm7Ps9/T2fsoA6G2C/RCAwD0EGAD3cKcqBC4n4AoyABwVNAi8hAAD4CUXzTEh4Ag8ZgDsH0a++fvoYavnm+vFXYQ0V0d6DJdTWvQdreWP4epLc3ni3m3tvMrRGm5/RcvqVHI473a+/a/zraY9ZgCsBp5+IXAlgawWAyAjgw6BFxBgALzgkjkiBDICDICMDDoEXkCAAfCCS+aI7yZwdPpHDwD3InwEI37bv/ju/46+kWt3hkzr7WN/xk9/Z7XcvszrdLf/jPO6vJnm+nqq9ugB8NRL41wQOIsAA+AskuSBwIIEGAALXhotQ6CVwCcfA+ATIb5D4MEEThkA2SNNqz4DX/cglPXv+nX7pTlvpskfw3mjZ1s7b3aGil7J67xbf/tf55Pm+trv2/8tf4z99/3fLm+vFmt/s767h1MGwDcHZw8EIHA/AQbA/XdABxAYQqAlKQOghRIeCDyUAAPgoRfLsSDQQoAB0EIJDwQeSqA0APavqlf8fSVz9xqbnbHSl8ub7Xde14PzScvyOt3ldb4zNPUWw9WXVqkXc2pd2a96LlyOVp/bK83tH6mpZkuUBkBLQjwQgMA6BBgA69wVnULgdAIMgNORkhAC6xBgAKxzV3QKgSYCFVM6APSgMmNUDuceWbIzubyZ1+V1+6taa17nk1ap585W2a96LlwO53P1pfV6Xf1MUz0Xzt/q017nnUFTbzHSARCNrCEAgecRYAA87045EQSaCTAAmlFhhMD8BKodMgCqxPBD4EEEGAAPukyOAoEqgXQAuNfYanLnr+R13kxztdzLq/NJy/I63eXNNOXuCZe3ks/1X9VcPdeXNOetaMoRI+s3+o7WWY6V9ApHdy63Px0AzowGAQjMS+CbzhgA31BjDwQeQoAB8JCL5BgQ+IYAA+AbauyBwEMIDBsA7hFCmuMm3cXRo078VsnbWsvlzDSXM9Ni70drlyPrweU5w5vlGKG787pzSXPeSk/KMSJcD5U6br80d95Ni7+unnLEGDYAYiHWEIDAfAQYAPPdCR1B4DICDIDLUFMIAvMRYADMdyd0BIESgR7zKQMgPkBoXWnKPVhIU57WaK2nvC5a95/haz2TfHf3qvP29uD262wunFc9uHBel1Oa259p8vdElndG/ZQBMOPB6AkCEPhMgAHwmREOCDyWAAPgsVfLwd5AoPeMDIBeguyHwMIEGAALXx6tQ6CXQGkAZC+jlSYqL7fOm2mtPVTOkNVyOTJvr16p5Rhk9Xu9br80V8+dQV4XzlvRXP1Mc/UzzeXIvL26q1XVWnsoDYDWpPggAIHxBM6owAA4gyI5ILAoAQbAohdH2xA4gwAD4AyK5IDAogTSAVB5dHBnz/ZXvJXHH5d3lObOVqk16lwub9bXDF7Xm2ObaW5/prnzZpqr57zOl2luv7Ss30/6Wd/TAXBWAfJAAALzEmAAzHs3dAaB4QQYAMMRUwAC8xJgAMx7N3QGAUvgTJEBcCZNckFgMQLpANALZYzK2eLebV3Jkb2oOt3ldb5M2/rb/7qcmbbf9+nvrIdWPcvveqt43f5My/K2niHLW9FdrUpfvbWy/a4H16s0583yVvTWvOkAqBTDCwEIrEmAAbDmvdH1SwmcfWwGwNlEyQeBhQgwABa6LFqFwNkESgPAPSxIc03pgcOF8ypHa7j90nprKUeMrKfoO2ud1Yu6O2umZb05f6yzrV0Ot1/atmf/27t/n+vT3+rBhesh01wN53U+aaO8yt0arQxKA8AdDA0CELiGwIgqDIARVMkJgUUIMAAWuSjahMAIAgyAEVTJCYFFCDAAFrko2nw3gVGnTweAe0XMtFHNuXrZK2hvD65Wprlamdfpbn+muf0ZA6e7/dKyer26csdwfWVa3FtdZ3l7z1XZ73rO9jtvprkcFa/bnw4AZ0aDAASeRYAB8Kz75DQQKBFgAJRwYYbA9QRGVmQAjKRLbghMTqA0ACoPLJnX6dlDRq+3wt7Vquw/w+s4nJG3NYerL83td7wyTTliuJzSshxOl39ExF61rtSp9Frxuh7cfmnO67TSAHAJ0CAAgXUJMADWvTs6fwGB0UdkAIwmTH4ITEyAATDx5dAaBEYTYACMJkx+CExMIB0AekmMkZ1Dr6Q9Eetsa5cz66FXH1VrO8v+t9Lrft/2t+s10yq1zvC6Plxe55PmvJm28dj/KoeLvWf7O8vr9G3P/tfVkeb2S2+NrUb8dftdrYqWDoBKErwQgMCaBBgAa94bXUPgFAIMgFMwkgQCaxJgAKx5b3T9cAJXHS8dAJUHh/hYcbSuHMzlqex3Xncuac6baSP6ymqptxiZ9+6+1KfrrdKXcsRwOTPN1ZIWc2qd5RihqwcXlVpuv87hwnldrXQAODMaBCDwLAIMgGfdJ6eBQIkAA6CECzMExhO4sgID4Era1ILAZARKA8A9NmRads7Wxwntd7ndfmnyt4S8Ltxe55PmvGdoyt0TlR4qdSr34PKO2K+clfOO8LqzSuutpbO56M3r9pcGgEuABgEIrEuAAbDu3dH5AwlcfSQGwNXEqQeBiQgwACa6DFqBwNUEGABXE6ceBCYikA4AvWb2xBlndPV787rXVWmulvTWcPuljei3klM9uOjNke13vFx958u0Sq1Kjoo366FX37PZ/s5yun63PfE3yxH1dABEI2sIQOB5BBgAz7tTTgSBZgIMgGZUGCHwPAIMgOfdKSdakMBdLZcGgHuEkOaal+6i4nX7M83ljQ8jR2uXN/O7WplWyeu8Lq/zSat45W+NSt5Wr/NVNXc/WQ7nrWgubyu/I5/Lm/XlvEe54ze3vzQAXAI0CEBgXQIMgHXvjs4h0E2AAdCNkAQQ6CNw524GwJ30qQ2BmwkwAG6+AMpD4E4C6QCIL4haV14nzziUq3dG3t4cri/xcVGp5fK6/c4nzXkzTf4YmXeEHmtv6xG1qjmvusdqXxujlt/W3OkAaE2ADwIQ+J7A3TsZAHffAPUhcCMBBsCN8CkNgbsJMADuvgHqQ+BGAqUB4B5HpLn+s4cK58005Y6ReUfosfbRulL/KE/85vJGz7Z23kzb9ux/M6/Ts/tt1fd193+37pfP9ZVp+xqf/s5ytOouv9ubaW5/VROfGK5eaQC4BGgQgMC6BBgA694dnUOgmwADoBshCSCwLgEGwLp3R+cLE5ildQbALDdBHxC4gcAUAyC+Vn6zduzcy6nzSavUlD9GZX/mjTm1dl7preH2VzVXy7HNNLc/07IcTs9yON2d2fkqmstZ1Vy9LEev1+2fYgC4xtAgAIHxBBgA4xlTAQL/R2CmBQNgptugFwhcTIABcDFwykFgJgLpAMgeIpxeeaBx3orWC++MWq0MKrXkdXkr51WOGL37lc/lcL1mmnLEcDmlZTmcLn8M55MWfUdr+WMc+eO3eFato2db61uM7Vv8jT1pHT3bOubUevu2/00HwN7E3xCAwDkEZsvCAJjtRugHAhcSYABcCJtSEJiNAANgthuhHwhcSIABcCFsSr2bwIynv3wA6OUyRgYm+rTOvFfqelGNkdVXz60Rc2qd5XW6q6McreFyZlqWM/NH3fUqLfqO1lkPTj/KE7/17tc5YsQaR2tXP9OO8rR8u3wAtDSFBwIQuIYAA+AazlSBwJQEGABTXgtNPY3ArOdhAMx6M/QFgQsIDBsAlUeL+GCyrV2OjEmrd8sdf11el1Na3Ku12y9N/hjSR0Sso7V6a42sJ+WJkXmd7uo7X1VzeTOtmrvFH5l8s26pc+TJajoOLs+wAeCKoUEAAnMRYADMdR9080ACMx+JATDz7dAbBAYTYAAMBkx6CMxMIB0A2eOC090B3SOEtNb9yil/DOkuok9r53P1pTmvcriQP4bzZZqrVdGyvE7P8sb+tc68Tne1pDmvco+I3lrq14XL6zS3N9PcfmmZ3+nynx3pADi7EPkg8EYCs5+ZATD7DdEfBAYSYAAMhEtqCMxOgAEw+w3RHwQGEmAADIRL6ncTWOH0pQHgXiYzLXv1rUBxObL9rd6sX5fX5ZTmvJkmf2u4HG6v80mreB0H5XDhvK6WNLf/CZrOFqNyLsdQWsx5tJa/NVwe129pALgEaBCAwLoEGADr3h2dQ6CbAAOgGyEJIPBvAqsoDIBVboo+ITCAwLAB0PpYIZ97sJCmbzGku4g+rR0vt1ea82aacsdQDhdZjqt015M0Vz+eaVvLH2P7Fn9b8zqftJjvaC1/jCN//BbPtK1jzmy9+Vt+sxxOj31ua+fNtG3P/td5hw0AVwwNAhCYiwADYK77oJsHEFjpCAyAlW6LXiFwMgEGwMlASQeBlQgwAFa6LXqFwMkE0gGwfz3c/s5eOys9uRxb/vg7wlvpNfazrSs5Kt4t/6ffLOenffvvjm2m7fdtf2c9uByZ1+luf0VzOaW5HNJ7YmOx/83+zuo4v+tVmssh3YXzOi0dAM6MBgEIPIsAA+BZ98lpIFAiwAAo4cIMgWcRYAA86z45zY0EVixdGgDuwUJa5RFC/hhuv7To07oCWTliKIcLlzfuPVq7nFXtKP+339y5pLnepLtwtZ1vlOZ6lTaq3pvylgbAm8BwVgi8gQAD4A23zBkhkBBgACRgkCFQIbCqlwGw6s3RNwROIMAAOAEiKSCwKoHSAHCvwdLc4aW7cN5M692vl+IYLqe0rIdWXTl6I/aqtasvvTWynip5nbeiuR4q+8/wOl5Z3orX5bjyvK5Xaa09lAaAOywaBN5OYOXzMwBWvj16h0AnAQZAJ0C2Q2BlAgyAlW+P3iHQSSAdAK2PCJ31D7frMSPG4Ybw0Z0h5jtah3SHy6M8rd9a+80aad2vfrIcrbqrJU25z47Wno586i3Gkb/1W68v9qR1xk/fYvTWTwdAb2L2QwAC8xNgAMx/R3QIgWEEGADD0JIYAvMTYADMf0d0OCmBJ7TFAHjCLXIGCHxJoDQAstfJil7pM754Hq1dXtdXlqN1v8spLctb0ZUnRmW/O0O233kzLfakHccAXQAABJlJREFUdeZ19ZzX+aQ5b0VTDhfqOUaW1+13XueTFuto7fZL07cYyuEi+rR2PmnK3RKlAdCSEA8EILAOAQbAOndFpxMReEorDICn3CTngMAXBBgAX0BjCwSeQiAdAHpgiKHHhdY4A1Csr3WWV99iuF6z/c6baVmOXt3Vi2c6a93ba7bf9ee8zifNec/QKmxdPfXWGm7/rFo6AGZtmL4gcDeBJ9VnADzpNjkLBIoEGABFYNgh8CQCDIAn3SZngUCRQDoA3KNJJbfbn2lZXufPvE5vfbSRr7K/4lXunnC1KppjWNVcvexMzuu0ag/On/XQqru+Pmn7766nqrbPt/2d9b99P/M3HQBnFiEXBCAwJwEGwJz3QlcQuIQAA+ASzBSBwJwEGABz3gtdTUjgiS0xAJ54q5wJAo0E0gGQvUTerTeeK7Vlr7TuXJk3Td74IcvbqjeWObS58x5uaPzoztC49ZfN9ZVpvzY0/tPbV2OZXzbX768Pjf+4XjPN1ZLWWOpHOgBaE+CDAATWJcAAWPfu6PxCAk8txQB46s1yLgg0EGAANEDCAoGnEigNgOwhYpRege56qOwf5X1bX3qAitHL1jGUVskbe9I6269vMTKv09VbDOebQSsNgBkapgcIXE3gyfUYAE++Xc4GgQ8EGAAfAPEZAk8mwAB48u1yNgh8IMAA+ACIz+8m8PTTnzIA4otpdX0GZFfT5XU+afHVVmu3P9Pkd+H8quei1et8mebqVLUst9NbGbi90ir7K17ljuH2S4u+bF3l6Pwut/NJc17160L+GG7/KQPAJUaDAATmJ8AAmP+O6BACwwgwAIahJfHqBN7QPwPgDbfMGSGQEHjMAHAPIe7MzifNeTNN/hjxweVoneUdocc+R6/duV1N55NWYSB/jMr+zOv6rWgub7a/4o1nPVq7eq7WYwaAOxwaBCBwTIABcMyHry8l8JZjMwDectOcEwKGAAPAQEGCwFsIMADectOcEwKGwKMHQOtLqOFyKLnX12xDpYfWvC5npmV9tdbK9vfqWb+ur0zLcji90q/zuh6cT1qlvvO6WtKUO4bbLy36svWjB0B2aHQIQOA3AQbAbw78C4FXEmAAvPLaOTQEfhNgAPzmwL8Q+EXgbf+cMgD06NATo6Dr4STGqFpZ3lhf68zrdMfV+aQpd2vIPyJcv609yef2Z5r8reFytO6Vz7GS7qLibd2vnO4M0nvilAHQ0wB7IQCB+wgwAO5jT2UI3E6AAXD7FdDALATe2AcD4I23zpkh8A8BBsA/IPiBwBsJlAaAe7EcqVUuxPXRu9/llFZ5jXXeiqZ6MSrn6q2l2q6edBfO63pwvjM0V0uayy3dhfP2aq6ONJdXugvnzbTWuykNgKwYOgRWJ/DW/hkAb715zg2BnwQYAD8h8H8IvJUAA+CtN8+5IfCTQDoA3CPEDNrPnu3/W3uzm3+Krfvl+2n/1/+lu/iXsShUcla8rg23X1qvd8R+5VRvMaRXI/pjzuo65jtau9xH/tZvrXnTAdBaCB8EILAuAQbAundH5xDoJsAA6EZIAgisS4ABsO7d0fkJBN6e4n8AAAD//4+jcb8AAAAGSURBVAMAEJw/HSmqO4AAAAAASUVORK5CYII=)
