# Security Policy

The `dssrf` project is built with a strict security-first philosophy.  
Its purpose is to eliminate entire classes of SSRF vulnerabilities through network validation.

If you discover a bypass, weakness, or any behavior that could lead to SSRF or related security issues, please report it responsibly to me.

---

## Supported Versions

Security updates are provided for the latest published version of `dssrf`.

Please ensure you are using latest version of `dssrf` before submitting the report.

---

## Reporting a Vulnerability

If you believe you have found one of:

- an SSRF bypass  
- a normalization flaw  
- a DNS rebinding weakness  
- an unsafe redirect handling case  
- a Parser vulnerability

please report it privately to me.

### 📧 Contact

Send your report to the email **cs7778503@gmail.com**.

Please include:

- a clear description of the issue  
- reproduction steps  
- the exact payload or URL used  
- expected vs. actual behavior  
- environment details NodeJS version and os version

You will receive a response as quickly as possible between 1 day and 3 days or even in hours depends in my situation.

---

## Responsible Disclosure

To protect users of this library:

- Do **not** open public GitHub issues for security vulnerabilities.  
- Do **not** publish exploit details before a fix is released.  
- Coordinated disclosure is appreciated.

---

## Scope

The following areas are considered in-scope for security reports:

- URL normalization  
- Unicode handling  
- IPv4/IPv6 parsing  
- DNS resolution  
- Internal IP detection  
- Redirect safety  
- Protocol allowlisting  
- Any behavior that could allow SSRF attacks or bypass existing protections

Out-of-scope:

- Issues caused by misuse of the library  
- Vulnerabilities in third-party HTTP clients  
- Application-level logic errors outside of `dssrf`

---

## Thank You

Your efforts help keep the ecosystem safer and more secure.  
