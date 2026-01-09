# ChangeLog

## 1.0.1
- Improved DNS rebinding protection timing window to resist against complex dns rebindings attacks.
- HTTP SSRF Redirect checks are disabled by default because it leaks the server ip and network connections and for privacy concerns reasons.
- Cleanuped uncessary dependencies
