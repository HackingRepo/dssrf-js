# ChangeLog

## 1.0.1

- Improved DNS rebinding protection timing window to resist against complex dns rebindings attacks.
- HTTP SSRF Redirect checks are disabled by default because it leaks the server ip and network connections and for privacy concerns reasons.
- Cleanuped unecessary dependencies

## 1.0.2

- Removed the `^` tag from package.json to improve supply chain security.
- Improved README.md and SECURITY.md formatting and mismatch between the content of README.md in NPM and Github
- Removed package-lock.json, Commited by mistake to the repo.
- Pinned SHA for workflows in the Github Repo

## 1.0.3

⚠️ Security Updates:
- Fix GHSA-8p33-q827-ghj5 vuln

### Other Changes
- That affects only build from source, fixed tsconfig.json, to allow build to successed
- Fix README.md, wrong claim for IPv6


## 1.0.4

⚠️ Security Updates:
- Fix GHSA-cg4g-m8jx-vjv2 vuln

### Other Changes
- Update SECURITY.md, to say to users patches will arrive with Tuesday matching the standard Patch tuesday


## 1.0.5

⚠️ Security Updates:
- Fix finded GHSA-5846-7qm3-r52j


## 1.0.6

### New IPs ranges added:
- 168.63.129.16/32 for microsoft azure, another ip, no longer for metadata
  but still reachable and have other useful informations to attackers
- added other special and reserved ips, while not malicious themselves, it is a good idea
  to add those, since have no legitimate reasons to be in there

### Other Changes
- Fix a typo in CONTRIBUTING.md, dssrf instead of url-sheriff
- Remove "I added a picture", from CONTRIBUTING.md, we forget it

