# ChangeLog

## 1.0.1

- Improved DNS rebinding protection timing window to resist against complex dns rebindings attacks.
- HTTP SSRF Redirect checks are disabled by default because it leaks the server ip and network connections and for privacy concerns reasons.
- Cleanuped unecessary dependencies

## 1.0.2

- Removed the `^` tag from package.json to improve supply chain security.
- Improved README.md and SECURITY.md formatting and mismatch between the content of README.md in NPM and Github
- Removed package-lock.json, Commited by mistake to the repo.
- Pinned SHA for workflows in Github Repo
