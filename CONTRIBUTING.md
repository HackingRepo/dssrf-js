# Contributing

:+1::tada: First off, thanks for taking the time to contribute! :tada::+1:

The following is a set of guidelines for contributing to url-sheriff.
These are mostly guidelines, not rules. Use your best judgment, and feel free to propose changes to this document in a pull request.

## Code of Conduct

This project and everyone participating in it is governed by a [Code of Conduct](./CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to contribute to dssrf-js

By contributing to dssrf you should not compromise those rules.

### Security
Ensure your changes do not introduce security risks or new ssrf bypasses to dssrf.

### Perfomance
Ensure your changes do not slowdown dssrf or make request longer.

### FPS
Ensure your changes not introduce false positives and block legitimate traffic and urls.

### Note
your changes will be introduced in the new version after accepted in the github repo not in the actual one.

### Tests

Make sure the code you're adding has decent test coverage.

Running project tests and coverage:

```bash
npm run test
```
