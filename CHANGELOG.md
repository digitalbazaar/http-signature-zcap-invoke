# http-signature-zcap-invoke ChangeLog

## 3.1.0 -

### Added
- Add details to the error message (url, method, action).

## 3.0.0 - 2021-03-02

### Changed
- **BREAKING**: Use `http-signature-header` ^2.0.0.
- **BREAKING**: `created` and `expires` headers are now seconds since the epoch
  instead of ms since the epoch.

### Added
- New optional parameters `created` & `expires` added to `signCapabilityInvocation`.
- **BREAKING**: `created` defaults to a unix time stamp representing time of call.
- **BREAKING**: `expires` defaults to a unix time stamp 10 minutes after created.

## 2.0.0 - 2020-12-07

### Changed
- **BREAKING**: Drop support for node 10.
- Use `@digitalbazaar/http-digest-header`.

## 1.1.1 - 2020-02-10

### Fixed
- Use gzip to compress the `capability` in the Capability-Invocation header.

## 1.1.0 - 2020-02-07

### Added
- Implement embedded capabilities.

### Changed
- Improve test coverage.
- Use isomorphic-webcrypto@2.3.4.

## 1.0.0 - 2019-08-02

## 0.1.0 - 2019-08-02

### Added
- Add core files.

- See git history for changes previous to this release.
