# @digitalbazaar/http-signature-zcap-invoke ChangeLog

## 6.0.0 - 2022-06-07

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- Update dependencies.
- Remove unused dependencies.
- Lint module.
- Use static browser detection.

## 5.0.3 - 2022-02-02

### Fixed
- Fix typo in error message.

## 5.0.2 - 2022-01-30

### Fixed
- Fix typo in error message.

## 5.0.1 - 2022-01-11

### Changed
- Update dependencies.

## 5.0.0 - 2022-01-11

### Changed
- **BREAKING**: Rename package to `@digitalbazaar/http-signature-zcap-invoke`.

## 4.0.2 - 2022-01-11

### Fixed
- Fix usage of http-signature-header dep.

## 4.0.1 - 2022-01-11

### Changed
- Updated http-signature-header dep.

## 4.0.0 - 2022-01-11

### Changed
- **BREAKING**: Change default capability to use zcap root URN prefix instead
  of the url itself. Root zcaps must now be independent entities, an object
  cannot be its own root zcap.
- **BREAKING**: Require `capabilityAction` to be passed when signing an
  invocation.

### Removed
- **BREAKING**: Remove built-in URL and Web crypto polyfills. If support is not
  available on a platform supported by your application, add appropriate
  polyfills to your application.

## 3.1.0 - 2021-11-26

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
