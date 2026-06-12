# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.7] - 2026-06-12

### Added

- Working basic example wired into `zig build example`
- Adversarial integration coverage (malformed keys, MFA config edges, recovery + replay lifecycle)

### Changed

- Explicit error sets on all public fallible functions (breaking API cleanup)
- Thread-safe `ApiKeyManager` with owned `validateKey` copies and optional pepper + max\_keys
- MFA `verifyCodeOnce` replay rejection and matched TOTP timestep exposed
- TOTP hot-path base32 decode moved to stack buffer (zero heap per verify)

### Fixed

- HMAC total sort order (key, value) — deterministic HMAC for duplicate keys
- `ApiKeyManager` cleanup reclaims revoked tombstones (max\_keys recovery)
- RFC 4648 base32 padding symmetry + exact-length decode (all 7 test vectors)
- `verifyScratchCode` release-mode length guard, TOCTOU/normalization docs, error-path zeroization
- CSPRNG recovery codes (160-bit, single-use, constant-time) replacing predictable codes
- `io.randomSecure` for credential generation — fail closed on entropy starvation
- `MfaConfig` validation rejects `digits=0` silent bypass

### Security

- Gate deterministic MFA secrets to test builds only
- Scratch code zeroization in `Enrollment.deinit` before free

### Documentation

- Comprehensive usage guide (token format config, HMAC chains, MFA knobs, recovery/replay lifecycle)
- Gap closure round 1 audit + refreshed gap analyses

## [0.1.6] - 2026-06-02

### Changed

- Converge `tls` dep onto v0.1.9 to resolve GAP-0838 diamond sync

## [0.1.5] - 2026-05-31

### Changed

- Converge dependency graph pins across four iterations
- Bump release to v0.1.5 (tagged sibling deps)

## [0.1.4] - 2026-05-02

### Changed

- Converge sibling dependency pins; release v0.1.4

## [0.1.3] - 2026-05-02

### Fixed

- Hardcode `enabled=false` to dodge Zig 0.16 `build_options` dedup regression; bump v0.1.3

## [0.1.2] - 2026-05-02

### Changed

- Bump release to v0.1.2 (tagged sibling deps)

## [0.1.1] - 2026-05-02

### Changed

- Bump release to v0.1.1 (tagged sibling deps)

## [0.1.0] - 2026-05-02

### Added

- HMAC-SHA256 record hashing, HKDF key derivation, and chain tamper detection
- API key management (create, validate, revoke, Bearer token parsing, scoped access)
- MFA/TOTP enrollment, code generation, and verification (RFC 6238)
- OpenTelemetry observability seam gated behind `-Dwith_otel` (no-op by default)
- Diamond-dep detector pre-commit hook
- CI/CD pipeline with Zig 0.16.0 runners
- Standardised `.pre-commit-config.yaml` from geode upstream

### Fixed

- Zig 0.16.0 compatibility (`Thread.Mutex` → `Io.Mutex`, `Mutex.lock`/`init` API updates)

[Unreleased]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.7...HEAD
[0.1.7]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.6...v0.1.7
[0.1.6]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.5...v0.1.6
[0.1.5]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.4...v0.1.5
[0.1.4]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.3...v0.1.4
[0.1.3]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.2...v0.1.3
[0.1.2]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.1...v0.1.2
[0.1.1]: https://gitlab.com/devnw/zig/auth/-/compare/v0.1.0...v0.1.1
[0.1.0]: https://gitlab.com/devnw/zig/auth/-/releases/v0.1.0
