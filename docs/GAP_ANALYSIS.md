# Gap Analysis

Last updated: 2026-03-23

> This file contains ONLY open gaps. Resolved items are in
> [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

## Implementation Status Summary

| Metric | Count |
|---|---|
| Total requirements | 15 |
| Fully implemented | 11 |
| Not implemented | 3 (AUTH-DOC-001 through DOC-003) |
| Deferred | 1 (AUTH-TEST-004 benchmarks) |
| Unit tests passing | 47 |
| Integration tests passing | 12 |
| Total tests passing | 59 |
| Memory leaks | 0 |
| Geode-branded strings in source | 0 |
| Code formatting issues | 0 |

## Requirements Tracker

### Functional Requirements

| ID | Issue | Title | Status |
|---|---|---|---|
| AUTH-REQ-001 | [#1](https://gitlab.com/devnw/zig/auth/-/issues/1) | Expose reusable API-key management and parsing primitives | Implemented |
| AUTH-REQ-002 | [#2](https://gitlab.com/devnw/zig/auth/-/issues/2) | Expose portable HMAC-chain helpers | Implemented |
| AUTH-REQ-003 | [#3](https://gitlab.com/devnw/zig/auth/-/issues/3) | MFA/TOTP support must be explicitly configured and reusable | Implemented |
| AUTH-REQ-004 | [#4](https://gitlab.com/devnw/zig/auth/-/issues/4) | No hardcoded Geode-branded token prefixes | Implemented |
| AUTH-REQ-005 | [#5](https://gitlab.com/devnw/zig/auth/-/issues/5) | No dependency on Geode feature flags or product salts | Implemented |

### Packaging Requirements

| ID | Issue | Title | Status |
|---|---|---|---|
| AUTH-PKG-001 | [#6](https://gitlab.com/devnw/zig/auth/-/issues/6) | API-key formatting must be leak-free | Implemented |
| AUTH-PKG-002 | [#7](https://gitlab.com/devnw/zig/auth/-/issues/7) | Extract HMAC helpers first (cleanest standalone candidate) | Implemented |

### Test Requirements

| ID | Issue | Title | Status |
|---|---|---|---|
| AUTH-TEST-001 | [#8](https://gitlab.com/devnw/zig/auth/-/issues/8) | Port API-key unit tests after fixing memory leak | Implemented |
| AUTH-TEST-002 | [#9](https://gitlab.com/devnw/zig/auth/-/issues/9) | Port HMAC-chain unit tests | Implemented |
| AUTH-TEST-003 | [#10](https://gitlab.com/devnw/zig/auth/-/issues/10) | Preserve MFA and recovery-code integration coverage | Implemented |
| AUTH-TEST-004 | [#11](https://gitlab.com/devnw/zig/auth/-/issues/11) | Preserve MFA benchmark references | Deferred (requires Geode runtime) |

### Documentation Requirements

| ID | Issue | Title | Status |
|---|---|---|---|
| AUTH-DOC-001 | [#12](https://gitlab.com/devnw/zig/auth/-/issues/12) | Document token-format configuration | Not implemented |
| AUTH-DOC-002 | [#13](https://gitlab.com/devnw/zig/auth/-/issues/13) | Document HMAC-chain usage | Not implemented |
| AUTH-DOC-003 | [#14](https://gitlab.com/devnw/zig/auth/-/issues/14) | Document MFA configuration knobs replacing feature flags and salts | Not implemented |

### Migration Requirements

| ID | Issue | Title | Status |
|---|---|---|---|
| AUTH-MIG-001 | [#15](https://gitlab.com/devnw/zig/auth/-/issues/15) | Extraction plan - ordered migration of auth primitives from Geode | Implemented |

## Gaps

### GAP-0001: README Quick Start shows non-existent auth.init API
- **Issue:** [#16](https://gitlab.com/devnw/zig/auth/-/issues/16)
- **Category:** Docs
- **Severity:** High
- **Requirement source:** README.md Quick Start section; public API surface
- **Current state (evidence):**
  - `README.md:46-50` -- shows `auth.init(.{ .debug = true })` which does not exist in the library
  - `examples/basic.zig:18-20` -- commented-out code also references non-existent `lib.Config` and `lib.init`
  - No `init` symbol exported from any module in `src/`
- **Why this is a gap:** The primary onboarding path gives users code that fails to compile. The library exposes `auth.hmac`, `auth.api_keys`, and `auth.mfa` but no top-level `init`.
- **Impact/Risk:** First-contact developer experience is completely broken; users will hit a compile error on first attempt.
- **Recommended fix:** Replace the Quick Start snippet with a working example using real API exports (e.g., `ApiKeyManager`, HMAC derivation, or TOTP enrollment). Update `examples/basic.zig` to be functional.
- **Acceptance criteria:**
  - README Quick Start example compiles and runs against the current library
  - `examples/basic.zig` is a functional, non-template example
  - `zig build` succeeds with no warnings for the example

### GAP-0002: examples/basic.zig is non-functional template placeholder
- **Issue:** None (tracked as part of GAP-0001 #16)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** Developer onboarding; examples directory
- **Current state (evidence):**
  - `examples/basic.zig:11-24` -- all library usage is commented out; the example only prints a banner and exits
  - References `lib.Config` and `lib.init` which do not exist
- **Why this is a gap:** The example file exists but provides no guidance on how to use the library.
- **Impact/Risk:** Developers looking at examples for usage patterns find only a non-functional template.
- **Recommended fix:** Rewrite `examples/basic.zig` with working demonstrations of API key, HMAC, and MFA usage.
- **Acceptance criteria:**
  - Example imports and uses at least one real library export
  - Example compiles with `zig build`

### GAP-0003: docs/README.md links to 5 nonexistent files
- **Issue:** None (to be created)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** `docs/README.md` Table of Contents
- **Current state (evidence):**
  - `docs/README.md:9-13` -- links to `getting-started.md`, `api-reference.md`, `examples.md`, `architecture.md`, `faq.md`
  - All 5 files are missing from the `docs/` directory
- **Why this is a gap:** Every link in the docs Table of Contents is a dead link.
- **Impact/Risk:** Users navigating documentation hit 404s on every link. Low severity because the links are template content, not references to intended documentation.
- **Recommended fix:** Either create the linked files with real content, or remove the dead links and replace with links to existing documentation (GAP_ANALYSIS.md, REQUIREMENTS.md).
- **Acceptance criteria:**
  - All links in `docs/README.md` resolve to existing files

### GAP-0004: GAP_ANALYSIS.md test count was stale (45 reported, 46 actual)
- **Issue:** None (fixed in this update)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** GAP_ANALYSIS.md Completion Report
- **Current state (evidence):**
  - Previous `GAP_ANALYSIS.md` reported 45 total tests (37 unit + 8 integration)
  - Actual test run shows 46 total (37 unit + 9 integration)
- **Why this is a gap:** Documentation was out of sync with reality. One integration test was not counted.
- **Impact/Risk:** Minor confusion for anyone auditing test coverage.
- **Recommended fix:** Corrected in this file update. Counts now read 37 unit + 9 integration = 46 total.
- **Acceptance criteria:**
  - Test counts in this file match `zig build test` output

### GAP-0005: revokeUserKeys, listUserKeys, cleanupExpired have zero dedicated tests
- **Issue:** [#18](https://gitlab.com/devnw/zig/auth/-/issues/18)
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** AUTH-TEST-001 ([#8](https://gitlab.com/devnw/zig/auth/-/issues/8)); AUTH-REQ-001 ([#1](https://gitlab.com/devnw/zig/auth/-/issues/1))
- **Current state (evidence):**
  - `src/api_keys.zig` -- `revokeUserKeys`, `listUserKeys`, `cleanupExpired` are public exports
  - 13 existing API-key tests cover creation, parsing, formatting, prefix config, bearer token parsing
  - No test named or structured around these three functions
- **Why this is a gap:** Key lifecycle functions (revocation, listing, expiration cleanup) are untested in isolation. Revocation bugs are a security-adjacent risk.
- **Impact/Risk:** A regression in revocation logic could leave revoked keys active. Untested cleanup could cause premature key expiration or memory issues.
- **Recommended fix:** Add at least 2 dedicated tests per function (6 total minimum) covering normal operation, empty/no-op cases, and correctness verification, all under `std.testing.allocator`.
- **Acceptance criteria:**
  - At least 6 new dedicated tests (2 per function)
  - Tests run under `std.testing.allocator` to detect leaks
  - All tests pass in `zig build test`

### GAP-0006: No base32 RFC 4648 test vectors
- **Issue:** None (to be created)
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** AUTH-REQ-003 ([#3](https://gitlab.com/devnw/zig/auth/-/issues/3)); RFC 4648 Section 10
- **Current state (evidence):**
  - `src/mfa.zig` exports `base32Encode` and `base32Decode`
  - Existing MFA tests exercise TOTP enrollment and code verification, which use base32 internally
  - No test directly validates against the RFC 4648 Section 10 test vectors
- **Why this is a gap:** Without canonical test vectors, subtle encoding/decoding bugs (padding, case sensitivity, alphabet mismatches) could go undetected.
- **Impact/Risk:** A base32 encoding bug would cause TOTP secrets to be unreadable by standard authenticator apps, silently breaking MFA enrollment for users.
- **Recommended fix:** Add a test that validates `base32Encode` and `base32Decode` against all RFC 4648 Section 10 test vectors: `""`, `"f"`, `"fo"`, `"foo"`, `"foob"`, `"fooba"`, `"foobar"`.
- **Acceptance criteria:**
  - All 7 RFC 4648 Section 10 encode/decode pairs pass
  - Round-trip property: `base32Decode(base32Encode(x)) == x` for all test vectors

## Public API (Implemented)

| Module | Exports |
|---|---|
| `auth.hmac` | `deriveHmacKey`, `computeRecordHmac`, `computeChainHash`, `verifyHmac`, `hmacToHex`, `hexToHmac`, `HkdfConfig`, `KeyValue` |
| `auth.api_keys` | `ApiKeyManager`, `parseApiKey`, `parseBearerToken`, `formatApiKey`, `Config`, `ApiKey`, `ParsedApiKey` |
| `auth.mfa` | `enroll`, `generateCode`, `verifyCode`, `base32Encode`, `base32Decode`, `MfaConfig`, `Enrollment` |
