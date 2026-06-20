# Requirements

Last updated: 2026-06-12

## Functional Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUTH-REQ-001 | The library SHALL expose reusable API-key management and parsing primitives. | `src/api_keys.zig` |
| AUTH-REQ-002 | The library SHALL expose portable HMAC-chain helpers. | `src/hmac.zig` |
| AUTH-REQ-003 | MFA/TOTP support, if included, SHALL be explicitly configured and reusable outside Geode. | `src/mfa.zig` |
| AUTH-REQ-004 | The library SHALL NOT hardcode Geode-branded token prefixes. | Resolved — see docs/GAP_ANALYSIS_RESOLVED.md |
| AUTH-REQ-005 | The library SHALL NOT depend on Geode feature flags or product salts. | Resolved — see docs/GAP_ANALYSIS_RESOLVED.md (deterministic salts gated test-only) |
| REQ-AUTH-FIPS-001 | Security cryptography (HMAC-SHA256, HKDF-SHA256, SHA-256, CSPRNG) SHALL route through the `-Dfips` `crypto_backend` seam; TOTP HMAC-SHA1 is the single documented exemption (RFC 6238 legacy-interop); tests SHALL pass with `-Dfips` both off (std shim, default) and on (OpenSSL FIPS provider). | `src/crypto_backend.zig`, `docs/FIPS.md`, `tests/crypto_backend_seam_test.zig`, `tests/fips_exemption_test.zig` |

## Packaging Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUTH-PKG-001 | API-key formatting shall be leak-free before extraction. | Resolved — see docs/GAP_ANALYSIS_RESOLVED.md (formatting leak-free) |
| AUTH-PKG-002 | HMAC helpers should be extracted first because they already compile cleanly standalone. | `src/hmac.zig` standalone review passed |

## Test Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUTH-TEST-001 | Port API-key unit tests after fixing the memory leak. | `src/api_keys.zig` |
| AUTH-TEST-002 | Port HMAC-chain unit tests. | `src/hmac.zig` |
| AUTH-TEST-003 | Preserve MFA and recovery-code integration coverage if MFA lands in this repo. | `tests/integration.zig` (MFA + recovery-code lifecycle tests) |
| AUTH-TEST-004 | Preserve MFA benchmark references. | Deferred — tracked by issue #11 |

## Documentation Requirements

- Document token-format configuration. (Implemented — docs/USAGE.md; AUTH-DOC issue #12 closed)
- Document HMAC-chain usage. (Implemented — docs/USAGE.md; AUTH-DOC issue #13 closed)
- If MFA is included, document all explicit configuration knobs that replace the current feature-flag and salt assumptions. (Implemented — docs/USAGE.md; AUTH-DOC issue #14 closed)

## Migration Requirements

1. Extract `auth_hmac` first. (Complete)
2. Fix and extract API-key logic next. (Complete)
3. Extract MFA only after configuration and policy boundaries are explicit. (Complete)
