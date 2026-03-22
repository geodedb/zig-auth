# Requirements

Last updated: 2026-03-21

## Functional Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUTH-REQ-001 | The library SHALL expose reusable API-key management and parsing primitives. | `src/security/api_keys.zig:43`, `:76`, `:130`, `:175`, `:203`, `:277`, `:318` |
| AUTH-REQ-002 | The library SHALL expose portable HMAC-chain helpers. | `src/security/auth_hmac.zig:23`, `:39`, `:56`, `:121`, `:138`, `:143`, `:150` |
| AUTH-REQ-003 | MFA/TOTP support, if included, SHALL be explicitly configured and reusable outside Geode. | `src/security/mfa.zig:13`, `:89`, `:141`, `:157` |
| AUTH-REQ-004 | The library SHALL NOT hardcode Geode-branded token prefixes. | blocker `src/security/api_keys.zig:15` |
| AUTH-REQ-005 | The library SHALL NOT depend on Geode feature flags or product salts. | blockers `src/security/mfa.zig:3` through `:9`, `src/security/mfa.zig:71` |

## Packaging Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUTH-PKG-001 | API-key formatting shall be leak-free before extraction. | current blocker `src/security/api_keys.zig:252` through `:271` |
| AUTH-PKG-002 | HMAC helpers should be extracted first because they already compile cleanly standalone. | `src/security/auth_hmac.zig` standalone review passed |

## Test Requirements

| ID | Requirement | Geode evidence |
|---|---|---|
| AUTH-TEST-001 | Port API-key unit tests after fixing the memory leak. | `src/security/api_keys.zig:338`, `:365`, `:379`, `:401`, `:416`, `:437`, `:453`, `:470`, `:475`, `:484`, `:490`, `:496` |
| AUTH-TEST-002 | Port HMAC-chain unit tests. | `src/security/auth_hmac.zig:158`, `:165`, `:172`, `:183`, `:196`, `:211`, `:221`, `:232`, `:239`, `:245` |
| AUTH-TEST-003 | Preserve MFA and recovery-code integration coverage if MFA lands in this repo. | `tests/test_auth_mfa_flows.zig:19`, `:32`, `:62`, `tests/test_recovery_codes.zig:7` |
| AUTH-TEST-004 | Preserve MFA benchmark references. | `build.zig:1293` through `:1299` |

## Documentation Requirements

- Document token-format configuration.
- Document HMAC-chain usage.
- If MFA is included, document all explicit configuration knobs that replace the current feature-flag and salt assumptions.

## Migration Requirements

1. Extract `auth_hmac` first.
2. Fix and extract API-key logic next.
3. Extract MFA only after configuration and policy boundaries are explicit.
