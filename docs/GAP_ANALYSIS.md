# GAP Analysis

Last updated: 2026-03-21

Repository status: bootstrapped from `../zig-template`; no Geode code has been moved yet.

## Goal

Extract reusable authentication primitives from Geode without carrying over Geode-branded tokens, feature flags, or product-specific policy wiring.

## Intended Boundary

Move into this library:

| Geode source | Why it belongs here |
|---|---|
| `src/security/api_keys.zig:43`, `:76`, `:130`, `:175`, `:203`, `:220`, `:277`, `:318` | Generic API-key management and parsing primitives once product branding is removed |
| `src/security/auth_hmac.zig:23`, `:39`, `:56`, `:121`, `:138`, `:143`, `:150` | Portable HMAC-chain helpers |
| `src/security/mfa.zig:13`, `:89`, `:141`, `:157` | Portable TOTP enrollment and verification logic if config is externalized |

Keep in Geode:

| Geode source | Why it stays |
|---|---|
| Feature-flag and product-policy wiring around MFA | `src/security/mfa.zig:3` through `:9` | This is product/runtime integration, not a generic auth primitive |

## Concrete Gaps

| Gap | Evidence | Impact | Required fix |
|---|---|---|---|
| API-key format is Geode-branded | `src/security/api_keys.zig:5`, `:6`, `:15` hardcode `gk1` | Prevents general reuse | Make token prefix configurable or neutral |
| Standalone review found a memory leak in API-key formatting flow | `src/security/api_keys.zig:252` through `:271` (`formatApiKey`) | Blocks production-grade extraction | Fix ownership/leak before extraction |
| MFA logic is tied to Geode feature flags and naming | `src/security/mfa.zig:3` through `:9`, `src/security/mfa.zig:71` | Couples library behavior to Geode runtime config | Replace feature flags and hard-coded salts with explicit config |

## Tests And Benchmarks To Carry Over

| Geode test / benchmark | Coverage provided |
|---|---|
| `src/security/api_keys.zig:338`, `:365`, `:379`, `:401`, `:416`, `:437`, `:453`, `:470`, `:475`, `:484`, `:490`, `:496` | API-key lifecycle and parsing behavior |
| `src/security/auth_hmac.zig:158`, `:165`, `:172`, `:183`, `:196`, `:211`, `:221`, `:232`, `:239`, `:245` | HMAC derivation, record hashing, chain hashing, and encoding |
| `tests/test_auth_mfa_flows.zig:19`, `:32`, `:62` | MFA enrollment and auth-flow integration |
| `tests/test_recovery_codes.zig:7` | Recovery-code flow |
| `build.zig:1293` through `:1299` | MFA step-up latency and recovery-code contention benchmark hooks |

## Proposed Public API

Initial public surface should include:

- `ApiKeyManager`
- `parseApiKey`
- `parseBearerToken`
- HMAC-chain helpers
- optional MFA/TOTP module with explicit configuration

## Extraction Plan

1. Generalize API-key prefixes and token formatting.
2. Fix the API-key memory leak.
3. Extract HMAC primitives first because they are already the cleanest candidate.
4. Extract API-key logic next.
5. Extract MFA only after feature-flag and salt configuration are externalized.

## Acceptance Criteria

- No Geode-specific token branding remains in the core API.
- API-key tests pass without leaks.
- MFA logic is configured explicitly rather than through Geode feature flags.
- Geode keeps policy- and user-store-specific auth logic outside the library.
