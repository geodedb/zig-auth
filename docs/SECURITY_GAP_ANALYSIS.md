# Security Gap Analysis

Last updated: 2026-03-23

## Summary

Security review of the `auth` library extracted from Geode. All findings are based on
source-level code review of `src/mfa.zig`, `src/api_keys.zig`, and `src/hmac.zig`.

| Severity | Count | Status |
|----------|------:|--------|
| Critical | 2 | Open -- SLA 7 days |
| High | 3 | Open -- SLA 30 days |
| Medium | 5 | Open -- SLA 90 days |
| Low | 3 | Open -- SLA 180 days |
| **Total** | **13** | |

### Top 5 Risks

1. **SEC-001** (Critical, RS 100) -- TOTP secrets are deterministic from public inputs; any user's MFA can be bypassed offline.
2. **SEC-002** (Critical, RS 80) -- Secret material is never zeroed in memory; recoverable from dumps/swap.
3. **SEC-004** (High, RS 70) -- `validateKey` returns a dangling pointer after mutex release; use-after-free under concurrency.
4. **SEC-005** (High, RS 70) -- `listUserKeys` shallow-copies structs with borrowed slice pointers; use-after-free.
5. **SEC-003** (High, RS 60) -- TOTP code comparison is not constant-time; timing side-channel.

## Stack-Ranked Findings

| Rank | Severity | Risk Score | Finding | Component | CWE / OWASP | Evidence | Issue | Fix | Owner | Due | Status |
|-----:|----------|:----------:|---------|-----------|-------------|----------|-------|-----|-------|-----|--------|
| 1 | Critical | 100 | Deterministic TOTP secret from username+salt, no server secret | mfa | CWE-330, CWE-321 / A02:2021 | `src/mfa.zig:102-107` | [#19](https://gitlab.com/devnw/zig/auth/-/issues/19) (confidential) | Generate random per-user secret via `crypto.random.bytes` | -- | 2026-03-30 | Open |
| 2 | Critical | 80 | No secret zeroing anywhere in codebase | mfa, api_keys, hmac | CWE-226, CWE-316 / A02:2021 | `src/mfa.zig:113`, `src/api_keys.zig:95-97,155-156`, `src/hmac.zig:42-46` | [#22](https://gitlab.com/devnw/zig/auth/-/issues/22) (confidential) | Use `std.crypto.secureZero` on all secret buffers before free/scope-exit | -- | 2026-03-30 | Open |
| 3 | High | 70 | `validateKey` returns raw pointer that outlives mutex lock | api_keys | CWE-416, CWE-362 / A04:2021 | `src/api_keys.zig:137-163` | [#29](https://gitlab.com/devnw/zig/auth/-/issues/29) (confidential) | Return owned copy or locked reference | -- | 2026-04-22 | Open |
| 4 | High | 70 | `listUserKeys` returns copies with borrowed slice pointers | api_keys | CWE-416, CWE-825 / A04:2021 | `src/api_keys.zig:205-218` | [#34](https://gitlab.com/devnw/zig/auth/-/issues/34) (confidential) | Deep-clone `name` and `scopes` slices | -- | 2026-04-22 | Open |
| 5 | High | 60 | TOTP code comparison not constant-time | mfa | CWE-208 / A02:2021 | `src/mfa.zig:213` | [#25](https://gitlab.com/devnw/zig/auth/-/issues/25) (confidential) | Use `std.crypto.timing_safe.eql` on code bytes | -- | 2026-04-22 | Open |
| 6 | Medium | 48 | `@panic` on >128 properties (DoS) | hmac | CWE-400, CWE-248 / A04:2021 | `src/hmac.zig:66` | [#38](https://gitlab.com/devnw/zig/auth/-/issues/38) | Return error or heap-allocate | -- | 2026-06-21 | Open |
| 7 | Medium | 48 | `validateKey` does not verify prefix matches config | api_keys | CWE-287 / A07:2021 | `src/api_keys.zig:137-138` | [#39](https://gitlab.com/devnw/zig/auth/-/issues/39) | Compare `parsed.prefix` to `self.config.key_prefix` | -- | 2026-06-21 | Open |
| 8 | Medium | 48 | API key secret hashed with plain SHA-256, no KDF | api_keys | CWE-916 / A02:2021 | `src/api_keys.zig:101,156` | [#40](https://gitlab.com/devnw/zig/auth/-/issues/40) | Use HMAC-SHA256 with server pepper or proper KDF | -- | 2026-06-21 | Open |
| 9 | Medium | 36 | Silent error swallowing in `cleanupExpired` | api_keys | CWE-390 / A04:2021 | `src/api_keys.zig:234` | [#41](https://gitlab.com/devnw/zig/auth/-/issues/41) | Return error or pre-allocate removal list | -- | 2026-06-21 | Open |
| 10 | Medium | 48 | Integer truncation panic on large key/value lengths | hmac | CWE-190 / A04:2021 | `src/hmac.zig:95,99` | [#42](https://gitlab.com/devnw/zig/auth/-/issues/42) | Validate lengths before `@intCast`, return error | -- | 2026-06-21 | Open |
| 11 | Low | 36 | No TOTP replay protection | mfa | CWE-294 / A07:2021 | `src/mfa.zig:201-216` | [#43](https://gitlab.com/devnw/zig/auth/-/issues/43) | Track last-used time step, reject reuse | -- | 2026-09-19 | Open |
| 12 | Low | 24 | `base32Encode` trailing garbage for non-mod-5 input | mfa | CWE-131 / A02:2021 | `src/mfa.zig:44-67` | [#44](https://gitlab.com/devnw/zig/auth/-/issues/44) | Truncate output or apply RFC 4648 padding | -- | 2026-09-19 | Open |
| 13 | Low | 24 | Custom HMAC-SHA1 implementation | mfa | CWE-327 / A02:2021 | `src/mfa.zig:146-175` | [#45](https://gitlab.com/devnw/zig/auth/-/issues/45) | Replace with `std.crypto.auth.hmac.sha1.HmacSha1` | -- | 2026-09-19 | Open |

## Findings by Area

### Authentication (MFA / TOTP)

| ID | Severity | Finding | CWE |
|----|----------|---------|-----|
| SEC-001 | Critical | Deterministic TOTP secret -- no server secret in derivation | CWE-330, CWE-321 |
| SEC-003 | High | Non-constant-time TOTP code comparison | CWE-208 |
| SEC-011 | Low | No replay protection for TOTP codes | CWE-294 |
| SEC-012 | Low | Base32 encoding trailing garbage for non-mod-5 input | CWE-131 |
| SEC-013 | Low | Custom HMAC-SHA1 instead of stdlib | CWE-327 |

### Authentication (API Keys)

| ID | Severity | Finding | CWE |
|----|----------|---------|-----|
| SEC-004 | High | `validateKey` dangling pointer after mutex release | CWE-416, CWE-362 |
| SEC-005 | High | `listUserKeys` shallow copies with borrowed slices | CWE-416, CWE-825 |
| SEC-007 | Medium | Key prefix not validated against config | CWE-287 |
| SEC-008 | Medium | SHA-256 without KDF for secret hashing | CWE-916 |
| SEC-009 | Medium | Silent error swallowing in expired key cleanup | CWE-390 |

### Cryptographic Primitives (HMAC)

| ID | Severity | Finding | CWE |
|----|----------|---------|-----|
| SEC-006 | Medium | `@panic` on >128 properties (DoS) | CWE-400, CWE-248 |
| SEC-010 | Medium | Integer truncation panic on large key/value | CWE-190 |

### Memory Safety (Cross-Cutting)

| ID | Severity | Finding | CWE |
|----|----------|---------|-----|
| SEC-002 | Critical | No secret zeroing in any module | CWE-226, CWE-316 |
| SEC-004 | High | Use-after-free: pointer outlives mutex | CWE-416 |
| SEC-005 | High | Use-after-free: borrowed slice pointers | CWE-416, CWE-825 |

## Remediation Roadmap

### Quick Wins (< 1 day each)

| ID | Task | Effort |
|----|------|--------|
| SEC-002 | Add `std.crypto.secureZero` / `@memset(buf, 0)` calls in defer blocks for all secret buffers | 2-4 hours |
| SEC-003 | Replace `==` with `std.crypto.timing_safe.eql` on TOTP code bytes | 30 minutes |
| SEC-007 | Add `std.mem.eql(u8, parsed.prefix, self.config.key_prefix)` check in `validateKey` | 30 minutes |
| SEC-009 | Change `catch continue` to `catch return error.OutOfMemory` or pre-allocate | 1 hour |
| SEC-013 | Replace custom `hmacSha1` with `std.crypto.auth.hmac.sha1.HmacSha1` | 1 hour |

### Medium Effort (1-5 days)

| ID | Task | Effort |
|----|------|--------|
| SEC-004 | Redesign `validateKey` to return an owned `ValidatedKey` struct (copy relevant fields) | 1-2 days |
| SEC-005 | Implement deep-clone in `listUserKeys` with a `dupeApiKey` helper | 1 day |
| SEC-006 | Replace `@panic` with error return or heap-allocated fallback for >128 properties | 1 day |
| SEC-010 | Add length validation before `@intCast` in `feedKv`, propagate error | 1 day |
| SEC-012 | Fix base32 encoding to produce correct-length output for any input size | 1 day |

### Strategic (> 5 days)

| ID | Task | Effort |
|----|------|--------|
| SEC-001 | Redesign TOTP enrollment to use cryptographically random per-user secrets; remove deterministic derivation; update all callers and tests | 3-5 days |
| SEC-008 | Replace SHA-256 with HMAC-SHA256 + server pepper or proper KDF; design migration path for stored hashes | 2-3 days |
| SEC-011 | Design and implement TOTP replay protection interface (last-used-step tracking) | 2-3 days |

## Immediate Actions Required

The following findings require immediate attention (within 7 days):

1. **SEC-001** -- The deterministic TOTP secret derivation is the highest-risk finding. Until fixed, any attacker who knows the salt value (hardcoded default: `"auth-mfa-salt-v1"`) can compute TOTP codes for any user. **Action**: Do not deploy MFA functionality until `enroll()` generates cryptographically random secrets.

2. **SEC-002** -- Secret zeroing is a defense-in-depth measure. While it requires a secondary memory disclosure vector, the fix is straightforward and should be applied immediately. **Action**: Add `secureZero` calls in the next commit.

## Scoring Methodology

Risk scores use the formula: `Impact(1-5) x Likelihood(1-5) x 4`, producing a 0-100 scale.

| Scale | 1 | 2 | 3 | 4 | 5 |
|-------|---|---|---|---|---|
| Impact | Hardening | Info leak | Data tampering | PII/credential leak | RCE / priv-esc |
| Likelihood | Theoretical | Rare conditions | Requires auth | Remote, constrained | Pre-auth, trivial |

All findings are tagged `confidence::confirmed` -- verified via direct source code review with exact file and line references.
