# Quality Gap Analysis

Last updated: 2026-03-23

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 3 |
| Medium   | 5 |
| Low      | 6 |
| **Total** | **14** |

### Top 5 Risks

1. **TOTP secret derived deterministically from public inputs** (QGA-002, PriorityScore 80) -- Anyone knowing a username and the default salt can reconstruct the TOTP secret, defeating MFA entirely.
2. **README Quick Start references non-existent API** (QGA-001, PriorityScore 80) -- Every new user gets a compile error on first use.
3. **listUserKeys returns dangling pointers after mutation** (QGA-003, PriorityScore 64) -- Use-after-free in normal usage patterns.
4. **computeRecordHmac panics on >128 properties** (QGA-006, PriorityScore 48) -- Library aborts the process instead of returning an error.
5. **CODEOWNERS placeholder blocks review routing** (QGA-004, PriorityScore 48) -- Merge request approvals are not routed to anyone.

---

## Stack-Ranked Findings

| Rank | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Fix Summary | Owner | Effort | Status |
|------|----------|---------------|----------|---------|-----------|----------|-------|-------------|-------|--------|--------|
| 1 | High | 80 | security | TOTP secret deterministically derived from username + public salt | `src/mfa.zig` | `mfa.zig:102-108`, `mfa.zig:15-18` | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) | Use `crypto.random.bytes()` for default enrollment; gate deterministic mode behind explicit opt-in | TBD | M | Triage |
| 2 | High | 80 | docs | README Quick Start shows non-existent `auth.init()` API | `README.md` | `README.md:46-50` vs `src/root.zig:14-29` | [#17](https://gitlab.com/devnw/zig/auth/-/issues/17) | Replace Quick Start with actual API usage from `root.zig` | TBD | S | Triage |
| 3 | High | 64 | api-contract | `listUserKeys` returns shallow copies with borrowed `name`/`scopes` pointers | `src/api_keys.zig` | `api_keys.zig:215` (shallow copy of struct with slice fields) | [#26](https://gitlab.com/devnw/zig/auth/-/issues/26) | Deep-copy `name` and `scopes` via `allocator.dupe()` / `dupeScopes()` | TBD | S | Triage |
| 4 | Medium | 48 | api-contract | `computeRecordHmac` panics on >128 properties instead of returning error | `src/hmac.zig` | `hmac.zig:66` (`@panic`) | [#32](https://gitlab.com/devnw/zig/auth/-/issues/32) | Return `error.TooManyProperties` or heap-allocate for overflow | TBD | S | Triage |
| 5 | Medium | 48 | cleanup | CODEOWNERS has placeholder `@your-username` | `CODEOWNERS` | `CODEOWNERS:3` | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) | Replace with actual maintainer usernames/groups | TBD | S | Triage |
| 6 | Medium | 36 | docs | `examples/basic.zig` is non-functional template placeholder | `examples/basic.zig` | `examples/basic.zig:11-24` (commented-out, references non-existent API) | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) | Rewrite with real API calls for hmac, api_keys, mfa | TBD | S | Triage |
| 7 | Medium | 40 | ci-cd | CI downloads Zig from scratch in every job, no caching | `.gitlab-ci.yml` | `.gitlab-ci.yml:34-39` (repeated in 5 jobs) | [#35](https://gitlab.com/devnw/zig/auth/-/issues/35) | Add CI cache keyed on `ZIG_VERSION` or use pre-built Docker image | TBD | S | Triage |
| 8 | Medium | 40 | ci-cd | Build artifact (`zig-out/`) not reused by test jobs | `.gitlab-ci.yml` | `.gitlab-ci.yml:49-64` (`needs: [build]` but rebuilds from scratch) | [#36](https://gitlab.com/devnw/zig/auth/-/issues/36) | Cache `.zig-cache/` or remove misleading artifact | TBD | S | Triage |
| 9 | Low | 20 | security | Default HKDF salts hardcoded in source | `src/hmac.zig`, `src/mfa.zig` | `hmac.zig:33-35` (`"auth-hmac-v1"`), `mfa.zig:18` (`"auth-mfa-salt-v1"`) | -- | Document that defaults are for development only; require callers to supply production salts | TBD | S | Backlog |
| 10 | Low | 24 | maintainability | Hand-rolled HMAC-SHA1 instead of using stdlib | `src/mfa.zig` | `mfa.zig:146-175` (manual ipad/opad implementation) | -- | Replace with `std.crypto.auth.hmac.sha2.HmacSha256` or evaluate if Zig stdlib has HMAC-SHA1 | TBD | S | Backlog |
| 11 | Low | 16 | perf | Repeated HKDF extract in scratch code generation loop | `src/mfa.zig` | `mfa.zig:130-131` (`HkdfSha256.extract()` called per iteration) | -- | Hoist `prk` extraction outside the `while` loop | TBD | S | Backlog |
| 12 | Low | 24 | maintainability | `cleanupExpired` silently swallows OOM via `catch continue` | `src/api_keys.zig` | `api_keys.zig:234` | -- | Return an error or use a pre-allocated buffer | TBD | S | Backlog |
| 13 | Low | 8 | docs | `docs/REQUIREMENTS.md` references old Geode file paths | `docs/REQUIREMENTS.md` | `REQUIREMENTS.md:9-13` (e.g., `src/security/api_keys.zig` instead of `src/api_keys.zig`) | -- | Update paths to match current repo layout | TBD | S | Backlog |
| 14 | Low | 8 | ci-cd | CI `ZIG_VERSION` 0.15.1 vs local 0.15.2 mismatch | `.gitlab-ci.yml` | `.gitlab-ci.yml:23` (`ZIG_VERSION: "0.15.1"`) | -- | Align CI version with local development version | TBD | S | Backlog |

---

## Findings by Category

### Security (1 finding)

| ID | Severity | Finding | Issue |
|----|----------|---------|-------|
| QGA-002 | High | TOTP secret deterministically derived from username + public salt | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) |

**Note:** QGA-009 (hardcoded HKDF salts) is related but lower severity since the salts are configurable defaults, not secrets.

### API Contract (2 findings)

| ID | Severity | Finding | Issue |
|----|----------|---------|-------|
| QGA-003 | High | `listUserKeys` returns borrowed pointers | [#26](https://gitlab.com/devnw/zig/auth/-/issues/26) |
| QGA-006 | Medium | `computeRecordHmac` panics on >128 properties | [#32](https://gitlab.com/devnw/zig/auth/-/issues/32) |

### Documentation (3 findings)

| ID | Severity | Finding | Issue |
|----|----------|---------|-------|
| QGA-001 | High | README Quick Start shows non-existent API | [#17](https://gitlab.com/devnw/zig/auth/-/issues/17) |
| QGA-005 | Medium | `examples/basic.zig` is non-functional template | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) |
| QGA-013 | Low | `REQUIREMENTS.md` references old file paths | -- |

### CI/CD (3 findings)

| ID | Severity | Finding | Issue |
|----|----------|---------|-------|
| QGA-007 | Medium | CI downloads Zig from scratch every job | [#35](https://gitlab.com/devnw/zig/auth/-/issues/35) |
| QGA-008 | Medium | Build artifact not reused by test jobs | [#36](https://gitlab.com/devnw/zig/auth/-/issues/36) |
| QGA-014 | Low | CI ZIG_VERSION mismatch with local | -- |

### Maintainability (2 findings)

| ID | Severity | Finding | Issue |
|----|----------|---------|-------|
| QGA-010 | Low | Hand-rolled HMAC-SHA1 instead of stdlib | -- |
| QGA-012 | Low | `cleanupExpired` silently swallows OOM | -- |

### Performance (1 finding)

| ID | Severity | Finding | Issue |
|----|----------|---------|-------|
| QGA-011 | Low | Repeated HKDF extract in scratch code loop | -- |

### Cleanup (1 finding)

| ID | Severity | Finding | Issue |
|----|----------|---------|-------|
| QGA-004 | Medium | CODEOWNERS placeholder `@your-username` | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) |

---

## Roadmap

### Quick Wins (< 1 day)

| ID | Finding | Effort | Issue |
|----|---------|--------|-------|
| QGA-001 | Fix README Quick Start | S | [#17](https://gitlab.com/devnw/zig/auth/-/issues/17) |
| QGA-003 | Deep-copy slices in `listUserKeys` | S | [#26](https://gitlab.com/devnw/zig/auth/-/issues/26) |
| QGA-004 | Update CODEOWNERS | S | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) |
| QGA-005 | Rewrite `examples/basic.zig` | S | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) |
| QGA-006 | Return error instead of panic in `computeRecordHmac` | S | [#32](https://gitlab.com/devnw/zig/auth/-/issues/32) |
| QGA-011 | Hoist HKDF extract out of scratch code loop | S | -- |
| QGA-013 | Update REQUIREMENTS.md file paths | S | -- |
| QGA-014 | Align CI ZIG_VERSION | S | -- |

### Medium (1-5 days)

| ID | Finding | Effort | Issue |
|----|---------|--------|-------|
| QGA-002 | Redesign TOTP secret generation with random entropy | M | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) |
| QGA-007 | Add CI caching for Zig toolchain | S-M | [#35](https://gitlab.com/devnw/zig/auth/-/issues/35) |
| QGA-008 | Fix CI artifact/cache strategy | S-M | [#36](https://gitlab.com/devnw/zig/auth/-/issues/36) |
| QGA-010 | Replace hand-rolled HMAC-SHA1 with stdlib | S-M | -- |
| QGA-012 | Handle OOM in `cleanupExpired` | S | -- |

### Strategic (> 5 days)

| ID | Finding | Effort | Issue |
|----|---------|--------|-------|
| QGA-009 | Design salt/secret management strategy across all modules | M-L | -- |

---

## Scoring Methodology

**PriorityScore** = Impact (1-5) x Likelihood (1-5) x 4

| Scale | Impact | Likelihood |
|-------|--------|------------|
| 5 | Outages / major perf cost / security bypass | Ubiquitous / touched often |
| 4 | Frequent bugs / major dev drag | Often encountered |
| 3 | Moderate impact | Sometimes encountered |
| 2 | Minor impact | Rare |
| 1 | Polish | Edge-case |

**Confidence tags:**
- `confirmed` -- Verified via direct code inspection (all findings in this analysis)
- `suspected` -- Plausible but unverified (none in this analysis)

---

## Issue Cross-Reference

| QGA ID | GitLab Issue | Title |
|--------|-------------|-------|
| QGA-001 | [#17](https://gitlab.com/devnw/zig/auth/-/issues/17) | README Quick Start shows non-existent API |
| QGA-002 | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) | TOTP secret deterministically derived from username + public salt |
| QGA-003 | [#26](https://gitlab.com/devnw/zig/auth/-/issues/26) | listUserKeys returns shallow copies with borrowed pointers |
| QGA-004 | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) | CODEOWNERS has placeholder @your-username |
| QGA-005 | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) | examples/basic.zig is non-functional template placeholder |
| QGA-006 | [#32](https://gitlab.com/devnw/zig/auth/-/issues/32) | computeRecordHmac panics on >128 properties |
| QGA-007 | [#35](https://gitlab.com/devnw/zig/auth/-/issues/35) | CI downloads Zig from scratch every job |
| QGA-008 | [#36](https://gitlab.com/devnw/zig/auth/-/issues/36) | CI build artifact not reused by test jobs |
| QGA-009 | -- | Default HKDF salts hardcoded in source |
| QGA-010 | -- | Hand-rolled HMAC-SHA1 instead of stdlib |
| QGA-011 | -- | Repeated HKDF extract in scratch code loop |
| QGA-012 | -- | cleanupExpired silently swallows OOM |
| QGA-013 | -- | REQUIREMENTS.md references old file paths |
| QGA-014 | -- | CI ZIG_VERSION mismatch |

---

## Related Existing Issues

The following pre-existing issues in the repository overlap with or are related to quality findings:

| Existing Issue | Related QGA | Relationship |
|---------------|-------------|--------------|
| [#5](https://gitlab.com/devnw/zig/auth/-/issues/5) AUTH-REQ-005: No dependency on product salts | QGA-002 | QGA-002 is the specific technical manifestation of this requirement gap |
| [#3](https://gitlab.com/devnw/zig/auth/-/issues/3) AUTH-REQ-003: MFA must be explicitly configured | QGA-002 | Fixing QGA-002 partially addresses this requirement |
| [#14](https://gitlab.com/devnw/zig/auth/-/issues/14) AUTH-DOC-003: Document MFA config knobs | QGA-002, QGA-009 | Documentation of the salt/secret design depends on QGA-002 resolution |
