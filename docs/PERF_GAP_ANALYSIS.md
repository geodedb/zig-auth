# Performance Gap Analysis

**Repository:** `devnw/zig/auth`
**Last updated:** 2026-03-23
**Methodology:** Static code analysis of `src/mfa.zig`, `src/api_keys.zig`, `src/hmac.zig`, `.gitlab-ci.yml`
**Scoring:** PerfScore = Impact(1-5) x Likelihood(1-5) x 4 (max 100)

---

## Summary

| PerfSeverity | Count | Description |
|---|---|---|
| **P0 -- Critical** | 3 | SLO breach / outage risk; requires immediate action |
| **P1 -- High** | 4 | Material user-facing impact; fix within sprint |
| **P2 -- Medium** | 4 | Moderate impact; address next quarter |
| **P3 -- Low** | 2 | Minor optimization; backlog |
| **Total** | **13** | |

### Top 5 Risks by Expected Impact

1. **PERF-P0-001** -- `verifyCode` redundant heap alloc/free: 3x unnecessary allocator pressure on every MFA verification (hot auth path).
2. **PERF-P0-003** -- SHA256 inside mutex in `validateKey`: serializes all concurrent API key validations behind crypto computation.
3. **PERF-P0-002** -- `computeRecordHmac` panics on >128 properties: process crash instead of error; denial-of-service risk.
4. **PERF-P1-001** -- Hand-rolled HMAC-SHA1: misses stdlib optimizations, increases crypto bug surface area.
5. **PERF-P1-002** -- `cleanupExpired` silent OOM: expired keys accumulate indefinitely under memory pressure.

---

## Stack-Ranked Findings

| Rank | Severity | PerfScore | Finding | Component | Evidence | Measurement | Issue | Fix Summary | Owner | SLA | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | P0 | 80 | `verifyCode` 3x redundant heap alloc/free of decoded secret per window iteration | `src/mfa.zig:201-214` | `generateCode` calls `base32Decode` (heap alloc) each iteration; secret is invariant | `confidence::confirmed` -- code inspection | [#20](https://gitlab.com/devnw/zig/auth/-/issues/20) | Hoist `base32Decode` above loop; add internal `generateCodeFromRaw` | @your-username | Immediate | Triage |
| 2 | P0 | 80 | SHA256 computed inside mutex in `validateKey` | `src/api_keys.zig:140-163` | `Sha256.hash` at line 156 runs between `mutex.lock()` and `defer mutex.unlock()` | `confidence::confirmed` -- code inspection | [#24](https://gitlab.com/devnw/zig/auth/-/issues/24) | Move `Sha256.hash` before `mutex.lock()` | @your-username | Immediate | Triage |
| 3 | P0 | 56 | `computeRecordHmac` panics on >128 properties | `src/hmac.zig:66` | `@panic(...)` in else branch when `props.len > max_stack` | `confidence::confirmed` -- code inspection | [#21](https://gitlab.com/devnw/zig/auth/-/issues/21) | Return `error.TooManyProperties` instead of `@panic` | @your-username | Immediate | Triage |
| 4 | P1 | 60 | Hand-rolled HMAC-SHA1 instead of stdlib | `src/mfa.zig:146-175` | 30-line manual ipad/opad construction duplicating `std.crypto.auth.hmac` | `confidence::confirmed` -- code inspection | [#27](https://gitlab.com/devnw/zig/auth/-/issues/27) | Replace with `std.crypto.auth.hmac.Hmac(Sha1)` | @your-username | Within sprint | Triage |
| 5 | P1 | 48 | `cleanupExpired` silently drops keys on OOM | `src/api_keys.zig:234` | `to_remove.append(...) catch continue` swallows allocation failure | `confidence::confirmed` -- code inspection | [#31](https://gitlab.com/devnw/zig/auth/-/issues/31) | Return `!usize` error union; propagate OOM | @your-username | Within sprint | Triage |
| 6 | P1 | 48 | HKDF PRK re-extracted inside scratch-code loop | `src/mfa.zig:130-131` | `HkdfSha256.extract(config.salt, raw_secret)` called per iteration; salt + ikm are invariant | `confidence::confirmed` -- code inspection | [#33](https://gitlab.com/devnw/zig/auth/-/issues/33) | Hoist `extract` above loop | @your-username | Within sprint | Triage |
| 7 | P1 | 40 | No secret zeroing before free | `src/mfa.zig:114`, `src/api_keys.zig:97` | `allocator.free(raw_secret)` without prior zeroing; stack secret not zeroed on scope exit | `confidence::confirmed` -- code inspection | [#37](https://gitlab.com/devnw/zig/auth/-/issues/37) | Use `std.crypto.utils.secureZero` before free/scope exit | @your-username | Within sprint | Triage |
| 8 | P2 | 48 | O(n) full scan for user operations | `src/api_keys.zig:189-219` | `revokeUserKeys` and `listUserKeys` iterate entire key map to filter by `user_id` | `confidence::suspected` -- needs load test to quantify | -- | Add secondary index `HashMap(u64, ArrayList(token_id))` for user-to-key lookup | @your-username | Next quarter | Backlog |
| 9 | P2 | 36 | Heap alloc for fixed-size base32 decode | `src/mfa.zig:179` | `base32Decode` heap-allocates output; TOTP secret is always 20 bytes (32 bytes base32-encoded = 20 decoded) | `confidence::confirmed` -- code inspection | -- | Add `base32DecodeBuf` variant that writes to caller-provided `[20]u8` buffer | @your-username | Next quarter | Backlog |
| 10 | P2 | 36 | Two-pass cleanup under mutex | `src/api_keys.zig:222-247` | First pass collects IDs into `to_remove` list, second pass removes them; both under lock | `confidence::suspected` -- needs profiling under load | -- | Use single-pass `swapRemove` or `removeByKey` during iteration | @your-username | Next quarter | Backlog |
| 11 | P2 | 24 | No HashMap capacity pre-allocation | `src/api_keys.zig:61` | `AutoHashMap.init(allocator)` starts with zero capacity; first inserts trigger multiple resizes | `confidence::suspected` -- needs allocation tracing | -- | Accept initial capacity hint in `ApiKeyManager.init` or `ensureTotalCapacity` on first batch insert | @your-username | Next quarter | Backlog |
| 12 | P3 | 24 | Unbounded key map growth | `src/api_keys.zig:54` | No maximum key count enforced; map grows without limit | `confidence::suspected` -- needs production sizing data | -- | Add configurable `max_keys` limit; return error when exceeded | @your-username | Backlog | Backlog |
| 13 | P3 | 12 | No CI cache for Zig toolchain | `.gitlab-ci.yml` | Zig toolchain (~100MB) downloaded fresh in every job via `curl` | `confidence::confirmed` -- CI config inspection | -- | Add `cache:` block for `zig-linux-x86_64-${ZIG_VERSION}/` directory | @your-username | Backlog | Backlog |

---

## Findings by Area

### area::app (12 findings)

All P0, P1, P2, and P3 application findings are listed in the stack-ranked table above (Ranks 1-12). Key themes:

- **MFA module (`src/mfa.zig`):** Redundant allocations in hot verify path (P0), hand-rolled crypto (P1), HKDF loop inefficiency (P1), missing secret zeroing (P1), heap alloc for fixed-size decode (P2).
- **API Keys module (`src/api_keys.zig`):** Crypto under lock (P0), silent OOM (P1), missing secret zeroing (P1), O(n) scans (P2), two-pass cleanup (P2), no pre-alloc (P2), unbounded growth (P3).
- **HMAC module (`src/hmac.zig`):** Panic instead of error on overflow (P0).

### area::ci (1 finding)

| Rank | Finding | Details |
|---|---|---|
| 13 | No CI cache for Zig toolchain | `.gitlab-ci.yml` downloads Zig on every job. Add `cache:` block. |

### area::db

No database-layer findings. This library does not include a persistence layer.

### area::infra

No infrastructure findings beyond CI (covered above).

---

## Roadmap

### Quick Wins (< 1 day)

| Rank | Finding | Effort | Impact |
|---|---|---|---|
| 1 | Hoist `base32Decode` out of `verifyCode` loop | ~1 hour | Eliminates 3x redundant alloc/free per MFA verify |
| 2 | Move SHA256 before mutex in `validateKey` | ~30 min | Reduces mutex hold time; improves concurrent throughput |
| 6 | Hoist HKDF `extract` out of scratch-code loop | ~30 min | Eliminates N redundant HMAC-SHA256 per enrollment |
| 7 | Add `secureZero` before free for secrets | ~1 hour | Security hygiene; near-zero perf cost |
| 13 | Add CI cache for Zig toolchain | ~30 min | Saves ~30-60s per CI job |

### Medium (1-5 days)

| Rank | Finding | Effort | Impact |
|---|---|---|---|
| 3 | Replace `@panic` with error return in `computeRecordHmac` | ~2 hours (includes updating all callers) | Prevents process crash; API-breaking change |
| 4 | Replace hand-rolled HMAC-SHA1 with stdlib | ~2 hours | Improved security and maintainability |
| 5 | Propagate OOM from `cleanupExpired` | ~2 hours | Prevents silent key accumulation under memory pressure |
| 9 | Add stack-buffer `base32DecodeBuf` for fixed-size decode | ~3 hours | Eliminates heap alloc for TOTP code generation |

### Strategic (> 5 days)

| Rank | Finding | Effort | Impact |
|---|---|---|---|
| 8 | Add secondary user-to-key index | ~2-3 days | O(1) user key lookup instead of O(n) full scan |
| 10 | Single-pass cleanup under mutex | ~1-2 days | Reduces lock hold time during cleanup |
| 11 | HashMap capacity pre-allocation | ~1 day | Reduces resize churn on initial load |
| 12 | Enforce maximum key count | ~1-2 days | Prevents unbounded memory growth |

---

## GitLab Issue Cross-Reference

| Finding | Issue URL |
|---|---|
| PERF-P0-001: verifyCode redundant alloc | https://gitlab.com/devnw/zig/auth/-/issues/20 |
| PERF-P0-002: computeRecordHmac panic | https://gitlab.com/devnw/zig/auth/-/issues/21 |
| PERF-P0-003: SHA256 inside mutex | https://gitlab.com/devnw/zig/auth/-/issues/24 |
| PERF-P1-001: Hand-rolled HMAC-SHA1 | https://gitlab.com/devnw/zig/auth/-/issues/27 |
| PERF-P1-002: cleanupExpired silent OOM | https://gitlab.com/devnw/zig/auth/-/issues/31 |
| PERF-P1-003: HKDF PRK in loop | https://gitlab.com/devnw/zig/auth/-/issues/33 |
| PERF-P1-004: No secret zeroing | https://gitlab.com/devnw/zig/auth/-/issues/37 |
| P2/P3 findings | Not yet tracked as issues (create when prioritized) |

---

## Unknowns and Blockers

1. **No benchmark suite exists yet.** Validation plans reference `zig build bench` which does not exist. Issue [#11](https://gitlab.com/devnw/zig/auth/-/issues/11) tracks preserving MFA benchmark references -- a benchmark harness should be created first to measure before/after for all fixes.
2. **Production workload profile unknown.** PerfScores for P2 findings (O(n) scans, HashMap sizing) are estimated. Actual impact depends on typical key counts per user and total key volume. Measurement under realistic load would confirm or adjust these scores.
3. **`std.crypto.auth.hmac.Hmac(Sha1)` availability.** Verify that the Zig 0.15.1 stdlib exposes the generic HMAC wrapper for SHA1 before implementing PERF-P1-001. If unavailable, the hand-rolled version must be retained with an audit.
4. **`secureZero` compiler guarantee.** Confirm that `std.crypto.utils.secureZero` is not optimized away in `ReleaseFast` builds on Zig 0.15.1.
