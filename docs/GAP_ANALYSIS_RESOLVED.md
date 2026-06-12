# Gap Analysis -- Resolved

Items moved here once resolved or confirmed as Won't Do.

Last updated: 2026-06-12 (post-remediation, round 1)

## Resolved -- Round 1 remediation (2026-06-12)

All issues closed on GitLab with per-issue evidence comments.

| Gap-ID | Issue | Resolution evidence (commit) |
|---|---|---|
| GAP-0002 | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) | 9ba0c79 -- working example wired into `zig build example` |
| GAP-0006 | [#55](https://gitlab.com/devnw/zig/auth/-/issues/55) | 65fe8a1 -- all 7 RFC 4648 base32 vectors + round-trip |
| GAP-0007 | [#56](https://gitlab.com/devnw/zig/auth/-/issues/56) | 3dc669e -- fail-closed `io.randomSecure` for all credential RNG |
| GAP-0008 | [#57](https://gitlab.com/devnw/zig/auth/-/issues/57) | 24d1150 + aeab6c6 + 2d0b429 -- 160-bit recovery codes, single-use constant-time `verifyScratchCode`, zeroization |
| GAP-0009 | [#58](https://gitlab.com/devnw/zig/auth/-/issues/58) | 0b45ee4 -- test-count/version claims reconciled |
| GAP-0010 | [#59](https://gitlab.com/devnw/zig/auth/-/issues/59) | e71c66d -- observability test aligned; inertness documented |
| GAP-0011 | [#60](https://gitlab.com/devnw/zig/auth/-/issues/60) | 0b45ee4 -- version single-sourced + sync hook |
| GAP-0012 | [#61](https://gitlab.com/devnw/zig/auth/-/issues/61) | 0b45ee4 -- dead README link fixed |
| GAP-0013 | [#62](https://gitlab.com/devnw/zig/auth/-/issues/62) | 0b45ee4 -- `minimum_zig_version` bumped to true 0.16.0 floor |
| GAP-0014 | [#63](https://gitlab.com/devnw/zig/auth/-/issues/63) | 0b45ee4 -- CHANGELOG backfilled 0.1.1-0.1.5 |
| GAP-0015 | [#40](https://gitlab.com/devnw/zig/auth/-/issues/40) | 5a36ff0 -- optional server-side pepper for API-key hashing |
| GAP-0016 | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) | 5988a6f -- deterministic TOTP derivation gated to test builds |
| GAP-0017 | [#43](https://gitlab.com/devnw/zig/auth/-/issues/43) | 5b36715 -- `verifyCodeStep`/`verifyCodeOnce` replay protection |
| GAP-0018 | [#64](https://gitlab.com/devnw/zig/auth/-/issues/64) | Investigation: fragment-pinned otel URL verified correct and deterministic; upstream `.version`-lag issue filed ([otel#169](https://gitlab.com/devnw/zig/otel/-/issues/169)) |
| GAP-0019 | [#65](https://gitlab.com/devnw/zig/auth/-/issues/65) | 5a36ff0 -- `validateKey` returns owned copies (no UAF) |
| GAP-0021 | [#44](https://gitlab.com/devnw/zig/auth/-/issues/44) | 65fe8a1 -- RFC 4648 base32 padding symmetry, no trailing garbage |
| GAP-0022 | [#67](https://gitlab.com/devnw/zig/auth/-/issues/67) | 5a36ff0 -- `listUserKeys` errdefer on append-OOM path |
| GAP-0023 | [#68](https://gitlab.com/devnw/zig/auth/-/issues/68) | 5a36ff0 -- `createKey` lock hoisted to map mutation only |
| GAP-0024 | [#69](https://gitlab.com/devnw/zig/auth/-/issues/69) | 5a36ff0 -- single `now()` read under lock |
| GAP-0025 | [#70](https://gitlab.com/devnw/zig/auth/-/issues/70) | Partial-close: CI Zig cache + BFS deque (74232f4), stack-buffer base32 decode (4a33957), max_keys + tombstone reclamation (5a36ff0/bb3ab93); remainder Accepted with rationale (see GAP_ANALYSIS.md) |
| GAP-0026 | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) | 0b45ee4 -- CODEOWNERS placeholder replaced |
| GAP-0027 | [#71](https://gitlab.com/devnw/zig/auth/-/issues/71) | 5b67caf -- MD040 language hints on all fences |
| GAP-0028 | [#72](https://gitlab.com/devnw/zig/auth/-/issues/72) | 5b67caf -- `.cz.yaml` pretty-format + ruff format |
| GAP-0029 | [#73](https://gitlab.com/devnw/zig/auth/-/issues/73) | 5b67caf -- doc comments; `validateKey` decomposed (5a36ff0) |
| GAP-0030 | [#74](https://gitlab.com/devnw/zig/auth/-/issues/74) | 9023a54 -- `MfaConfig.validate` rejects `digits=0` bypass |
| GAP-0031 | [#75](https://gitlab.com/devnw/zig/auth/-/issues/75) | 9023a54 -- `MfaConfig.validate` rejects lockout/div-by-zero/overflow configs |
| GAP-0032 | [#76](https://gitlab.com/devnw/zig/auth/-/issues/76) | 5a36ff0 -- collision-safe insert, no clobber/leak |
| GAP-0033 | [#77](https://gitlab.com/devnw/zig/auth/-/issues/77) | 19f4a95 -- total (key,value) sort order, deterministic HMAC |
| GAP-0034 | [#78](https://gitlab.com/devnw/zig/auth/-/issues/78) | 5a36ff0 -- `key_prefix` separator rejection enforced |
| GAP-0036 | [#80](https://gitlab.com/devnw/zig/auth/-/issues/80) | 5d6c97a + 9cf314a -- unconditional assertions + adversarial integration tests |
| GAP-0037 | [#81](https://gitlab.com/devnw/zig/auth/-/issues/81) | 634d36c -- explicit error sets on all public fallible fns |
| GAP-0038 | [#82](https://gitlab.com/devnw/zig/auth/-/issues/82) | 3df58e5 -- allocator-pairing contract documented in docs/USAGE.md |
| GAP-0039 | [#83](https://gitlab.com/devnw/zig/auth/-/issues/83) | 5a36ff0 -- io helper accessors |
| GAP-0040 | [#84](https://gitlab.com/devnw/zig/auth/-/issues/84) | 5a36ff0 -- threading/ownership contract documented (incl. Io.Mutex futex verification) |
| GAP-0041 | [#85](https://gitlab.com/devnw/zig/auth/-/issues/85) | 5a36ff0 -- comptime-guarded subject-id bufPrints |
| GAP-0043 | [#87](https://gitlab.com/devnw/zig/auth/-/issues/87) | 9023a54 -- modulus hoisted out of window loop |
| GAP-0044 | [#88](https://gitlab.com/devnw/zig/auth/-/issues/88) | 9023a54 -- comptime assert `HmacSha1.mac_length == 20` |
| GAP-0045 | [#89](https://gitlab.com/devnw/zig/auth/-/issues/89) | 3d0e632 -- Makefile aligned with CI (check, fuzz, release matrix, fmt examples/) |
| QGA-007 | [#35](https://gitlab.com/devnw/zig/auth/-/issues/35) | 74232f4 -- CI caches Zig toolchain across jobs |
| QGA-008 | [#36](https://gitlab.com/devnw/zig/auth/-/issues/36) | 74232f4 -- CI caching eliminates per-job setup cost |
| AUTH-DOC-001 | [#12](https://gitlab.com/devnw/zig/auth/-/issues/12) | 3df58e5 -- token-format configuration documented in docs/USAGE.md |
| AUTH-DOC-002 | [#13](https://gitlab.com/devnw/zig/auth/-/issues/13) | 3df58e5 -- HMAC-chain usage documented in docs/USAGE.md |
| AUTH-DOC-003 | [#14](https://gitlab.com/devnw/zig/auth/-/issues/14) | 3df58e5 -- MFA configuration knobs documented in docs/USAGE.md |

## Resolved

### GAP-0001: README Quick Start showed non-existent auth.init API [RESOLVED]

- **Issue:** [#16](https://gitlab.com/devnw/zig/auth/-/issues/16) (closed); duplicate [#17](https://gitlab.com/devnw/zig/auth/-/issues/17) (closed)
- **Category:** Docs
- **Resolution:** README Quick Start rewritten to use the real public API surface; no `auth.init` symbol exists anywhere in the library.
- **Evidence:**
  - `README.md:44-58` -- now shows `auth.hmac.deriveHmacKey`, `auth.api_keys.ApiKeyManager.init`/`createKey`, and `auth.mfa.enroll`
  - No `init` export in `src/` (api_keys.zig, hmac.zig, mfa.zig, root.zig)
- **Resolved date:** 2026-06-12

### GAP-0003: docs/README.md linked to nonexistent files [RESOLVED]

- **Issue:** None (doc-only finding)
- **Category:** Docs
- **Resolution:** The dead Table-of-Contents links in `docs/README.md` were removed/repointed to existing documentation; no broken links remain in the docs index.
- **Evidence:**
  - `docs/README.md` -- Table of Contents no longer references the missing `getting-started.md`, `api-reference.md`, `examples.md`, `architecture.md`, `faq.md`
- **Resolved date:** 2026-06-12
- **Note:** A residual broken link from the top-level `README.md` to `otel/docs/integration/RECIPE.md` is tracked separately as GAP-0012 ([#61](https://gitlab.com/devnw/zig/auth/-/issues/61)).

### GAP-0004: GAP_ANALYSIS.md test count was stale [RESOLVED]

- **Issue:** None (doc-only finding)
- **Category:** Docs
- **Resolution:** Test counts in the gap analysis were reconciled with the actual `zig build test` output at the time of the fix.
- **Evidence:**
  - Corrected counts in `GAP_ANALYSIS.md` matched the test run
- **Resolved date:** 2026-06-12
- **Note:** A fresh, broader stale-claims finding (README claims 59 tests/v0.1.0; actual 64 pass + 2 skip) is tracked separately as GAP-0009 ([#58](https://gitlab.com/devnw/zig/auth/-/issues/58)).

### GAP-0005: revokeUserKeys, listUserKeys, cleanupExpired lacked dedicated tests [RESOLVED]

- **Issue:** [#18](https://gitlab.com/devnw/zig/auth/-/issues/18) (closed)
- **Category:** Test
- **Resolution:** Six dedicated lifecycle tests added covering revocation, listing, and expiration cleanup, all under the leak-detecting allocator.
- **Evidence:**
  - `src/api_keys.zig:651-751` -- six dedicated tests (e.g. `"revokeUserKeys revokes all keys for a user"` at `:651`)
  - All run under `std.testing.allocator`
- **Resolved date:** 2026-06-12

### GAP: API-key format is Geode-branded [RESOLVED]

- **Issue:** [#4](https://gitlab.com/devnw/zig/auth/-/issues/4) (AUTH-REQ-004), [#1](https://gitlab.com/devnw/zig/auth/-/issues/1) (AUTH-REQ-001)
- **Category:** Feature
- **Resolution:** `api_keys.Config.key_prefix` defaults to `"ak1"`; caller can pass any string. No Geode-branded `gk1` prefix remains.
- **Evidence:**
  - `src/api_keys.zig` -- `Config.key_prefix` field with default `"ak1"`
  - Unit tests in `src/api_keys.zig` including `"custom prefix"` test
  - `zig build test` -- 0 failures, 0 leaks
- **Resolved date:** 2026-03-23

### GAP: Memory leak in API-key formatting flow [RESOLVED]

- **Issue:** [#6](https://gitlab.com/devnw/zig/auth/-/issues/6) (AUTH-PKG-001)
- **Category:** Bug
- **Resolution:** Moved `formatApiKey` call before `keys.put`; extracted `dupeScopes` helper with proper partial-failure errdefer.
- **Evidence:**
  - `src/api_keys.zig` -- `formatApiKey` runs before `keys.put`; `dupeScopes` has errdefer for partial allocations
  - API-key tests pass under `std.testing.allocator` (leak-detecting)
  - `zig test src/api_keys.zig` -- 0 leaks
- **Resolved date:** 2026-03-23

### GAP: MFA logic tied to Geode feature flags and naming [RESOLVED]

- **Issue:** [#5](https://gitlab.com/devnw/zig/auth/-/issues/5) (AUTH-REQ-005), [#3](https://gitlab.com/devnw/zig/auth/-/issues/3) (AUTH-REQ-003)
- **Category:** Feature
- **Resolution:** Removed `feature_flags` import; removed all `globallyEnabled()` checks; `MfaConfig.salt` replaces hardcoded `"GEODE_MFA_SALT_V1"`.
- **Evidence:**
  - `src/mfa.zig` -- no `feature_flags` import; `MfaConfig.salt` is caller-provided
  - Unit tests in `src/mfa.zig` + MFA integration tests
  - `zig build test && zig build test-integration` -- 0 failures
- **Resolved date:** 2026-03-23

## Won't Do

### GAP-0042: ApiKey two ?i64 fields cost ~16B padding per key [WON'T DO]

- **Issue:** [#86](https://gitlab.com/devnw/zig/auth/-/issues/86) (closed 2026-06-12)
- **Category:** Perf
- **Reason:** Optionals are the clearer API; the ~16B/key padding saving is
  unproven without a bench harness ([#11](https://gitlab.com/devnw/zig/auth/-/issues/11)).
  Reopen if profiling ever shows scan-bound behavior on the key map.

### Recovery-code single-use test (`tests/test_recovery_codes.zig:7`)

- **Issue:** [#10](https://gitlab.com/devnw/zig/auth/-/issues/10) (AUTH-TEST-003, partial)
- **Category:** Test
- **Reason:** Test depends on Geode `AuthContext` user store, `createUser`, `enableMFAForUser`, `addRecoveryCodes`, and `authenticateWithMFA` with recovery-code parameter. Recovery-code consumption is product-level logic (user store + state mutation), not a reusable auth primitive.
- **Note:** A library-level recovery/scratch-code verify API (with adequate entropy) is tracked forward as GAP-0008 ([#57](https://gitlab.com/devnw/zig/auth/-/issues/57)).
