# Gap Analysis -- Resolved

Items moved here once resolved or confirmed as Won't Do.

Last updated: 2026-06-12

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

### Recovery-code single-use test (`tests/test_recovery_codes.zig:7`)

- **Issue:** [#10](https://gitlab.com/devnw/zig/auth/-/issues/10) (AUTH-TEST-003, partial)
- **Category:** Test
- **Reason:** Test depends on Geode `AuthContext` user store, `createUser`, `enableMFAForUser`, `addRecoveryCodes`, and `authenticateWithMFA` with recovery-code parameter. Recovery-code consumption is product-level logic (user store + state mutation), not a reusable auth primitive.
- **Note:** A library-level recovery/scratch-code verify API (with adequate entropy) is tracked forward as GAP-0008 ([#57](https://gitlab.com/devnw/zig/auth/-/issues/57)).
