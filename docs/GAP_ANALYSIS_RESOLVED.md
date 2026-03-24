# Gap Analysis -- Resolved

Items moved here once resolved or confirmed as Won't Do.

## Resolved

### GAP: API-key format is Geode-branded [RESOLVED]
- **Issue:** [#4](https://gitlab.com/devnw/zig/auth/-/issues/4) (AUTH-REQ-004), [#1](https://gitlab.com/devnw/zig/auth/-/issues/1) (AUTH-REQ-001)
- **Category:** Feature
- **Resolution:** `api_keys.Config.key_prefix` defaults to `"ak1"`; caller can pass any string. No Geode-branded `gk1` prefix remains.
- **Evidence:**
  - `src/api_keys.zig` -- `Config.key_prefix` field with default `"ak1"`
  - 13 unit tests in `src/api_keys.zig` including `"custom prefix"` test
  - `zig build test` -- 0 failures, 0 leaks
- **Resolved date:** 2026-03-23

### GAP: Memory leak in API-key formatting flow [RESOLVED]
- **Issue:** [#6](https://gitlab.com/devnw/zig/auth/-/issues/6) (AUTH-PKG-001)
- **Category:** Bug
- **Resolution:** Moved `formatApiKey` call before `keys.put`; extracted `dupeScopes` helper with proper partial-failure errdefer.
- **Evidence:**
  - `src/api_keys.zig` -- `formatApiKey` runs before `keys.put`; `dupeScopes` has errdefer for partial allocations
  - All 13 API-key tests pass under `std.testing.allocator` (leak-detecting)
  - `zig test src/api_keys.zig` -- 0 leaks
- **Resolved date:** 2026-03-23

### GAP: MFA logic tied to Geode feature flags and naming [RESOLVED]
- **Issue:** [#5](https://gitlab.com/devnw/zig/auth/-/issues/5) (AUTH-REQ-005), [#3](https://gitlab.com/devnw/zig/auth/-/issues/3) (AUTH-REQ-003)
- **Category:** Feature
- **Resolution:** Removed `feature_flags` import; removed all `globallyEnabled()` checks; `MfaConfig.salt` replaces hardcoded `"GEODE_MFA_SALT_V1"`.
- **Evidence:**
  - `src/mfa.zig` -- no `feature_flags` import; `MfaConfig.salt` is caller-provided
  - 12 unit tests in `src/mfa.zig` + 2 MFA integration tests
  - `zig build test && zig build test-integration` -- 0 failures
- **Resolved date:** 2026-03-23

## Won't Do

### Recovery-code single-use test (`tests/test_recovery_codes.zig:7`)
- **Issue:** [#10](https://gitlab.com/devnw/zig/auth/-/issues/10) (AUTH-TEST-003, partial)
- **Category:** Test
- **Reason:** Test depends on Geode `AuthContext` user store, `createUser`, `enableMFAForUser`, `addRecoveryCodes`, and `authenticateWithMFA` with recovery-code parameter. Recovery-code consumption is product-level logic (user store + state mutation), not a reusable auth primitive.

### MFA benchmark hooks (`build.zig:1293-1299`)
- **Issue:** [#11](https://gitlab.com/devnw/zig/auth/-/issues/11) (AUTH-TEST-004)
- **Category:** Performance
- **Reason:** Benchmarks require Geode runtime infrastructure. A standalone benchmark harness can be added to this library later if performance regression testing is needed. Issue #11 remains open as deferred/low-priority.
