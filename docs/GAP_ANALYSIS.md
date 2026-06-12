# Gap Analysis

Last updated: 2026-06-12 (post-remediation, round 1)

> This file contains ONLY open gaps. Resolved items are in
> [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).
> Platform issues (GitLab) are the source of truth; this file is a mirror.

## Implementation Status Summary

| Metric | Count |
|---|---|
| Total tracked requirements | 15 |
| Open gaps (this file) | 3 (2 blocked, 1 deferred) |
| Open gaps by severity | Medium: 1 · Low: 2 |
| Gaps resolved in round 1 (2026-06-12) | 40 (see RESOLVED) |
| Accepted (Won't Fix) with rationale | 4 items (see below) |
| Won't Do | 1 (GAP-0042) |

## Severity / Issue Index

| Gap-ID | Title | Severity | Category | Issue | Status |
|---|---|---|---|---|---|
| GAP-0020 | observability seam permanently disabled; enabled path untested | Low | Observability | [#66](https://gitlab.com/devnw/zig/auth/-/issues/66) | Blocked (upstream) |
| GAP-0035 | installGlobals publishes unsynchronized global pointers | Medium | Security | [#79](https://gitlab.com/devnw/zig/auth/-/issues/79) | Blocked (on GAP-0020) |
| AUTH-TEST-004 | Preserve MFA benchmark references | Low | Test | [#11](https://gitlab.com/devnw/zig/auth/-/issues/11) | Deferred |

## Open Gaps

### GAP-0020: observability seam permanently disabled; enabled path untested

- **Issue:** [#66](https://gitlab.com/devnw/zig/auth/-/issues/66)
- **Category:** Observability
- **Severity:** Low
- **Status:** BLOCKED on an upstream Zig module-dedup issue
- **Requirement source:** Observability contract
- **Current state (evidence):** `src/observability.zig` -- `enabled` hardcoded
  false; telemetry calls no-op; enabled path uncovered. The inertness is now
  explicitly documented in code (e71c66d) and README, so it is no longer a
  silent surprise.
- **Why this is a gap:** Telemetry cannot be turned on; enabled path is latent.
- **Recommended fix:** Re-enable the seam once the upstream Zig module-dedup
  issue is resolved, wire `enabled` to `-Dwith_otel`, and cover the enabled
  path.
- **Acceptance criteria:** Enabled path reachable and tested.

### GAP-0035: installGlobals publishes unsynchronized global pointers

- **Issue:** [#79](https://gitlab.com/devnw/zig/auth/-/issues/79)
- **Category:** Security
- **Severity:** Medium
- **Status:** BLOCKED on GAP-0020 ([#66](https://gitlab.com/devnw/zig/auth/-/issues/66))
- **Requirement source:** Concurrency safety
- **Current state (evidence):** `src/observability_init.zig` -- global provider
  pointers written without synchronization. The safety contract (call before
  spawning threads; do not deinit while in use) is documented in e71c66d.
  Because the telemetry seam is inert (GAP-0020), the racy path is currently
  unreachable.
- **Why this is a gap:** Once telemetry is re-enabled, concurrent readers could
  observe torn/freed pointers.
- **Recommended fix:** Publish via atomics (acquire/release) or guard
  init/teardown with a mutex when the seam is re-enabled.
- **Acceptance criteria:** Globals published/consumed with proper
  synchronization; lifecycle tested.

### AUTH-TEST-004: Preserve MFA benchmark references

- **Issue:** [#11](https://gitlab.com/devnw/zig/auth/-/issues/11)
- **Category:** Test
- **Severity:** Low
- **Status:** DEFERRED (no bench harness; originally required Geode runtime)
- **Why this matters now:** The absence of a bench harness also blocks perf
  validation of the accepted-with-rationale items below and the GAP-0042
  padding question.
- **Acceptance criteria:** Bench harness exists; MFA benchmark references
  preserved or re-established.

## Accepted (Won't Fix) with rationale

These items from the GAP-0025 performance umbrella
([#70](https://gitlab.com/devnw/zig/auth/-/issues/70), closed) were
deliberately NOT implemented. Rationale: no bench harness exists to prove a
win ([#11](https://gitlab.com/devnw/zig/auth/-/issues/11)), and all affected
operations are admin-path (not hot-path) frequency. Reopen individually if
profiling ever shows them to matter.

| Item | Rationale |
|---|---|
| O(n) user scans (`revokeUserKeys`/`listUserKeys`) | Admin-path frequency; per-user index adds invariant-maintenance complexity with unproven benefit |
| Two-pass `cleanupExpired` | Admin/maintenance path; single-pass rewrite risks correctness for unmeasured gain |
| HashMap pre-allocation | No measured allocation pressure; capacity guessing without data |
| GAP-0042 ([#86](https://gitlab.com/devnw/zig/auth/-/issues/86), closed Won't Do): ApiKey `?i64` sentinel encoding | Optionals are the clearer API; ~16B/key padding unproven without a bench harness |

The DONE half of the umbrella (CI Zig cache, stack-buffer base32 decode, BFS
deque, max_keys cap + tombstone reclamation) is recorded in
[GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).

## Public API (Implemented)

| Module | Exports |
|---|---|
| `auth.hmac` | `deriveHmacKey`, `computeRecordHmac`, `computeChainHash`, `verifyHmac`, `hmacToHex`, `hexToHmac`, `HkdfConfig`, `KeyValue` |
| `auth.api_keys` | `ApiKeyManager`, `parseApiKey`, `parseBearerToken`, `formatApiKey`, `Config`, `ApiKey`, `ParsedApiKey` |
| `auth.mfa` | `enroll`, `generateCode`, `verifyCode`, `verifyCodeStep`, `verifyCodeOnce`, `verifyScratchCode`, `base32Encode`, `base32Decode`, `MfaConfig`, `Enrollment` |
