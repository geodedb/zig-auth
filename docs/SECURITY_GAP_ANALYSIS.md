# Security Gap Analysis

Last updated: 2026-06-12 (post-remediation round 1+2)

## Overview

Security gap analysis for the `auth` library (`devnw/zig/auth`) at `main`,
Zig 0.16.0, refreshed after the **round-1 remediation** (`db4c3b6..a0de467`, 30
commits) and the **round-2 appsec review**. The authoritative deep-dives are:

- Round 1 (pre-remediation findings): [`docs/APPSEC_REVIEW_2026-06-12.md`](./APPSEC_REVIEW_2026-06-12.md)
- Round 2 (post-remediation verification): [`docs/APPSEC_REVIEW_2026-06-12_2.md`](./APPSEC_REVIEW_2026-06-12_2.md)

The round-2 review verified **every round-1 finding genuinely remediated at the
code level** (not just by presence), with targeted dynamic checks (5M-iteration
base32 fuzz, scratch-code double-spend, replay-window trace, deterministic-gate
execution, full test matrix) and reported **0 new Critical/High/Medium findings**
(1 Low, dispositioned; 2 Informational, fixed on save). Its bottom line: "No
further remediation round is required."

The previous (2026-06-12 pre-remediation) revision of this document carried 19
open findings. **17 of them are now resolved or dispositioned** and moved to the
[Resolved](#resolved-findings) / [Dispositioned](#dispositioned--accepted) sections
with commit evidence. The 2 that remain open are both **blocked**, mirroring the
repo tracker ([GAP_ANALYSIS.md](GAP_ANALYSIS.md)).

This is a **library**, not a running service — there is no network listener, no
in-repo privilege boundary. "Exploitability" is assessed from the perspective of a
consuming production application.

> Issue operations (create/update/close) are owned by a separate agent. This document
> only references Gap-IDs and existing issue numbers; it does not create issues.

## Summary

| Severity | Open | Resolved (round 1) | Dispositioned | SLA |
|----------|-----:|-------------------:|--------------:|-----|
| Critical | 0 | 0 | 0 | 7 days |
| High | 0 | 3 | 0 | 30 days |
| Medium | 1 (blocked) | 7 | 1 | 90 days |
| Low | 1 (blocked) | 6 | 0 | 180 days |
| Info | 0 | 0 | 1 | backlog |
| **Total** | **2** | **16** | **2** | |

Prior-revision resolutions (SEC-001…SEC-013 era): 10 (table retained below).

**No Critical or High findings are open.** The only two open items are blocked —
one on an upstream Zig issue, one on the other — and both are latent (the affected
code path is unreachable as shipped). No SLA clock is running on actionable work.

## Scanner Results

| Scanner | Scope | Round 1 | Round 2 (post-remediation) |
|---------|-------|---------|----------------------------|
| gitleaks | HEAD + full history | Clean | **Clean** — no secrets detected |
| semgrep | `p/python`, `p/secrets`, `p/ci-cd-security` | Clean | **Clean** — no findings |
| vuln-mcp (advisory DB) | dependency manifest | No advisories (Zig ecosystem not indexed; no-coverage, not no-risk) | unchanged |
| Zig toolchain download | `.gitlab-ci.yml` | SHA-256 verification sound | unchanged; verification preserved through the new CI cache (round-2 review §5) |
| Dynamic adversarial (round 2) | base32 decode/encode, scratch codes, replay, deterministic gate | — | 5M-iteration fuzz + targeted traces, **no overflow/OOB/double-spend/replay/gate-bypass** |

## Stack-Ranked Open Findings

Sorted by risk score descending. `Risk Score = Impact(1-5) x Likelihood(1-5) x 4`.

| Rank | Severity | RS | Finding | Component | CWE / OWASP | Evidence | Gap-ID / Issue | Status |
|-----:|----------|:--:|---------|-----------|-------------|----------|----------------|--------|
| 1 | Medium | 24 | `installGlobals` publishes unsynchronized global pointers | observability_init | CWE-825, CWE-362 / A04:2025 | `src/observability_init.zig` | GAP-0035 / SR-011 / [#79](https://gitlab.com/devnw/zig/auth/-/issues/79) | **Blocked** on GAP-0020 (#66) |
| 2 | Low | 24 | Telemetry hard-disabled; no auth security events emitted | observability | CWE-778 / A09:2025 | `src/observability.zig` (`enabled` hardcoded false) | GAP-0020 / AUTH-OBS-001 / [#66](https://gitlab.com/devnw/zig/auth/-/issues/66) | **Blocked** upstream (Zig module-dedup) |

## Open Findings — Detail

### GAP-0020 / AUTH-OBS-001 — Telemetry hard-disabled, no auth security events (Low, BLOCKED)

- **CWE/OWASP:** CWE-778 / A09:2025 Logging & Alerting Failures.
- **Status:** BLOCKED on an upstream Zig module-dedup issue. Issue [#66](https://gitlab.com/devnw/zig/auth/-/issues/66).
- **Evidence:** `src/observability.zig` — `enabled` hardcoded false collapses all
  spans to no-ops regardless of `-Dwith_otel`. **Round-1 improvement (e71c66d):**
  the inertness is now explicitly documented in code and README, the
  observability test is aligned with the hardcoded-disabled seam, and the
  `installGlobals` safety contract is documented — so the gap is no longer a
  silent surprise, and the seam was verified credential-safe by construction
  (round-2 review §5).
- **Impact:** Loss of authentication-failure / authz-denial signal. Consumers can
  log around it.
- **Remediation (when unblocked):** Restore `enabled = build_options.with_otel`,
  wire `-Dwith_otel=true` into a CI job, and cover the enabled path.

### GAP-0035 / SR-011 — `installGlobals` unsynchronized global pointers (Medium, BLOCKED)

- **CWE/OWASP:** CWE-825, CWE-362 / A04:2025. Issue [#79](https://gitlab.com/devnw/zig/auth/-/issues/79).
- **Status:** BLOCKED on GAP-0020 (#66) — the racy path is currently unreachable
  because the telemetry seam is inert.
- **Evidence:** `src/observability_init.zig` — global provider pointers written
  without synchronization. **Round-1 improvement (e71c66d):** the safety contract
  (call before spawning threads; do not deinit while in use) is now documented.
- **Impact:** Once telemetry is re-enabled, concurrent readers could observe
  torn/freed pointers.
- **Remediation (when unblocked):** Publish via atomics (acquire/release) or a
  `std.once`/CAS guard; test the lifecycle.

## Dispositioned / Accepted

| ID | Severity | Item | Disposition |
|----|----------|------|-------------|
| GAP-0018 / AUTH-SUP-001(-R2) | Medium → Low | `otel` dep `ref`/`hash` version-label disagreement (`build.zig.zon`) | **Dispositioned with evidence** ([#64](https://gitlab.com/devnw/zig/auth/-/issues/64) closed): cold-cache `zig fetch` of the fragment-pinned URL reproduces the pinned hash exactly — the pin is correct and deterministic; the label skew is upstream `.version` lag, filed as [otel#169](https://gitlab.com/devnw/zig/otel/-/issues/169). Re-confirmed by round-2 review (AUTH-SUP-001-R2, Low). |
| PC-PIN-001 / CI-COMP-001 | Info | pre-commit hooks + CI components pinned by version tag, not SHA | **Accepted** as Info-level hygiene: hooks are version-tag pinned and updated via controlled `pre-commit autoupdate` bumps; CI components are catalog-versioned (`@v1.7.1`) from the org's own `devnw/ci-catalog`. CI **images** are now digest-pinned (see CI-IMG-001, resolved). Reopen if third-party mutable-tag hooks are introduced. |

## Resolved Findings

### Round 1 remediation (2026-06-12)

All 16 findings below were fixed in round 1 (`db4c3b6..a0de467`) and the
corresponding GitLab issues closed with per-issue evidence comments
([GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md)). Remediations were
independently verified correct in situ — including dynamic adversarial
checks — by the round-2 review
([`APPSEC_REVIEW_2026-06-12_2.md`](./APPSEC_REVIEW_2026-06-12_2.md) §5).
Spot-check notes against the current tree inline.

| Gap-ID | Issue | Severity | Finding | Resolution evidence (commit) |
|--------|-------|----------|---------|------------------------------|
| GAP-0030 / SR-004 | [#74](https://gitlab.com/devnw/zig/auth/-/issues/74) | High | `MfaConfig.digits=0` → all-zero TOTP codes, silent MFA bypass | 9023a54 -- `MfaConfig.validate` rejects out-of-range digits (verified: `src/mfa.zig:63-67`, `digits` bounded 6..9) |
| GAP-0007 / AUTH-RNG-001 | [#56](https://gitlab.com/devnw/zig/auth/-/issues/56) | High | Credential generation used fallible `io.random()` (silent low-entropy fallback) | 3dc669e -- fail-closed `io.randomSecure` on all credential paths (verified: `src/api_keys.zig:186-187`; errors propagate via `std.Io.RandomSecureError` in the explicit error sets) |
| GAP-0008 / AUTH-MFA-002 | [#57](https://gitlab.com/devnw/zig/auth/-/issues/57) | High | Recovery codes 40-bit, no verify/consume API | 24d1150 + aeab6c6 + 2d0b429 -- 160-bit CSPRNG recovery codes, single-use constant-time `verifyScratchCode`, zeroization incl. error paths (round-2 dynamic check: no double-spend/resurrection) |
| GAP-0019 / AUTH-AKEY-002 | [#65](https://gitlab.com/devnw/zig/auth/-/issues/65) | Medium | `validateKey` returned borrowed `name`/`scopes` slices (UAF under concurrent revoke) | 5a36ff0 -- owned deep copies + `freeValidatedKey`; survives concurrent revoke + cleanup (test-proven) |
| GAP-0032 / SR-001 | [#76](https://gitlab.com/devnw/zig/auth/-/issues/76) | Medium | `createKey` clobbered on ID collision (overwrite + heap leak) | 5a36ff0 -- collision-safe `getOrPut` (`error.TokenIdCollision`), layered errdefer chain |
| GAP-0015 / AUTH-AKEY-001 | [#40](https://gitlab.com/devnw/zig/auth/-/issues/40) | Medium | API-key secret hashed with bare SHA-256, no server pepper | 5a36ff0 -- optional `Config.pepper`: `HMAC-SHA256(pepper, secret)` when set (verified: `hashSecret` at `src/api_keys.zig:35-38`); bare-SHA-256 default documented honestly in USAGE (7b21d7f) |
| GAP-0031 / SR-005+SR-006 | [#75](https://gitlab.com/devnw/zig/auth/-/issues/75) | Medium | `MfaConfig` unvalidated (div-by-zero panic, overflow panic, silent lockout) | 9023a54 -- `MfaConfig.validate` bounds `digits`/`step_seconds`/`window`, fails closed (verified: `src/mfa.zig:63-67`) |
| GAP-0016 / AUTH-MFA-001 | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) | Medium | `deterministic` misuse switch could defeat MFA in prod | 5988a6f -- compile-gated to test builds: `error.DeterministicModeIsTestOnly` outside `zig test` (round-2 dynamic check: gate executes) |
| GAP-0017 / AUTH-MFA-003 | [#43](https://gitlab.com/devnw/zig/auth/-/issues/43) | Medium | No TOTP replay protection; matched step not exposed | 5b36715 -- `verifyCodeStep` returns matched step (highest, no early exit); `verifyCodeOnce` enforces a monotonic high-water mark (round-2 replay trace: rejected) |
| GAP-0036 / SR-012 | [#80](https://gitlab.com/devnw/zig/auth/-/issues/80) | Medium | No adversarial / concurrency security tests | 5d6c97a + 9cf314a -- unconditional assertions; adversarial integration coverage (malformed keys, MFA config edges, recovery + replay lifecycle); 4-thread stress test (5a36ff0) |
| GAP-0033 / SR-008 | [#77](https://gitlab.com/devnw/zig/auth/-/issues/77) | Low | Duplicate-key HMAC order-dependent | 19f4a95 -- total (key,value) sort order, deterministic HMAC for duplicate keys + boundary tests |
| GAP-0034 / SR-003 | [#78](https://gitlab.com/devnw/zig/auth/-/issues/78) | Low | `key_prefix` `.` separator unenforced | 5a36ff0 -- separator rejection enforced at config boundary |
| GAP-0021 / AUTH-MFA-004 | [#44](https://gitlab.com/devnw/zig/auth/-/issues/44) | Low | Base32 encode/decode length asymmetry | 65fe8a1 -- RFC 4648 padding symmetry, exact-length decode, impossible-length rejection (round-2: fuzzed 5M iterations, no overflow/OOB) |
| GAP-0007-rel / QGA-009 | -- | Low | Default HKDF salts hardcoded (public) | 3df58e5 -- documented as development-only domain-separation strings (non-secret), production guidance in docs/USAGE.md; predictability concern mooted by the GAP-0016 compile gate |
| GAP-0013 / AUTH-SUP-002 | [#62](https://gitlab.com/devnw/zig/auth/-/issues/62) | Low | `minimum_zig_version` understated (0.15.1 vs real 0.16) | 0b45ee4 -- `minimum_zig_version` bumped to the true 0.16.0 floor; version single-sourced + sync hook |
| CI-IMG-001 | -- | Low | `debian:bookworm-slim` not digest-pinned (9 CI jobs) | 74232f4 + d759dfa -- base image digest-pinned (verified: `debian:bookworm-slim@sha256:35ae959f…` across all jobs in `.gitlab-ci.yml`) |

### Prior revision (2026-03-23 era, verified pre-round-1)

| ID | Issue | Original Severity | Finding | Remediation Evidence | Residual |
|----|-------|-------------------|---------|----------------------|----------|
| SEC-001 | #19 | Critical | Deterministic-by-default TOTP secret from public inputs | Default is random CSPRNG | Misuse switch → GAP-0016, **now resolved** (5988a6f) |
| SEC-002 | #22 | Critical | No secret zeroization anywhere | `crypto.secureZero` broadly applied | none |
| SEC-003 | #25 | High | Non-constant-time TOTP code comparison | `std.crypto.timing_safe.eql` | none |
| SEC-004 | #29 | High | `validateKey` returned dangling `*ApiKey` after mutex release | Returns owned value copy | Slice aliasing → GAP-0019, **now resolved** (5a36ff0) |
| SEC-005 | #34 | High | `listUserKeys` shallow-copied borrowed slices | Deep-clones with partial-failure cleanup | none |
| SEC-006 | #38 | Medium | `@panic` on >128 properties (DoS) | Returns `error.TooManyProperties` | none |
| SEC-007 | #39 | Medium | Key prefix not validated against config | Prefix equality check | none |
| SEC-009 | #41 | Medium | Silent error swallowing in `cleanupExpired` | Errors propagated, collect-then-remove | none |
| SEC-010 | #42 | Medium | Integer truncation panic on large key/value lengths | Guarded by the 128-property cap | none |
| SEC-013 | #45 | Low | Custom HMAC-SHA1 implementation | Uses stdlib `HmacSha1` | none |

Notes:

- **SEC-008**, **SEC-011**, **SEC-012** were re-scoped as GAP-0015, GAP-0017,
  GAP-0021 respectively — all three **resolved in round 1** (table above).
- Every residual carried forward from this table is now closed.

## Findings by Area

All areas are clean of open actionable findings; per-area status:

| Area | Open | Notes |
|------|------|-------|
| Authentication (MFA / TOTP) | 0 | GAP-0030/0031/0016/0017/0008/0021 + salts all resolved round 1; round-2 dynamic checks clean |
| Authentication (API Keys) | 0 | GAP-0019/0032/0015/0034 resolved round 1 (5a36ff0 cluster) |
| Cryptographic primitives (HMAC) | 0 | GAP-0033 resolved (19f4a95) |
| RNG / Entropy | 0 | GAP-0007 resolved (3dc669e, fail-closed `randomSecure`) |
| Observability / Detection | 2 (blocked) | GAP-0020 (#66, upstream) and GAP-0035 (#79, on #66); GAP-0036 tests resolved |
| Supply chain / CI | 0 | GAP-0013 + CI-IMG-001 resolved; GAP-0018 dispositioned (upstream otel#169); PC-PIN-001 accepted (Info) |

## Remediation Roadmap

All Quick-Win and Medium-Effort items from the previous revision are complete
(see Resolved tables). Remaining:

### Blocked / Strategic

| Gap-ID | Task | Gate |
|--------|------|------|
| GAP-0020 / GAP-0035 | Restore telemetry seam, synchronize global install, add `-Dwith_otel=true` CI job | Upstream Zig module-dedup issue (#66) |

### Optional hardening (round-2 suggestions, not findings)

- `Io.failing`-backed entropy-starvation test (type-system guarantee already
  strong via `randomSecure` explicit error sets).
- TSan CI job for the `ApiKeyManager` concurrency path (4-thread stress test
  currently passes 200/200).

## Immediate Actions Required

**None.** gitleaks and semgrep are clean on the post-remediation tree (round 2);
no leaked secrets, no active RCE, no finding requires credential rotation. The
pre-production blockers from the previous revision (GAP-0030 digits bypass,
GAP-0007 entropy fail-open, GAP-0008 recovery codes, GAP-0018 otel pin) are all
resolved or dispositioned with evidence. Per the round-2 appsec review: "No
further remediation round is required."

## Scoring Methodology

Risk scores use `Risk Score = Impact(1-5) x Likelihood(1-5) x 4`, producing a 0-100 scale.

| Scale | 1 | 2 | 3 | 4 | 5 |
|-------|---|---|---|---|---|
| Impact | Hardening | Info leak | Data tampering | PII/credential leak / auth bypass | RCE / priv-esc / cross-tenant |
| Likelihood | Theoretical | Rare / misconfig | Requires auth | Remote, constrained | Pre-auth, trivial |

Confidence: both open findings are `confidence::confirmed` as to current state
(the seam is verifiably inert; the unsynchronized install is verifiably
unreachable), with GAP-0035's *exploitability* `suspected` pending the seam
re-enable. All round-1 resolution evidence is `confidence::confirmed` via
current-tree spot checks plus the round-2 review's code-level and dynamic
verification.
