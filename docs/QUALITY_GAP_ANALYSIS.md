# Quality Gap Analysis

Last updated: 2026-06-12 (post-remediation round 1+2)

> Phase 4 (quality domain) of the full audit. This file tracks **open**
> code-quality findings only. The 2026-06-12 (pre-remediation) revision of
> this document carried 32 open findings; the round-1 remediation
> (commits `db4c3b6..a0de467`, 30 commits) closed 29 of them with code,
> test, and doc changes. They are recorded in
> [Resolved -- Round 1 remediation](#resolved----round-1-remediation-2026-06-12)
> below with per-finding commit evidence. The remaining 3 map onto the
> repo's 3 tracker-open items (see
> [GAP_ANALYSIS.md](GAP_ANALYSIS.md)); a handful of nit-level
> observations are recorded as accepted (won't-fix) below.
>
> Gap-IDs (e.g. `GAP-0019`) are the cross-domain audit identifiers shared
> with the security, performance, and gap-analysis tracks. QGA-IDs are the
> local quality-analysis sequence. Where a quality finding maps to a
> cross-domain gap, both IDs are listed. Issue ops (creating/updating
> GitLab issues) are owned by a separate agent; this document references
> existing issue numbers and Gap-IDs only.
>
> Round-2 verification: the post-remediation tree was independently
> re-reviewed in
> [`docs/APPSEC_REVIEW_2026-06-12_2.md`](./APPSEC_REVIEW_2026-06-12_2.md)
> (round 2), which confirmed every round-1 remediation correct in situ
> (0 new Critical/High/Medium findings).

## Summary

| Severity | Open |
|----------|------|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |
| **Total (open, actionable)** | **0** |

| Disposition | Count |
|-------------|-------|
| Resolved in round 1 (2026-06-12) | 29 |
| Pointers to tracker-open items (quality-relevant) | 3 |
| Accepted (won't-fix) nits | 5 |
| Round-2 cleanup (landed, 43b2ac3) | 1 |

No actionable quality findings remain open in this domain. Everything
below is either blocked on an upstream/tracker item, an accepted nit, or
landed round-2 polish.

---

## Open -- Pointers to Tracker-Open Items

These are the only 3 open items in the repo tracker
([GAP_ANALYSIS.md](GAP_ANALYSIS.md)); each has a quality-relevant facet
formerly tracked here:

| Tracker item | Issue | Status | Quality facet (former QGA) |
|---|---|---|---|
| GAP-0020 -- observability seam permanently disabled | [#66](https://gitlab.com/devnw/zig/auth/-/issues/66) | Blocked (upstream Zig module-dedup) | QGA-023: `observability_init.zig` unreachable as shipped. Inertness is now explicitly documented in code and README (e71c66d), so it is no longer a silent surprise; remove-or-enable decision is blocked on #66. |
| GAP-0035 -- `installGlobals` unsynchronized globals | [#79](https://gitlab.com/devnw/zig/auth/-/issues/79) | Blocked (on GAP-0020) | QGA-027 residual: the threading model is now documented (mutex/futex verification note, `src/api_keys.zig:23`; ownership/threading contract in docs/USAGE.md), but the global-install synchronization itself waits on the seam re-enable. |
| AUTH-TEST-004 -- preserve MFA benchmark references | [#11](https://gitlab.com/devnw/zig/auth/-/issues/11) | Deferred | No bench harness; blocks quantitative validation of the perf accepted-with-rationale items (see PERF_GAP_ANALYSIS.md). |

## Round-2 Cleanup

- **`DecodedSecret` extraction (src/mfa.zig) -- landed (43b2ac3).** The
  stack-vs-heap base32 secret decode (introduced in 4a33957) is factored
  into a dedicated `DecodedSecret` helper type with its own
  `slice()`/`deinit()` contract; the TOTP secret length is a named
  constant and the replay assertion is unguarded. No behavior change;
  readability/structure only.

## Accepted (Won't-Fix) Nits

Recorded so future passes do not re-raise them. Reopen only with new
evidence.

| ID | Nit | Rationale |
|----|-----|-----------|
| F3 | Observability span boilerplate repeated across `api_keys.zig`/`mfa.zig` call sites | The seam is a comptime no-op by default (GAP-0020); deduplicating boilerplate around an inert seam is churn. Revisit when #66 unblocks. |
| F5 | Long doc comments on some public functions | Deliberate: the round-1 remediation made ownership/threading/error contracts explicit in `///` docs (GAP-0029/0040). Verbosity accepted over ambiguity. |
| -- | `ioh` helper naming (`src/api_keys.zig:24`) | Terse but local, documented, and single-purpose; renaming is churn with no contract change. |
| QGA-018 | Time source not injectable in `api_keys.zig` (`nowSeconds` via `ioh()`) | `std.Io` is itself the intended seam; an injectable clock is deferred to the future threaded-io work and bench harness (#11). Expiry boundary behavior is now covered by a real test (`src/api_keys.zig:925`). |
| QGA-034 | `parseBearerToken` returns a borrowed sub-slice of the input; `///` doc does not spell out the lifetime | Pure-slice helper with no allocation; the one-line doc comment landed in 5b67caf. Lifetime note is doc polish only. |

---

## Resolved -- Round 1 remediation (2026-06-12)

All 29 findings below were closed by the round-1 remediation
(`db4c3b6..a0de467`). Cross-domain log:
[GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md). Spot-checked
against the current tree (verification notes inline); independently
confirmed by the round-2 appsec review
([`APPSEC_REVIEW_2026-06-12_2.md`](./APPSEC_REVIEW_2026-06-12_2.md) §5).

| QGA ID | Severity | Finding | Gap-ID | Resolution evidence (commit) |
|--------|----------|---------|--------|------------------------------|
| QGA-015 | High | `validateKey` shallow-copy aliasing manager-owned `name`/`scopes` | GAP-0019 | 5a36ff0 -- owned deep copies + `freeValidatedKey` (verified: docs/USAGE.md:75 ownership table; survives concurrent revoke in stress test) |
| QGA-016 | Medium | Inconsistent explicit vs inferred error sets | GAP-0037 | 634d36c -- explicit error sets on all public fallible fns (verified: `ParseError`/`CreateKeyError` at `src/api_keys.zig:69,72`) |
| QGA-017 | Medium | `listUserKeys`/`freeKeyList` caller-allocator cross-free hazard | GAP-0038 | 3df58e5 -- allocator-pairing contract documented (verified: docs/USAGE.md:74-76 same-allocator table) |
| QGA-019 | Medium | ~20x repeated `io()` incantation | GAP-0039 | 5a36ff0 -- `ioh()` helper centralizes the call (verified: `src/api_keys.zig:24`) |
| QGA-020 | Medium | No ownership/threading contract doc | GAP-0040 | 5a36ff0 + 3df58e5 -- threading/ownership contract in module docs + docs/USAGE.md |
| QGA-021 | Medium | `examples/basic.zig` removed-API + not shipped/built | GAP-0002 | 9ba0c79 -- working example wired into `zig build example` (verified: `build.zig:191-203` example step; `examples/basic.zig` compiles) |
| QGA-022 | Medium | README/zon 0.15.1 claims vs 0.16 reality | GAP-0013 | 0b45ee4 -- `minimum_zig_version` bumped to true 0.16.0 floor; README aligned |
| QGA-024 | Medium | No concurrency tests for mutex-bearing `ApiKeyManager` | GAP-0036 | 5a36ff0 + 5d6c97a + 9cf314a -- 4-thread create/validate/revoke/cleanup stress test (passes 200/200 per round-2 review) + adversarial integration tests |
| QGA-025 | Medium | Missing edge cases (empty name/scopes, unicode, max sizes) | -- | 5a36ff0 + 9cf314a -- boundary/edge tests (verified: `"createKey accepts empty name and empty scopes"` at `src/api_keys.zig:934`; malformed-key adversarial tests) |
| QGA-026 | Medium | `docs/REQUIREMENTS.md` stale Geode source paths | -- | 58578e7 + round-1 doc passes -- verified: no `src/security/*` path remains in docs/REQUIREMENTS.md |
| QGA-028 | Medium | Misleading "copy of key info" comment | GAP-0019 | 5a36ff0 -- comment corrected as part of the deep-copy fix |
| QGA-029 | Medium | `CODEOWNERS` placeholder `@your-username` | GAP-0026 | 0b45ee4 -- placeholder replaced with the real maintainer ([#28](https://gitlab.com/devnw/zig/auth/-/issues/28) closed) |
| QGA-030 | Low | Default HKDF salts hardcoded (dev-default) | -- | 3df58e5 -- documented as development-only domain-separation strings (verified: docs/USAGE.md:180) |
| QGA-031 | Low | Magic-number literals (32/20/8) in crypto/encoding code | -- | 24d1150 -- named constants (verified: `SCRATCH_CODE_RAW_LEN`/`SCRATCH_CODE_LEN` at `src/mfa.zig:91-93`) |
| QGA-032 | Low | Missing `comptime` assert `HmacSha1.mac_length == 20` | GAP-0044 | 9023a54 -- comptime assert added next to the offset math |
| QGA-033 | Low | `Enrollment.deinit` vs manager `deinit` divergence | -- | 3df58e5 + 5b67caf -- divergence documented (Enrollment takes the allocator; manager owns its own) in `///` docs and USAGE ownership table |
| QGA-035 | Low | `root.zig` version constant out of sync with tag | GAP-0011 | 0b45ee4 -- version single-sourced + version-sync pre-commit hook |
| QGA-036 | Low | Conditionally no-op test (`real_code == 999999` skip) | -- | 5d6c97a -- wrong-code rejection test made unconditional (verified: no `999999` guard remains in `src/mfa.zig`) |
| QGA-037 | Low | `expires_at >= now` boundary untested/undocumented | -- | 5a36ff0 -- inclusive-expiry boundary test (verified: `src/api_keys.zig:925`) |
| QGA-038 | Low | 128-prop boundary of `computeRecordHmac` untested at the edge | -- | 19f4a95 -- exact-boundary test (verified: `"accepts exactly 128 properties"` at `src/hmac.zig:287`) |
| QGA-039 | Low | Empty-input `base32Decode`/`base32Encode` untested | -- | 65fe8a1 -- empty-input + all 7 RFC 4648 vectors (verified: `src/mfa.zig:640`) |
| QGA-040 | Low | README test-count drift | GAP-0009 | 0b45ee4 -- test-count/version claims reconciled with real runs |
| QGA-041 | Low | README "Zero Dependencies" vs otel dep | -- | 0b45ee4 -- claim corrected (verified: no "Zero Dependencies" claim at HEAD) |
| QGA-042 | Low | README install URL pins v0.1.0 | -- | 0b45ee4 -- install snippet updated to the released tag |
| QGA-043 | Low | Missing doc comments; `validateKey` precondition undocumented | GAP-0029 | 5b67caf -- `///` doc comments on remaining pub fns; `validateKey` decomposed + documented (5a36ff0) |
| QGA-044 | Low | markdownlint MD040 (fences missing language) x2 | GAP-0027 | 5b67caf -- language hints on all fences |
| QGA-045 | Low | `.cz.yaml` / ruff formatting polish | GAP-0028 | 5b67caf -- `.cz.yaml` pretty-format + ruff format |
| QGA-046 | Low | Makefile `fmt`/`ci` diverge from CI; no fuzz/examples targets | GAP-0045 | 3d0e632 -- Makefile aligned with CI (check, fuzz, release-mode matrix, fmt examples/) |
| QGA-027 | Medium | `single_threaded` io seam vs per-method mutex contradiction | GAP-0040 | 5a36ff0 -- resolved by documentation + verification: the mutex/futex path delegates to real OS futexes in non-single-threaded builds (note at `src/api_keys.zig:23`); residual global-install sync tracked as GAP-0035 (see pointers above) |

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

- `confirmed` -- Verified via direct code inspection in this revision.
- `suspected` -- Plausible from configuration/docs but not tool-verified.

All round-1 resolutions above are `confirmed` (current-tree spot checks
plus the round-2 appsec review's in-situ verification).

---

## Resolved Since Previous Revision (2026-03-23)

The following items from the 2026-03-23 revision were resolved before
round 1. Retained for traceability; see also
`docs/GAP_ANALYSIS_RESOLVED.md` for the cross-domain resolution log.

| Prev ID | Severity | Finding | Resolution Evidence | Issue | Resolved |
|---------|----------|---------|---------------------|-------|----------|
| QGA-001 | High | README Quick Start referenced non-existent `auth.init` API | `README.md` now uses the real `auth.hmac` / `auth.api_keys` / `auth.mfa` surface | [#17](https://gitlab.com/devnw/zig/auth/-/issues/17) | 2026-06-12 |
| QGA-002 | High | TOTP secret derived deterministically by default | Default is random CSPRNG. Residual misuse switch was re-scoped as **GAP-0016**, now also resolved (5988a6f, test-build-gated) | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) | 2026-06-12 |
| QGA-003 | High | `listUserKeys` returned shallow copies with borrowed pointers | `listUserKeys` deep-clones `name`/`scopes`. Residual `validateKey` aliasing was re-scoped as **QGA-015 / GAP-0019**, now also resolved (5a36ff0) | [#26](https://gitlab.com/devnw/zig/auth/-/issues/26) | 2026-06-12 |
| QGA-006 | Medium | `computeRecordHmac` panicked on >128 properties | Returns `error.TooManyProperties`; boundary covered both sides (19f4a95) | [#32](https://gitlab.com/devnw/zig/auth/-/issues/32) | 2026-06-12 |
| QGA-010 | Low | Hand-rolled HMAC-SHA1 | Replaced with `std.crypto.auth.hmac.HmacSha1` | -- | 2026-06-12 |
| QGA-011 | Low | Repeated HKDF extract in scratch-code loop | `prk` extraction hoisted out of the loop | -- | 2026-06-12 |
| QGA-012 | Low | `cleanupExpired` swallowed OOM via `catch continue` | Propagates errors via fallible collect-then-remove | -- | 2026-06-12 |

### Re-scoped / superseded (all now closed)

- **QGA-004** (CODEOWNERS) -> closed as **QGA-029 / GAP-0026** (0b45ee4).
- **QGA-005** (examples/basic.zig) -> closed as **QGA-021 / GAP-0002** (9ba0c79).
- **QGA-007 / QGA-008** (CI Zig caching / artifact reuse) -> closed via **GAP-0025** partial-close (74232f4); see PERF_GAP_ANALYSIS.md.
- **QGA-009** (hardcoded HKDF salts) -> closed as **QGA-030** (documented dev-only, 3df58e5).
- **QGA-013** (REQUIREMENTS.md stale paths) -> closed as **QGA-026**.
- **QGA-014** (CI `ZIG_VERSION` vs zon min version) -> closed as **QGA-022 / GAP-0013** (0b45ee4).
