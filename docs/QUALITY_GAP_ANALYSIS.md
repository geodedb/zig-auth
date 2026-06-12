# Quality Gap Analysis

Last updated: 2026-06-12

> Phase 4 (quality domain) of the full audit. This file tracks **open**
> code-quality findings only. Items resolved since the previous revision
> (2026-03-23) are moved to the [Resolved](#resolved-since-previous-revision)
> section at the bottom of this document.
>
> Gap-IDs (e.g. `GAP-0019`) are the cross-domain audit identifiers shared
> with the security, performance, and gap-analysis tracks. QGA-IDs are the
> local quality-analysis sequence. Where a quality finding maps to a
> cross-domain gap, both IDs are listed. Issue ops (creating/updating
> GitLab issues) are owned by a separate agent; this document references
> existing issue numbers and Gap-IDs only.

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 1 |
| Medium   | 14 |
| Low      | 17 |
| **Total (open)** | **32** |

### Top 5 Risks

1. **`validateKey` returns a shallow `ApiKey` copy that aliases manager-owned `name`/`scopes`** (QGA-015 / GAP-0019, PriorityScore 60) -- The returned struct borrows pointers into the manager's hashmap. A concurrent `revokeKey`/`cleanupExpired`/`deinit` frees those slices, leaving the caller with a use-after-free. Security-tracked.
2. **`examples/basic.zig` uses a 0.16-removed API and is not shipped or built** (QGA-021 / GAP-0002, PriorityScore 36) -- `std.io.getStdOut()` (removed in Zig 0.16) means the example does not compile; it is absent from `build.zig` and from `build.zig.zon` `.paths`, so it is neither built in CI nor packaged for consumers.
3. **Inferred vs explicit error sets are inconsistent across the public API** (QGA-016 / GAP-0037, PriorityScore 36) -- `hmac.zig` declares explicit `error{...}!` returns while `api_keys.zig` and `mfa.zig` use inferred `!`, making the failure contract opaque to callers.
4. **No concurrency tests for the mutex-bearing `ApiKeyManager`** (QGA-024 / GAP-0036, PriorityScore 36) -- The manager carries a `std.Io.Mutex` but every test is single-threaded, so the locking discipline is unverified.
5. **`observability_init.zig` is permanently dead code** (QGA-023, PriorityScore 36) -- It is gated behind `observability.enabled`, which is hardwired `false` in the default build, so the module can never be reached as shipped.

---

## Stack-Ranked Findings

| Rank | Severity | PriorityScore | Category | Finding | Component | Evidence | Issue | Gap-ID | Fix Summary | Owner | Effort | Confidence | Status |
|------|----------|---------------|----------|---------|-----------|----------|-------|--------|-------------|-------|--------|------------|--------|
| 1 | High | 60 | api-contract | `validateKey` returns shallow `ApiKey` copy aliasing manager-owned `name`/`scopes` | `src/api_keys.zig` | `api_keys.zig:212` (`return key.*;`), borrows `name`/`scopes` set at `:129,:132` | -- | GAP-0019 | Deep-copy `name`/`scopes` into a caller-owned `ApiKey`, or document a borrow contract + `freeKey` and forbid concurrent mutation | TBD | M | confirmed | Open |
| 2 | Medium | 36 | docs | `examples/basic.zig` uses removed 0.16 API and is not shipped/built | `examples/basic.zig` | `examples/basic.zig:20` (`std.io.getStdOut()`, removed in 0.16); not referenced in `build.zig`; not in `build.zig.zon` `.paths` (`build.zig.zon:18-24`) | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) | GAP-0002 | Rewrite using `0.16` writer API, wire an `examples` build step, add `examples/` to `.paths` | TBD | M | confirmed | Open |
| 3 | Medium | 36 | api-contract | Inconsistent error sets: explicit `error{...}!` vs inferred `!` across modules | `src/hmac.zig`, `src/api_keys.zig`, `src/mfa.zig` | explicit at `hmac.zig:60,113`; inferred at `api_keys.zig:98,162,294,332`, `mfa.zig:148,191,231` | -- | GAP-0037 | Adopt one convention (prefer explicit error sets on public fns) and document it | TBD | M | confirmed | Open |
| 4 | Medium | 36 | tests | No concurrency tests for mutex-bearing `ApiKeyManager` | `src/api_keys.zig` | `api_keys.zig:60` (`mutex: std.Io.Mutex`); all tests at `:449-751` are single-threaded | -- | GAP-0036 | Add a multi-threaded stress test exercising create/validate/revoke/cleanup under contention | TBD | M | confirmed | Open |
| 5 | Medium | 36 | cleanup | `observability_init.zig` is permanently dead code | `src/root.zig`, `src/observability_init.zig` | `root.zig:60` gates on `observability.enabled`, which is `false` in the default build | -- | -- | Either document it as an otel-only (`-Dwith_otel=true`) module with a build that exercises it, or remove if unreachable | TBD | M | confirmed | Open |
| 6 | Medium | 36 | maintainability | Cross-free hazard: caller-allocator `listUserKeys`/`freeKeyList` vs manager `self.allocator` | `src/api_keys.zig` | `listUserKeys(self, allocator, ...)` at `:294`; `freeKeyList(allocator, ...)` at `:323`; manager owns `self.allocator` at `:57` | -- | GAP-0038 | Document that list/free must use the SAME allocator, or drop the param and use `self.allocator` consistently | TBD | S | confirmed | Open |
| 7 | Medium | 36 | maintainability | Time source not injectable (inline `now` in api_keys vs explicit `timestamp_ms` param in mfa) | `src/api_keys.zig`, `src/mfa.zig` | `api_keys.zig:119,192,202` call `std.Io.Timestamp.now(...)` inline; `mfa.zig:191,231` take an explicit timestamp | -- | -- | Introduce a clock seam (param or injected provider) so expiry logic is testable without real time | TBD | M | confirmed | Open |
| 8 | Medium | 36 | maintainability | ~20x repeated `std.Io.Threaded.global_single_threaded.io()` incantation | `src/api_keys.zig`, `src/mfa.zig` | repeated at `api_keys.zig:72,73,105,106,111,112,119,184,...`; `mfa.zig:135` | -- | GAP-0039 | Extract a small `io()` / `defaultIo()` helper (or store on the manager) to centralize the call | TBD | S | confirmed | Open |
| 9 | Medium | 36 | maintainability | No documented ownership/threading contract for returned `ApiKey`/`Enrollment` | `src/api_keys.zig`, `src/mfa.zig`, docs | borrow/own semantics undocumented at `api_keys.zig:162,294`; `mfa.zig:43-53,148` | -- | GAP-0040 | Add an ownership & threading contract section to module docs (who allocates/frees, lock scope) | TBD | M | confirmed | Open |
| 10 | Medium | 24 | tests | Missing edge-case coverage (empty name/scopes, unicode, max sizes) | `src/api_keys.zig` | `createKey` at `:92` has no tests for empty `name`, empty `scopes`, unicode, or maximum sizes | -- | -- | Add boundary/edge tests for name/scope inputs | TBD | S | confirmed | Open |
| 11 | Medium | 24 | docs | `docs/REQUIREMENTS.md` references stale Geode source paths | `docs/REQUIREMENTS.md` | old paths such as `src/security/api_keys.zig` instead of `src/api_keys.zig` | -- | -- | Update paths to the current flat `src/` layout | TBD | S | confirmed | Open |
| 12 | Medium | 24 | docs | README/zon claim Zig 0.15.1 while CI and code target 0.16 | `README.md`, `.gitlab-ci.yml`, `build.zig.zon` | `README.md:4,62` say `0.15.1+`; `build.zig.zon:5` `minimum_zig_version = "0.15.1"`; `.gitlab-ci.yml:27` `ZIG_VERSION: "0.16.0"`; code uses 0.16-only `std.Io.*` | -- | GAP-0013 | Reconcile the version story: bump min version + README badge, or restore 0.15.1 compatibility | TBD | S | confirmed | Open |
| 13 | Medium | 16 | maintainability | `single_threaded` io seam contradicts the per-method mutex locking | `src/api_keys.zig` | uses `std.Io.Threaded.global_single_threaded.io()` (`:72,105,...`) yet locks `mutex` on every method | -- | GAP-0040 | Decide the threading model: drop the mutex if truly single-threaded, or use a multi-threaded io | TBD | M | suspected | Open |
| 14 | Medium | 16 | maintainability | Misleading comment: "copy of the associated key info" implies a deep copy | `src/api_keys.zig` | `api_keys.zig:153` doc comment vs shallow `return key.*;` at `:212` | -- | GAP-0019 | Correct the comment as part of the GAP-0019 fix (deep copy or documented borrow) | TBD | S | confirmed | Open |
| 15 | Medium | 12 | cleanup | `CODEOWNERS` still uses placeholder `@your-username` | `CODEOWNERS` | `CODEOWNERS:3` (`* @your-username`) | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) | GAP-0026 | Replace with the real maintainer user/group so MR approvals route | TBD | S | confirmed | Open |
| 16 | Low | 20 | security | Default HKDF salts hardcoded in source (dev-default warning item) | `src/hmac.zig`, `src/mfa.zig` | `hmac.zig:33-35` (`"auth-hmac-v1"` / `"auth-chain-integrity"`); `mfa.zig:40` (`"auth-mfa-salt-v1"`) | -- | -- | Keep open: document that defaults are dev-only and callers must supply production salts | TBD | S | confirmed | Open |
| 17 | Low | 16 | maintainability | Magic-number literals (32 / 20 / 8) scattered through crypto/encoding code | `src/api_keys.zig`, `src/mfa.zig` | secret/hash `32`, secret `20` (`mfa.zig:129`), scratch `8` (`mfa.zig:174,181`) | -- | -- | Promote to named constants alongside existing `TOKEN_ID_SIZE`/`SECRET_SIZE` | TBD | S | confirmed | Open |
| 18 | Low | 12 | maintainability | `Enrollment.deinit(allocator)` vs `ApiKeyManager.deinit()` -- divergent deinit contracts | `src/mfa.zig`, `src/api_keys.zig` | `mfa.zig:47` takes an allocator; `api_keys.zig:71` takes none | -- | -- | Document the divergence (manager owns its allocator; Enrollment does not) or unify the pattern | TBD | S | confirmed | Open |
| 19 | Low | 12 | docs | `parseBearerToken` returns a borrowed slice into the input; undocumented | `src/api_keys.zig` | `api_keys.zig:436-443` returns a sub-slice of `auth_header` with no lifetime note | -- | -- | Document that the result borrows the caller's buffer (no allocation) | TBD | S | confirmed | Open |
| 20 | Low | 12 | maintainability | Missing `comptime` assert that `HmacSha1.mac_length == 20` | `src/mfa.zig` | `mfa.zig:206` indexes `h[19]`/`h[offset+3]` assuming a 20-byte MAC | -- | GAP-0044 | Add `comptime std.debug.assert(HmacSha1.mac_length == 20);` near the offset math | TBD | S | confirmed | Open |
| 21 | Low | 8 | tests | Conditionally no-op test: assertion skipped when `real_code == 999999` | `src/mfa.zig` | `mfa.zig:386-388` (`if (real_code != 999999) { ... expect(!valid) }`) | -- | -- | Pick a wrong code guaranteed != the real code, or compute one, so the assert always runs | TBD | S | confirmed | Open |
| 22 | Low | 8 | tests | `expires_at >= now` boundary semantics untested and undocumented | `src/api_keys.zig` | `api_keys.zig:192` uses `>=` (expiry inclusive) with no boundary test | -- | -- | Add a boundary test at `now == expires_at` and document inclusive-expiry semantics | TBD | S | confirmed | Open |
| 23 | Low | 8 | tests | 128-property boundary path of `computeRecordHmac` untested at the exact edge | `src/hmac.zig` | `hmac.zig:63` (`props.len <= max_stack`); test at `:245` uses 129, none at exactly 128 | -- | -- | Add a 128-prop (max stack) success test alongside the 129-prop error test | TBD | S | confirmed | Open |
| 24 | Low | 8 | tests | Empty-input `base32Decode("")` / `base32Encode("")` untested | `src/mfa.zig` | `base32Decode` at `:88`, `base32Encode` at `:61`; no empty-string test | -- | -- | Add explicit empty-input round-trip tests | TBD | S | confirmed | Open |
| 25 | Low | 8 | docs | README test count drift ("59 tests (47 unit + 12 integration)") | `README.md` | `README.md:15` vs actual `zig build test` / `test-integration` output | -- | GAP-0009 | Regenerate the count from a real test run (or drop the hard number) | TBD | S | suspected | Open |
| 26 | Low | 8 | docs | README claims "Zero Dependencies" but an otel dependency exists | `README.md`, `build.zig.zon` | `README.md:13` ("Zero Dependencies") vs `build.zig.zon:12-16` (`otel`, lazy) | -- | -- | Reword to "zero **required** dependencies; optional otel via `-Dwith_otel`" | TBD | S | confirmed | Open |
| 27 | Low | 8 | docs | README install URL pins `v0.1.0` while the released tag is `v0.1.5` | `README.md`, `build.zig.zon` | `README.md:26` (`.../v0.1.0/auth-v0.1.0.tar.gz`) vs `build.zig.zon:3` (`version = "0.1.5"`) | -- | -- | Update the install snippet to the current tag (or use a version placeholder) | TBD | S | confirmed | Open |
| 28 | Low | 8 | cleanup | `root.zig` `version` constant out of sync with the released tag | `src/root.zig`, `build.zig.zon` | `root.zig:38` (`version = "0.1.0"`) vs `build.zig.zon:3` (`"0.1.5"`) | -- | GAP-0011 | Derive the version from a single source of truth, or update the constant on release | TBD | S | confirmed | Open |
| 29 | Low | 8 | ci-cd | Makefile `fmt`/`ci` diverge from the real CI and lack fuzz/examples targets | `Makefile`, `.gitlab-ci.yml` | `Makefile:45` `fmt` omits `examples/`; `Makefile:52` `ci` runs `build`, CI build runs `zig build check` (`.gitlab-ci.yml:92`); no fuzz/examples make targets | -- | GAP-0045 | Align `make ci` with the CI job graph; add `fuzz` + `examples` targets; format `examples/` | TBD | S | confirmed | Open |
| 30 | Low | 8 | docs | `.cz.yaml` / ruff formatting and doc-comment polish | `.cz.yaml`, repo configs | `.cz.yaml` present (`bump_pattern`/`bump_map`); ruff cache present (`.ruff_cache/`) | -- | GAP-0028 | Ensure `.cz.yaml`/python tooling is ruff-formatted and consistent | TBD | S | suspected | Open |
| 31 | Low | 8 | docs | markdownlint MD040 (fenced code missing language) x2 | docs/*.md | `.markdownlint.json` does not disable MD040, so unlabeled fences fail lint | -- | GAP-0027 | Add language hints to the two offending fenced blocks | TBD | S | suspected | Open |
| 32 | Low | 8 | docs | Missing doc comments on public fns; `validateKey` length precondition undocumented | `src/api_keys.zig`, `src/mfa.zig` | `parseApiKey`/`parseBearerToken`/`base32*` lack `///` contracts; `validateKey` length/format precondition unstated | -- | GAP-0029 | Add `///` doc comments to public fns; document `validateKey` input length/format constraints | TBD | S | confirmed | Open |

---

## Findings by Category

### API Contract (3 findings)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-015 | High | `validateKey` returns shallow copy aliasing manager-owned slices | -- | GAP-0019 |
| QGA-016 | Medium | Inconsistent explicit vs inferred error sets | -- | GAP-0037 |
| QGA-017 | Medium | `listUserKeys`/`freeKeyList` caller-allocator cross-free hazard | -- | GAP-0038 |

### Maintainability (8 findings)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-017 | Medium | Caller-allocator vs `self.allocator` cross-free hazard | -- | GAP-0038 |
| QGA-018 | Medium | Time source not injectable | -- | -- |
| QGA-019 | Medium | ~20x repeated `io()` incantation | -- | GAP-0039 |
| QGA-020 | Medium | No ownership/threading contract doc | -- | GAP-0040 |
| QGA-027 | Medium | `single_threaded` io vs mutex contradiction | -- | GAP-0040 |
| QGA-028 | Medium | Misleading "copy of key info" comment | -- | GAP-0019 |
| QGA-031 | Low | Magic-number literals (32/20/8) | -- | -- |
| QGA-033 | Low | `Enrollment.deinit` vs manager `deinit` divergence | -- | -- |

### Tests (6 findings)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-024 | Medium | No concurrency tests for `ApiKeyManager` | -- | GAP-0036 |
| QGA-025 | Medium | Missing edge cases (empty name/scopes, unicode, max sizes) | -- | -- |
| QGA-036 | Low | Conditionally no-op `verifyCode` reject test | -- | -- |
| QGA-037 | Low | `expires_at >= now` boundary untested | -- | -- |
| QGA-038 | Low | 128-prop boundary untested | -- | -- |
| QGA-039 | Low | Empty `base32Decode`/`base32Encode` untested | -- | -- |

### Documentation (10 findings)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-021 | Medium | `examples/basic.zig` uses removed 0.16 API + not shipped | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) | GAP-0002 |
| QGA-022 | Medium | README/zon 0.15.1 claims vs 0.16 reality | -- | GAP-0013 |
| QGA-026 | Medium | `docs/REQUIREMENTS.md` stale Geode paths | -- | -- |
| QGA-034 | Low | `parseBearerToken` borrow undocumented | -- | -- |
| QGA-040 | Low | README test-count drift | -- | GAP-0009 |
| QGA-041 | Low | README "Zero Dependencies" vs otel dep | -- | -- |
| QGA-042 | Low | README install URL pins v0.1.0 | -- | -- |
| QGA-043 | Low | Missing doc comments + `validateKey` length note | -- | GAP-0029 |
| QGA-044 | Low | markdownlint MD040 x2 | -- | GAP-0027 |
| QGA-045 | Low | `.cz.yaml` / ruff formatting polish | -- | GAP-0028 |

### Cleanup (3 findings)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-023 | Medium | `observability_init.zig` permanently dead | -- | -- |
| QGA-029 | Medium | `CODEOWNERS` placeholder `@your-username` | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) | GAP-0026 |
| QGA-035 | Low | `root.zig` version constant mismatch | -- | GAP-0011 |

### Security (1 finding)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-030 | Low | Default HKDF salts hardcoded (dev-default) | -- | -- |

### Correctness assertions (1 finding)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-032 | Low | Missing `comptime` assert `HmacSha1.mac_length == 20` | -- | GAP-0044 |

### CI/CD (1 finding)

| ID | Severity | Finding | Issue | Gap-ID |
|----|----------|---------|-------|--------|
| QGA-046 | Low | Makefile `fmt`/`ci` diverge from CI; no fuzz/examples targets | -- | GAP-0045 |

---

## Roadmap

### Quick Wins (< 1 day)

| ID | Finding | Effort | Gap-ID |
|----|---------|--------|--------|
| QGA-017 | Document or unify list/free allocator contract | S | GAP-0038 |
| QGA-019 | Extract `io()` helper | S | GAP-0039 |
| QGA-029 | Update `CODEOWNERS` | S | GAP-0026 |
| QGA-030 | Document dev-only HKDF salts | S | -- |
| QGA-031 | Name the 32/20/8 magic numbers | S | -- |
| QGA-032 | Add `HmacSha1.mac_length` comptime assert | S | GAP-0044 |
| QGA-034 | Document `parseBearerToken` borrow | S | -- |
| QGA-035 | Sync `root.zig` version constant | S | GAP-0011 |
| QGA-036 | Fix conditionally-skipped reject test | S | -- |
| QGA-037 | Add expiry boundary test | S | -- |
| QGA-038 | Add 128-prop boundary test | S | -- |
| QGA-039 | Add empty base32 tests | S | -- |
| QGA-040 | Fix README test count | S | GAP-0009 |
| QGA-041 | Reword "Zero Dependencies" | S | -- |
| QGA-042 | Update README install URL to v0.1.5 | S | -- |
| QGA-043 | Add missing doc comments | S | GAP-0029 |
| QGA-044 | Fix MD040 fences | S | GAP-0027 |
| QGA-045 | ruff-format `.cz.yaml`/python tooling | S | GAP-0028 |
| QGA-046 | Align Makefile with CI; add targets | S | GAP-0045 |
| QGA-026 | Update REQUIREMENTS.md paths | S | -- |

### Medium (1-5 days)

| ID | Finding | Effort | Gap-ID |
|----|---------|--------|--------|
| QGA-015 | Deep-copy / document borrow for `validateKey` | M | GAP-0019 |
| QGA-016 | Standardize error sets across modules | M | GAP-0037 |
| QGA-018 | Introduce an injectable clock seam | M | -- |
| QGA-020 | Write the ownership/threading contract | M | GAP-0040 |
| QGA-021 | Rewrite + wire + ship `examples/basic.zig` | M | GAP-0002 |
| QGA-022 | Reconcile the Zig 0.15.1 vs 0.16 version story | S-M | GAP-0013 |
| QGA-023 | Resolve dead `observability_init.zig` (doc or remove) | M | -- |
| QGA-024 | Add concurrency stress tests | M | GAP-0036 |
| QGA-025 | Add input edge-case tests | S-M | -- |
| QGA-028 | Correct misleading "copy of key info" comment | S | GAP-0019 |

### Strategic (> 5 days)

| ID | Finding | Effort | Gap-ID |
|----|---------|--------|--------|
| QGA-027 | Resolve the single-threaded io vs mutex threading model | M-L | GAP-0040 |

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
- `suspected` -- Plausible from configuration/docs but not tool-verified. What would
  confirm each suspected item is noted below:
  - QGA-022/027 threading model (GAP-0040): a `-Dsingle-threaded` build comparison
    and a TSan/race run would confirm whether the mutex is load-bearing.
  - QGA-040 (README test count, GAP-0009): a clean `zig build test` +
    `zig build test-integration` run gives the exact number.
  - QGA-044 (MD040, GAP-0027): running `markdownlint **/*.md` enumerates the two fences.
  - QGA-045 (`.cz.yaml`/ruff, GAP-0028): running `ruff format --check` confirms.

---

## Issue & Gap Cross-Reference

| QGA ID | Severity | GitLab Issue | Gap-ID | Title |
|--------|----------|--------------|--------|-------|
| QGA-015 | High | -- | GAP-0019 | `validateKey` shallow-copy aliasing |
| QGA-016 | Medium | -- | GAP-0037 | Inconsistent error sets |
| QGA-017 | Medium | -- | GAP-0038 | list/free caller-allocator cross-free hazard |
| QGA-018 | Medium | -- | -- | Time not injectable |
| QGA-019 | Medium | -- | GAP-0039 | Repeated `io()` incantation |
| QGA-020 | Medium | -- | GAP-0040 | No ownership/threading contract doc |
| QGA-021 | Medium | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) | GAP-0002 | example uses removed 0.16 API + not shipped |
| QGA-022 | Medium | -- | GAP-0013 | 0.15.1 claims vs 0.16 reality |
| QGA-023 | Medium | -- | -- | `observability_init.zig` permanently dead |
| QGA-024 | Medium | -- | GAP-0036 | No concurrency tests |
| QGA-025 | Medium | -- | -- | Missing input edge-case tests |
| QGA-026 | Medium | -- | -- | REQUIREMENTS.md stale Geode paths |
| QGA-027 | Medium | -- | GAP-0040 | single_threaded io vs mutex contradiction |
| QGA-028 | Medium | -- | GAP-0019 | misleading "copy of key info" comment |
| QGA-029 | Medium | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) | GAP-0026 | CODEOWNERS placeholder |
| QGA-030 | Low | -- | -- | hardcoded dev-default HKDF salts |
| QGA-031 | Low | -- | -- | magic numbers (32/20/8) |
| QGA-032 | Low | -- | GAP-0044 | missing `HmacSha1.mac_length` assert |
| QGA-033 | Low | -- | -- | divergent deinit contracts |
| QGA-034 | Low | -- | -- | `parseBearerToken` borrow undocumented |
| QGA-035 | Low | -- | GAP-0011 | root.zig version constant mismatch |
| QGA-036 | Low | -- | -- | conditionally no-op reject test |
| QGA-037 | Low | -- | -- | expiry `>=` boundary untested |
| QGA-038 | Low | -- | -- | 128-prop boundary untested |
| QGA-039 | Low | -- | -- | empty base32 untested |
| QGA-040 | Low | -- | GAP-0009 | README test-count drift |
| QGA-041 | Low | -- | -- | "Zero Dependencies" vs otel dep |
| QGA-042 | Low | -- | -- | README install URL pins v0.1.0 |
| QGA-043 | Low | -- | GAP-0029 | missing doc comments + validateKey length |
| QGA-044 | Low | -- | GAP-0027 | markdownlint MD040 x2 |
| QGA-045 | Low | -- | GAP-0028 | `.cz.yaml`/ruff format polish |
| QGA-046 | Low | -- | GAP-0045 | Makefile vs CI divergence |

---

## Related Existing Issues

Pre-existing repository issues that overlap with open quality findings:

| Existing Issue | Related QGA | Relationship |
|---------------|-------------|--------------|
| [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) CODEOWNERS placeholder | QGA-029 | Same finding; still open (re-scoped as GAP-0026) |
| [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) examples/basic.zig non-functional | QGA-021 | Same finding; worse than first reported (re-scoped as GAP-0002) |
| [#14](https://gitlab.com/devnw/zig/auth/-/issues/14) AUTH-DOC-003: document MFA config knobs | QGA-030 | Salt/secret documentation depends on this requirement |

---

## Resolved Since Previous Revision

The following items from the 2026-03-23 revision are now resolved. They are
retained here for traceability; see also `docs/GAP_ANALYSIS_RESOLVED.md` for the
cross-domain resolution log.

| Prev ID | Severity | Finding | Resolution Evidence | Issue | Resolved |
|---------|----------|---------|---------------------|-------|----------|
| QGA-001 | High | README Quick Start referenced non-existent `auth.init` API | `README.md:44-58` now uses the real `auth.hmac` / `auth.api_keys` / `auth.mfa` surface | [#17](https://gitlab.com/devnw/zig/auth/-/issues/17) | 2026-06-12 |
| QGA-002 | High | TOTP secret derived deterministically by default | Default is now random CSPRNG (`mfa.zig:37-38,134-136`). Residual = deterministic-mode misuse switch, re-scoped as **GAP-0016** | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) | 2026-06-12 |
| QGA-003 | High | `listUserKeys` returned shallow copies with borrowed pointers | `listUserKeys` now deep-clones `name`/`scopes` (`api_keys.zig:312-314`). Residual `validateKey` aliasing tracked as **QGA-015 / GAP-0019** | [#26](https://gitlab.com/devnw/zig/auth/-/issues/26) | 2026-06-12 |
| QGA-006 | Medium | `computeRecordHmac` panicked on >128 properties | Now returns `error.TooManyProperties` (`hmac.zig:60,67`); covered by test at `hmac.zig:245-253` | [#32](https://gitlab.com/devnw/zig/auth/-/issues/32) | 2026-06-12 |
| QGA-010 | Low | Hand-rolled HMAC-SHA1 | Replaced with `std.crypto.auth.hmac.HmacSha1` (`mfa.zig:16,206-207`) | -- | 2026-06-12 |
| QGA-011 | Low | Repeated HKDF extract in scratch-code loop | `prk` extraction hoisted out of the loop (`mfa.zig:170-171`) | -- | 2026-06-12 |
| QGA-012 | Low | `cleanupExpired` swallowed OOM via `catch continue` | Now propagates errors via a fallible collect-then-remove pass (`api_keys.zig:332-356`) | -- | 2026-06-12 |

### Re-scoped / superseded

- **QGA-004** (CODEOWNERS) -> still open, re-scoped as **QGA-029 / GAP-0026**.
- **QGA-005** (examples/basic.zig) -> still open and worse than first reported, re-scoped as **QGA-021 / GAP-0002**.
- **QGA-007 / QGA-008** (CI Zig caching / artifact reuse) -> still open, folded into **GAP-0025**.
- **QGA-009** (hardcoded HKDF salts) -> still open as a dev-default warning item, re-scoped as **QGA-030**.
- **QGA-013** (REQUIREMENTS.md stale paths) -> still open, re-scoped as **QGA-026**.
- **QGA-014** (CI `ZIG_VERSION` vs zon min version) -> still open, re-scoped as **QGA-022 / GAP-0013** (now a 0.15.1-vs-0.16 mismatch).
