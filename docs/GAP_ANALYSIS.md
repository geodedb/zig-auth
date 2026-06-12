# Gap Analysis

Last updated: 2026-06-12

> This file contains ONLY open gaps. Resolved items are in
> [GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md).
> Platform issues (GitLab) are the source of truth; this file is a mirror.

## Implementation Status Summary

| Metric | Count |
|---|---|
| Total tracked requirements | 15 |
| Open gaps (this file) | 41 |
| Open gaps by severity | High: 4 · Medium: 18 · Low: 19 |
| Open gaps by category | Security: 12 · Quality: 11 · Perf: 6 · Docs: 5 · Test: 3 · Supply-chain: 2 · Observability: 1 · Bug: 1 |
| Resolved gaps | 7 (see RESOLVED) |
| Unit + integration tests | 64 pass + 2 skip |
| Memory leaks | 0 |

> Note: the `64 pass + 2 skip` figure is itself a documentation-vs-reality
> finding tracked as GAP-0009; the README still claims 59.

## Severity / Issue Index

| Gap-ID | Title | Severity | Category | Issue |
|---|---|---|---|---|
| GAP-0002 | examples/basic.zig non-functional placeholder | Medium | Docs | [#30](https://gitlab.com/devnw/zig/auth/-/issues/30) |
| GAP-0006 | Incomplete RFC 4648 base32 test vectors | Medium | Test | [#55](https://gitlab.com/devnw/zig/auth/-/issues/55) |
| GAP-0007 | Credential RNG uses fallible io.random() | High | Security | [#56](https://gitlab.com/devnw/zig/auth/-/issues/56) |
| GAP-0008 | Recovery codes ~40-bit entropy + no verify API | High | Security | [#57](https://gitlab.com/devnw/zig/auth/-/issues/57) |
| GAP-0009 | Stale test-count/version claims in docs | Low | Docs | [#58](https://gitlab.com/devnw/zig/auth/-/issues/58) |
| GAP-0010 | observability_disabled_test fails under -Dwith_otel=true | High | Test | [#59](https://gitlab.com/devnw/zig/auth/-/issues/59) |
| GAP-0011 | root.zig vs zon version mismatch; no sync check | Medium | Quality | [#60](https://gitlab.com/devnw/zig/auth/-/issues/60) |
| GAP-0012 | README dead link to RECIPE.md | Low | Docs | [#61](https://gitlab.com/devnw/zig/auth/-/issues/61) |
| GAP-0013 | minimum_zig_version understates 0.16 floor | Low | Supply-chain | [#62](https://gitlab.com/devnw/zig/auth/-/issues/62) |
| GAP-0014 | CHANGELOG missing 0.1.1-0.1.5 entries | Low | Docs | [#63](https://gitlab.com/devnw/zig/auth/-/issues/63) |
| GAP-0015 | API key secret hashed with plain SHA-256, no pepper | Medium | Security | [#40](https://gitlab.com/devnw/zig/auth/-/issues/40) |
| GAP-0016 | Deterministic TOTP misuse switch needs compile-time gate | Medium | Security | [#23](https://gitlab.com/devnw/zig/auth/-/issues/23) |
| GAP-0017 | No TOTP replay protection | Medium | Security | [#43](https://gitlab.com/devnw/zig/auth/-/issues/43) |
| GAP-0018 | otel pin ref vs hash mismatch (cold CI fetch fails) | Medium | Supply-chain | [#64](https://gitlab.com/devnw/zig/auth/-/issues/64) |
| GAP-0019 | validateKey borrowed slices -> UAF under concurrent revoke | Medium | Security | [#65](https://gitlab.com/devnw/zig/auth/-/issues/65) |
| GAP-0020 | observability seam permanently disabled; enabled path untested | Low | Observability | [#66](https://gitlab.com/devnw/zig/auth/-/issues/66) |
| GAP-0021 | base32Encode trailing garbage for non-mod-5 input | Low | Security | [#44](https://gitlab.com/devnw/zig/auth/-/issues/44) |
| GAP-0022 | listUserKeys leaks copy.scopes on append OOM | Medium | Bug | [#67](https://gitlab.com/devnw/zig/auth/-/issues/67) |
| GAP-0023 | createKey holds mutex across RNG+SHA256+format+allocs | Medium | Perf | [#68](https://gitlab.com/devnw/zig/auth/-/issues/68) |
| GAP-0024 | validateKey double Timestamp.now under lock | Low | Perf | [#69](https://gitlab.com/devnw/zig/auth/-/issues/69) |
| GAP-0025 | Perf backlog umbrella (incl. CI cache #35/#36) | Low | Perf | [#70](https://gitlab.com/devnw/zig/auth/-/issues/70) |
| GAP-0026 | CODEOWNERS placeholder @your-username | Medium | Quality | [#28](https://gitlab.com/devnw/zig/auth/-/issues/28) |
| GAP-0027 | markdownlint MD040 fences | Low | Quality | [#71](https://gitlab.com/devnw/zig/auth/-/issues/71) |
| GAP-0028 | .cz.yaml + ruff formatting | Low | Quality | [#72](https://gitlab.com/devnw/zig/auth/-/issues/72) |
| GAP-0029 | Missing doc comments; validateKey 52 lines | Low | Quality | [#73](https://gitlab.com/devnw/zig/auth/-/issues/73) |
| GAP-0030 | MfaConfig digits=0 -> silent MFA bypass | High | Security | [#74](https://gitlab.com/devnw/zig/auth/-/issues/74) |
| GAP-0031 | MfaConfig unvalidated: lockout/div-by-zero/overflow panics | Medium | Security | [#75](https://gitlab.com/devnw/zig/auth/-/issues/75) |
| GAP-0032 | createKey keys.put clobbers on ID collision | Medium | Security | [#76](https://gitlab.com/devnw/zig/auth/-/issues/76) |
| GAP-0033 | computeRecordHmac duplicate keys -> order-dependent HMAC | Low | Security | [#77](https://gitlab.com/devnw/zig/auth/-/issues/77) |
| GAP-0034 | key_prefix separator documented but not enforced | Low | Quality | [#78](https://gitlab.com/devnw/zig/auth/-/issues/78) |
| GAP-0035 | installGlobals publishes unsynchronized global pointers | Medium | Security | [#79](https://gitlab.com/devnw/zig/auth/-/issues/79) |
| GAP-0036 | Test coverage: concurrency/MFA-config/adversarial/boundaries | Medium | Test | [#80](https://gitlab.com/devnw/zig/auth/-/issues/80) |
| GAP-0037 | Inconsistent error-set declarations | Medium | Quality | [#81](https://gitlab.com/devnw/zig/auth/-/issues/81) |
| GAP-0038 | listUserKeys/freeKeyList cross-free hazard | Medium | Quality | [#82](https://gitlab.com/devnw/zig/auth/-/issues/82) |
| GAP-0039 | Repeated io() incantation; time not injectable | Low | Quality | [#83](https://gitlab.com/devnw/zig/auth/-/issues/83) |
| GAP-0040 | ApiKeyManager ownership/threading contract undocumented | Medium | Docs | [#84](https://gitlab.com/devnw/zig/auth/-/issues/84) |
| GAP-0041 | Dead subject-id bufPrint when telemetry disabled | Low | Perf | [#85](https://gitlab.com/devnw/zig/auth/-/issues/85) |
| GAP-0042 | ApiKey two ?i64 fields cost ~16B padding | Low | Perf | [#86](https://gitlab.com/devnw/zig/auth/-/issues/86) |
| GAP-0043 | TOTP digit modulus recomputed per window step | Low | Perf | [#87](https://gitlab.com/devnw/zig/auth/-/issues/87) |
| GAP-0044 | Missing comptime assert HmacSha1.mac_length==20 | Low | Quality | [#88](https://gitlab.com/devnw/zig/auth/-/issues/88) |
| GAP-0045 | Makefile/CI divergence | Low | Quality | [#89](https://gitlab.com/devnw/zig/auth/-/issues/89) |

## Open Requirements (not yet implemented)

| ID | Issue | Title | Status |
|---|---|---|---|
| AUTH-TEST-004 | [#11](https://gitlab.com/devnw/zig/auth/-/issues/11) | Preserve MFA benchmark references | Deferred (requires Geode runtime) |
| AUTH-DOC-001 | [#12](https://gitlab.com/devnw/zig/auth/-/issues/12) | Document token-format configuration | Not implemented |
| AUTH-DOC-002 | [#13](https://gitlab.com/devnw/zig/auth/-/issues/13) | Document HMAC-chain usage | Not implemented |
| AUTH-DOC-003 | [#14](https://gitlab.com/devnw/zig/auth/-/issues/14) | Document MFA configuration knobs | Not implemented |

## Gaps

### GAP-0002: examples/basic.zig is a non-functional template placeholder

- **Issue:** [#30](https://gitlab.com/devnw/zig/auth/-/issues/30)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** Developer onboarding; `examples/` directory
- **Current state (evidence):**
  - `examples/basic.zig` -- library usage commented out; references `lib.Config`/`lib.init` which do not exist
  - Also uses `std.io.getStdOut`, removed in Zig 0.16, so it would not compile on the real toolchain floor
  - Not referenced in `build.zig.zon` paths; not wired into `build.zig` (dead/unbuilt)
- **Why this is a gap:** The example provides no working usage guidance and cannot compile.
- **Impact/Risk:** Developers looking for usage patterns find a broken template.
- **Recommended fix:** Rewrite with working API-key/HMAC/MFA demonstrations using current exports; wire it into the build.
- **Acceptance criteria:** Example imports a real export, compiles with `zig build`, and is reachable from the build graph.

### GAP-0006: Incomplete RFC 4648 base32 test vectors

- **Issue:** [#55](https://gitlab.com/devnw/zig/auth/-/issues/55)
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** AUTH-REQ-003 (#3); RFC 4648 Section 10
- **Current state (evidence):** `src/mfa.zig:413-434` -- only 1 of the 7 RFC 4648 vectors exercised.
- **Why this is a gap:** Canonical padding/alphabet bugs could go undetected.
- **Impact/Risk:** Silent TOTP-secret interchange breakage with standard authenticators.
- **Recommended fix:** Assert all 7 vectors plus a round-trip property.
- **Acceptance criteria:** All 7 encode/decode pairs pass; round-trip holds.

### GAP-0007: Credential RNG uses fallible io.random() not io.randomSecure()

- **Issue:** [#56](https://gitlab.com/devnw/zig/auth/-/issues/56)
- **Category:** Security
- **Severity:** High
- **Requirement source:** Appsec review (RNG for security-critical material)
- **Current state (evidence):** `src/api_keys.zig:111-112`, `src/mfa.zig:135` -- secrets generated via `io.random()`.
- **Why this is a gap:** `io.random()` may seed weakly / fail open for credential material.
- **Impact/Risk:** Predictable API-key secrets or TOTP seeds undermine the auth boundary.
- **Recommended fix:** Use `io.randomSecure()` (fail-closed CSPRNG) and propagate errors.
- **Acceptance criteria:** All secret generation uses a fail-closed CSPRNG; error propagation tested.

### GAP-0008: Recovery codes ~40-bit entropy + no verifyScratchCode API

- **Issue:** [#57](https://gitlab.com/devnw/zig/auth/-/issues/57)
- **Category:** Security
- **Severity:** High
- **Requirement source:** Appsec review; MFA recovery design
- **Current state (evidence):** `src/mfa.zig:173-184` -- ~40-bit recovery codes; no verify/consume entry point.
- **Why this is a gap:** Low entropy is brute-forceable; no API means callers cannot enforce single-use.
- **Impact/Risk:** Recovery-code guessing bypasses MFA.
- **Recommended fix:** Raise entropy to >= 80 bits; add `verifyScratchCode` with single-use semantics.
- **Acceptance criteria:** Codes >= 80 bits; verify API with single-use enforcement + tests.

### GAP-0009: Stale test-count and version claims in docs

- **Issue:** [#58](https://gitlab.com/devnw/zig/auth/-/issues/58)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** README accuracy
- **Current state (evidence):** README claims 59 tests, v0.1.0 install URL, zero-deps wording; actual 64 pass + 2 skip.
- **Why this is a gap:** Documentation diverges from reality.
- **Impact/Risk:** Misleading onboarding/marketing; contributor confusion.
- **Recommended fix:** Update counts, version/install URL, reconcile zero-deps wording with `build.zig.zon`.
- **Acceptance criteria:** README counts match `zig build test`; version/install URL matches released tag.

### GAP-0010: observability_disabled_test fails under -Dwith_otel=true

- **Issue:** [#59](https://gitlab.com/devnw/zig/auth/-/issues/59)
- **Category:** Test
- **Severity:** High
- **Requirement source:** Observability build option contract
- **Current state (evidence):** `observability_disabled_test.zig:28` asserts `enabled` tracks the flag; `src/observability.zig:44` hardcodes `false`.
- **Why this is a gap:** The otel build option is silently inert; a green test masks it.
- **Impact/Risk:** Telemetry cannot be enabled; latent failure surface.
- **Recommended fix:** Wire `enabled` to `-Dwith_otel`; test asserts both states.
- **Acceptance criteria:** `enabled` reflects the build option; test passes for true and false.

### GAP-0011: root.zig version vs zon version mismatch; no sync check

- **Issue:** [#60](https://gitlab.com/devnw/zig/auth/-/issues/60)
- **Category:** Quality
- **Severity:** Medium
- **Requirement source:** Release hygiene
- **Current state (evidence):** `src/root.zig` version `"0.1.0"` vs `build.zig.zon` `"0.1.5"`; no guard.
- **Why this is a gap:** Runtime-reported version is wrong; drift unguarded.
- **Impact/Risk:** Misreported version; future divergence.
- **Recommended fix:** Single-source the version; add comptime/CI sync check.
- **Acceptance criteria:** Versions equal; mismatch fails the build/CI.

### GAP-0012: README dead link to otel/docs/integration/RECIPE.md

- **Issue:** [#61](https://gitlab.com/devnw/zig/auth/-/issues/61)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** Docs navigation
- **Current state (evidence):** `README.md:147` -- link target does not exist.
- **Why this is a gap:** Broken documentation navigation.
- **Impact/Risk:** 404 on a referenced doc.
- **Recommended fix:** Repoint to a real document or remove.
- **Acceptance criteria:** All README links resolve.

### GAP-0013: minimum_zig_version understates real 0.16 floor

- **Issue:** [#62](https://gitlab.com/devnw/zig/auth/-/issues/62)
- **Category:** Supply-chain
- **Severity:** Low
- **Requirement source:** Toolchain contract
- **Current state (evidence):** `build.zig.zon:5` = `0.15.1`; `README.md:4,62` repeat it; code uses 0.16-only APIs.
- **Why this is a gap:** Declared floor is a false contract.
- **Impact/Risk:** Users on 0.15.1 hit compile failures.
- **Recommended fix:** Bump `minimum_zig_version` to the true 0.16 floor; update README.
- **Acceptance criteria:** Declared floor matches lowest compiling toolchain; README agrees.

### GAP-0014: CHANGELOG missing 0.1.1-0.1.5 entries

- **Issue:** [#63](https://gitlab.com/devnw/zig/auth/-/issues/63)
- **Category:** Docs
- **Severity:** Low
- **Requirement source:** Release documentation
- **Current state (evidence):** CHANGELOG has no 0.1.1-0.1.5 sections despite tagged releases.
- **Why this is a gap:** Five releases undocumented.
- **Impact/Risk:** Consumers cannot see what changed.
- **Recommended fix:** Backfill entries; adopt a release process that updates CHANGELOG.
- **Acceptance criteria:** Every released tag has a CHANGELOG entry.

### GAP-0015: API key secret hashed with plain SHA-256, no pepper/KDF

- **Issue:** [#40](https://gitlab.com/devnw/zig/auth/-/issues/40)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** Appsec review (SEC-008)
- **Current state (evidence):** API-key secret hashed with plain SHA-256; no server-side pepper or KDF.
- **Why this is a gap:** Fast, unsalted hashing of secret material weakens offline-cracking resistance.
- **Impact/Risk:** Leaked store enables faster brute force.
- **Recommended fix:** Add a server-side pepper / use a KDF appropriate for high-entropy secrets.
- **Acceptance criteria:** Stored verifier uses pepper/KDF; documented and tested.

### GAP-0016: Deterministic TOTP secret misuse switch needs compile-time gate

- **Issue:** [#23](https://gitlab.com/devnw/zig/auth/-/issues/23)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** QGA-002 (re-scoped)
- **Current state (evidence):** `src/mfa.zig:38` -- default `deterministic = false` (good), but the deterministic-derivation switch is still reachable at runtime.
- **Why this is a gap:** A runtime misuse switch can ship to production and produce predictable TOTP secrets.
- **Impact/Risk:** Predictable MFA seeds if enabled in production.
- **Recommended fix:** Gate the deterministic path behind a compile-time flag so it cannot ship in release builds.
- **Acceptance criteria:** Deterministic derivation is unavailable unless a compile-time test/debug flag is set.

### GAP-0017: No TOTP replay protection

- **Issue:** [#43](https://gitlab.com/devnw/zig/auth/-/issues/43)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** Appsec review (SEC-011; severity raised to Medium)
- **Current state (evidence):** No mechanism prevents reusing a valid TOTP code within its window.
- **Why this is a gap:** A captured code can be replayed before expiry.
- **Impact/Risk:** Code interception enables a single replay.
- **Recommended fix:** Track and reject already-consumed (user, time-step) codes.
- **Acceptance criteria:** A consumed code is rejected on reuse within its window; tested.

### GAP-0018: otel pin ref=v0.1.10 vs hash otel-0.1.9 mismatch

- **Issue:** [#64](https://gitlab.com/devnw/zig/auth/-/issues/64)
- **Category:** Supply-chain
- **Severity:** Medium
- **Requirement source:** Dependency integrity
- **Current state (evidence):** `build.zig.zon` -- `ref=v0.1.10` but hash `otel-0.1.9-B0v3ltxe...`; `zig fetch` now emits `B0v3lphe...`, so cold CI fetch fails integrity.
- **Why this is a gap:** ref and hash disagree; non-deterministic fetch.
- **Impact/Risk:** Cold (uncached) CI fails dependency fetch.
- **Recommended fix:** Re-run `zig fetch --save` for the intended ref so ref and hash agree.
- **Acceptance criteria:** ref and hash reference the same release; cold build fetches successfully.

### GAP-0019: validateKey returns borrowed name/scopes slices -> UAF under concurrent revoke

- **Issue:** [#65](https://gitlab.com/devnw/zig/auth/-/issues/65)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** Concurrency safety (residual of SEC-004 #29)
- **Current state (evidence):** `src/api_keys.zig:212` -- returned struct aliases manager-owned name/scopes; concurrent revoke/cleanup can free them.
- **Why this is a gap:** Borrowed slices outlive their guaranteed lifetime under concurrency.
- **Impact/Risk:** Use-after-free / data race.
- **Recommended fix:** Return owned copies or document and enforce a caller lock contract; prefer owned copies.
- **Acceptance criteria:** validateKey returns owned data; validate-during-revoke test passes under detectors.

### GAP-0020: observability seam permanently disabled; enabled path untested

- **Issue:** [#66](https://gitlab.com/devnw/zig/auth/-/issues/66)
- **Category:** Observability
- **Severity:** Low
- **Requirement source:** Observability contract
- **Current state (evidence):** `src/observability.zig:44` -- `enabled` hardcoded false; telemetry calls no-op; enabled path uncovered.
- **Why this is a gap:** Telemetry cannot be turned on; enabled path is latent.
- **Impact/Risk:** Latent failure surface when telemetry is later wired.
- **Recommended fix:** Wire to the build option (see GAP-0010) and cover the enabled path.
- **Acceptance criteria:** Enabled path reachable and tested.

### GAP-0021: base32Encode produces trailing garbage for non-mod-5 input

- **Issue:** [#44](https://gitlab.com/devnw/zig/auth/-/issues/44)
- **Category:** Security
- **Severity:** Low
- **Requirement source:** Appsec review (SEC-012)
- **Current state (evidence):** base32 encode/decode asymmetry on non-mod-5 lengths produces trailing garbage.
- **Why this is a gap:** Output diverges from RFC 4648 for certain lengths.
- **Impact/Risk:** Interchange/encoding errors for affected inputs.
- **Recommended fix:** Correct padding/truncation; cover with the GAP-0006 vector set.
- **Acceptance criteria:** Encode output is RFC-correct for all input lengths.

### GAP-0022: listUserKeys leaks copy.scopes on append OOM

- **Issue:** [#67](https://gitlab.com/devnw/zig/auth/-/issues/67)
- **Category:** Bug
- **Severity:** Medium
- **Requirement source:** Leak-free contract
- **Current state (evidence):** `src/api_keys.zig:314-315` -- cloned `copy.scopes` leaked if the result append OOMs (no errdefer).
- **Why this is a gap:** Allocation-failure path leaks.
- **Impact/Risk:** Memory leak under pressure; fails leak-detecting tests.
- **Recommended fix:** Add errdefer to free the clone before the fallible append.
- **Acceptance criteria:** errdefer present; failing-allocator test shows zero leaks.

### GAP-0023: createKey holds mutex across RNG+SHA256+format+allocs

- **Issue:** [#68](https://gitlab.com/devnw/zig/auth/-/issues/68)
- **Category:** Perf
- **Severity:** Medium
- **Requirement source:** Concurrency performance
- **Current state (evidence):** `src/api_keys.zig:105-151` -- lock spans RNG, hashing, formatting, allocations.
- **Why this is a gap:** Critical section is far wider than the shared-state mutation.
- **Impact/Risk:** Lock contention under concurrent createKey load.
- **Recommended fix:** Move RNG/hash/format/alloc outside the lock; hold the mutex only around the map mutation.
- **Acceptance criteria:** Critical section covers only the map mutation; tests pass.

### GAP-0024: validateKey double Timestamp.now under lock

- **Issue:** [#69](https://gitlab.com/devnw/zig/auth/-/issues/69)
- **Category:** Perf
- **Severity:** Low
- **Requirement source:** Critical-section hygiene
- **Current state (evidence):** `src/api_keys.zig:192` and `:202` -- two `now()` reads under the lock.
- **Why this is a gap:** Redundant work and a small inconsistency window inside the lock.
- **Impact/Risk:** Minor contention/inconsistency.
- **Recommended fix:** Read the timestamp once and reuse.
- **Acceptance criteria:** Single timestamp read reused.

### GAP-0025: Performance backlog (umbrella)

- **Issue:** [#70](https://gitlab.com/devnw/zig/auth/-/issues/70) (groups [#35](https://gitlab.com/devnw/zig/auth/-/issues/35), [#36](https://gitlab.com/devnw/zig/auth/-/issues/36))
- **Category:** Perf
- **Severity:** Low
- **Requirement source:** Performance review backlog
- **Current state (evidence):** O(n) user scans; no map pre-alloc; base32 heap alloc on hot path (`base32DecodeInto` private); two-pass cleanup; unbounded map; CI no cache (#35) / no artifact reuse (#36); Python BFS `pop(0)` in `scripts/detect_diamond_deps.py`.
- **Why this is a gap:** Aggregate latency/throughput drag and CI cost.
- **Impact/Risk:** Cumulative inefficiency; each item individually low.
- **Recommended fix:** Address opportunistically: per-user index, map pre-alloc, expose `base32DecodeInto`, single-pass cleanup, bound the map, CI caching/artifact reuse, `collections.deque`.
- **Acceptance criteria:** Each sub-item has measured before/after or an explicit deferral rationale.

### GAP-0026: CODEOWNERS has placeholder @your-username

- **Issue:** [#28](https://gitlab.com/devnw/zig/auth/-/issues/28)
- **Category:** Quality
- **Severity:** Medium
- **Requirement source:** Repo hygiene (QGA-004)
- **Current state (evidence):** CODEOWNERS still contains the placeholder `@your-username` (confirmed present).
- **Why this is a gap:** Ownership routing points at a non-existent user.
- **Impact/Risk:** Review requests/notifications misrouted.
- **Recommended fix:** Replace with the real owner handle(s).
- **Acceptance criteria:** CODEOWNERS references valid GitLab users/groups.

### GAP-0027: markdownlint MD040 fences missing language hint

- **Issue:** [#71](https://gitlab.com/devnw/zig/auth/-/issues/71)
- **Category:** Quality
- **Severity:** Low
- **Requirement source:** Docs lint
- **Current state (evidence):** `.gitlab/issue_templates/Bug Report.md:44`, `CONTRIBUTING.md:48` -- fenced blocks without a language.
- **Why this is a gap:** markdownlint MD040 violations.
- **Impact/Risk:** Lint failures / inconsistent highlighting.
- **Recommended fix:** Add a language to each fence; enable MD040 in CI.
- **Acceptance criteria:** markdownlint passes with MD040 enabled.

### GAP-0028: .cz.yaml pretty-format + ruff format detect_diamond_deps.py

- **Issue:** [#72](https://gitlab.com/devnw/zig/auth/-/issues/72)
- **Category:** Quality
- **Severity:** Low
- **Requirement source:** Formatting hygiene
- **Current state (evidence):** `.cz.yaml` fails pretty-format-yaml; `scripts/detect_diamond_deps.py` fails ruff format.
- **Why this is a gap:** Inconsistent formatting; pre-commit/CI noise.
- **Recommended fix:** Run the formatters; add both to pre-commit.
- **Acceptance criteria:** Formatters report no changes.

### GAP-0029: Missing doc comments on pub fns; validateKey 52 lines

- **Issue:** [#73](https://gitlab.com/devnw/zig/auth/-/issues/73)
- **Category:** Quality
- **Severity:** Low
- **Requirement source:** Maintainability
- **Current state (evidence):** `src/api_keys.zig` -- several pub fns lack doc comments; `validateKey` ~52 lines.
- **Why this is a gap:** Reduced readability/maintainability.
- **Recommended fix:** Add doc comments; decompose `validateKey` into focused helpers.
- **Acceptance criteria:** All pub fns documented; `validateKey` decomposed.

### GAP-0030: MfaConfig digits=0 -> every TOTP code is 0 (silent MFA bypass)

- **Issue:** [#74](https://gitlab.com/devnw/zig/auth/-/issues/74)
- **Category:** Security
- **Severity:** High
- **Requirement source:** Appsec review
- **Current state (evidence):** `src/mfa.zig:216-219` -- `digits = 0` collapses every code to `0`; no validation rejects it.
- **Why this is a gap:** A misconfiguration silently disables MFA while appearing functional.
- **Impact/Risk:** Critical auth bypass.
- **Recommended fix:** Validate `digits` (e.g. 6-8) at config construction; reject 0.
- **Acceptance criteria:** `digits=0` rejected; test asserts non-trivial codes.

### GAP-0031: MfaConfig unvalidated: lockout, div-by-zero, overflow panics

- **Issue:** [#75](https://gitlab.com/devnw/zig/auth/-/issues/75)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** Appsec review
- **Current state (evidence):** `src/mfa.zig:202` (window<0 silent lockout), `:216-218` (step_seconds=0 div-by-zero; digits>=10 u32 overflow), `:247-254` (window extremes overflow).
- **Why this is a gap:** Unchecked config causes panics or silent lockout.
- **Impact/Risk:** DoS (panics) and silent lockout.
- **Recommended fix:** Add `MfaConfig.validate()` rejecting out-of-range values; call at enroll/verify.
- **Acceptance criteria:** Invalid configs error instead of panicking/locking out; boundary tests added.

### GAP-0032: createKey keys.put clobbers on token-ID collision

- **Issue:** [#76](https://gitlab.com/devnw/zig/auth/-/issues/76)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** Appsec review
- **Current state (evidence):** `src/api_keys.zig:147` -- `keys.put` overwrites on collision without freeing old name/scopes.
- **Why this is a gap:** Silent overwrite + leak of prior allocations on ID collision.
- **Impact/Risk:** Auth confusion + memory leak.
- **Recommended fix:** Use `getOrPut`/`putNoClobber`; error or regenerate on collision.
- **Acceptance criteria:** Collisions detected without overwrite/leak; test simulates collision.

### GAP-0033: computeRecordHmac duplicate keys -> order-dependent HMAC

- **Issue:** [#77](https://gitlab.com/devnw/zig/auth/-/issues/77)
- **Category:** Security
- **Severity:** Low
- **Requirement source:** Determinism contract
- **Current state (evidence):** `src/hmac.zig:79-84` -- duplicate keys leave relative order input-dependent, varying the HMAC.
- **Why this is a gap:** Determinism contract breach.
- **Impact/Risk:** Identical logical records can yield different HMACs, breaking chain verification.
- **Recommended fix:** Enforce a total order (reject duplicates or stable secondary sort); document.
- **Acceptance criteria:** Duplicate-key inputs deterministic (or rejected); test added.

### GAP-0034: key_prefix separator documented but not enforced

- **Issue:** [#78](https://gitlab.com/devnw/zig/auth/-/issues/78)
- **Category:** Quality
- **Severity:** Low
- **Requirement source:** API contract
- **Current state (evidence):** `src/api_keys.zig:28-30` (doc) and `:404` (parse) -- parsing assumes a single `.` separator; a prefix containing `.` is never rejected.
- **Why this is a gap:** Format/parse disagree for such prefixes; every key fails validation.
- **Impact/Risk:** Silent total auth breakage on misconfiguration.
- **Recommended fix:** Validate `key_prefix` at config construction (reject the separator and invalid prefixes).
- **Acceptance criteria:** Invalid prefixes rejected; test asserts rejection.

### GAP-0035: installGlobals publishes unsynchronized global pointers

- **Issue:** [#79](https://gitlab.com/devnw/zig/auth/-/issues/79)
- **Category:** Security
- **Severity:** Medium
- **Requirement source:** Concurrency safety
- **Current state (evidence):** `src/observability_init.zig:87-96` -- global provider pointers written without synchronization.
- **Why this is a gap:** Concurrent readers can observe torn/freed pointers.
- **Impact/Risk:** Data race / UAF once telemetry is enabled.
- **Recommended fix:** Publish via atomics (acquire/release) or guard init/teardown with a mutex; document lifecycle.
- **Acceptance criteria:** Globals published/consumed with proper synchronization; lifecycle tested.

### GAP-0036: Test coverage gaps (concurrency, MFA-config, adversarial, boundaries)

- **Issue:** [#80](https://gitlab.com/devnw/zig/auth/-/issues/80)
- **Category:** Test
- **Severity:** Medium
- **Requirement source:** Coverage completeness
- **Current state (evidence):** No concurrency tests; no MFA-config edge tests; no adversarial parseApiKey integration; `src/mfa.zig:377-389` conditional no-op test; untested 128-prop boundary; untested empty base32.
- **Why this is a gap:** Whole failure classes unverified.
- **Impact/Risk:** Races/misconfig/malformed-input/boundary regressions slip through.
- **Recommended fix:** Add the missing tests and a real assertion in the mfa.zig:377-389 test.
- **Acceptance criteria:** New tests cover the named areas; the no-op test asserts meaningfully.

### GAP-0037: Inconsistent error-set declarations

- **Issue:** [#81](https://gitlab.com/devnw/zig/auth/-/issues/81)
- **Category:** Quality
- **Severity:** Medium
- **Requirement source:** API contract stability
- **Current state (evidence):** `src/hmac.zig` explicit error sets vs inferred sets in `src/api_keys.zig`/`src/mfa.zig`.
- **Why this is a gap:** Inconsistent public contracts; inferred sets hide breaking changes.
- **Recommended fix:** Adopt explicit error sets on public fns project-wide.
- **Acceptance criteria:** Public fns declare explicit error sets consistently.

### GAP-0038: listUserKeys/freeKeyList caller-vs-manager allocator cross-free hazard

- **Issue:** [#82](https://gitlab.com/devnw/zig/auth/-/issues/82)
- **Category:** Quality
- **Severity:** Medium
- **Requirement source:** API contract
- **Current state (evidence):** `src/api_keys.zig` -- list allocates the returned slice; `freeKeyList` must use the same allocator, but the contract is undocumented.
- **Why this is a gap:** Invites cross-allocator free.
- **Impact/Risk:** Corruption / cross-allocator free.
- **Recommended fix:** Document (and/or capture) the allocator so the pairing cannot be misused.
- **Acceptance criteria:** Allocator ownership documented and enforced.

### GAP-0039: Repeated io() incantation; time not injectable

- **Issue:** [#83](https://gitlab.com/devnw/zig/auth/-/issues/83)
- **Category:** Quality
- **Severity:** Low
- **Requirement source:** Testability
- **Current state (evidence):** `src/api_keys.zig`/`src/mfa.zig` -- `std.Io.Threaded.global_single_threaded.io()` repeated ~20x; no time injection seam (blocks expiry-boundary tests).
- **Why this is a gap:** Boilerplate plus untestable time-dependent logic.
- **Recommended fix:** Add an io/clock accessor and inject time (Clock interface / now() fn).
- **Acceptance criteria:** Time source injectable; expiry-boundary tests pass deterministically.

### GAP-0040: ApiKeyManager ownership/threading contract undocumented

- **Issue:** [#84](https://gitlab.com/devnw/zig/auth/-/issues/84)
- **Category:** Docs
- **Severity:** Medium
- **Requirement source:** Concurrency documentation (QR-020)
- **Current state (evidence):** Manager uses `global_single_threaded` io yet guards state with a mutex; the threading model is unwritten and seemingly contradictory.
- **Why this is a gap:** Callers cannot tell what is safe concurrently.
- **Impact/Risk:** Misuse leads to GAP-0019/0023/0035 races.
- **Recommended fix:** Document the threading contract; reconcile single-threaded io with the mutex.
- **Acceptance criteria:** Threading/ownership contract documented; io and locking consistent with it.

### GAP-0041: Dead subject-id bufPrint when telemetry disabled

- **Issue:** [#85](https://gitlab.com/devnw/zig/auth/-/issues/85)
- **Category:** Perf
- **Severity:** Low
- **Requirement source:** Hot-path efficiency
- **Current state (evidence):** `src/api_keys.zig:101-102,168-169,209,246-247,273-274` -- subject-id formatted via bufPrint unconditionally though only telemetry (disabled) consumes it.
- **Why this is a gap:** Wasted formatting on hot paths.
- **Recommended fix:** Comptime/runtime-guard the formatting on the telemetry flag.
- **Acceptance criteria:** Formatting skipped when telemetry disabled.

### GAP-0042: ApiKey two ?i64 fields cost ~16B padding per key

- **Issue:** [#86](https://gitlab.com/devnw/zig/auth/-/issues/86)
- **Category:** Perf
- **Severity:** Low
- **Requirement source:** Memory footprint
- **Current state (evidence):** `src/api_keys.zig:34-44` -- two optional i64 timestamp fields add ~16B per key.
- **Why this is a gap:** Higher per-key footprint at scale.
- **Recommended fix:** Encode "absent" with a sentinel i64 instead of optionals.
- **Acceptance criteria:** ApiKey size reduced; behavior unchanged; tests pass.

### GAP-0043: TOTP digit modulus recomputed per window step

- **Issue:** [#87](https://gitlab.com/devnw/zig/auth/-/issues/87)
- **Category:** Perf
- **Severity:** Low
- **Requirement source:** Hot-path efficiency
- **Current state (evidence):** `src/mfa.zig:216-219` -- `10^digits` modulus recomputed inside the per-window loop.
- **Why this is a gap:** Redundant arithmetic per verification window.
- **Recommended fix:** Hoist the modulus out of the loop.
- **Acceptance criteria:** Modulus computed once per verify call.

### GAP-0044: Missing comptime assert HmacSha1.mac_length==20

- **Issue:** [#88](https://gitlab.com/devnw/zig/auth/-/issues/88)
- **Category:** Quality
- **Severity:** Low
- **Requirement source:** RFC 4226 assumption hardening
- **Current state (evidence):** `src/mfa.zig:206` -- dynamic-truncation assumes a 20-byte HMAC output without a comptime assert.
- **Why this is a gap:** A hash change would silently break truncation offsets.
- **Recommended fix:** Add `comptime assert(HmacSha1.mac_length == 20)`.
- **Acceptance criteria:** A comptime assertion guards the 20-byte assumption.

### GAP-0045: Makefile/CI divergence

- **Issue:** [#89](https://gitlab.com/devnw/zig/auth/-/issues/89)
- **Category:** Quality
- **Severity:** Low
- **Requirement source:** Build/CI parity
- **Current state (evidence):** `make ci` is a subset of `.gitlab-ci.yml`; `fmt` omits `examples/`; no fuzz target; `build` vs `check` semantics differ.
- **Why this is a gap:** Local `make ci` can pass while the pipeline fails (and vice versa).
- **Recommended fix:** Align `make ci` with pipeline stages; include `examples/` in `fmt`; add a fuzz target; reconcile build vs check.
- **Acceptance criteria:** `make ci` runs the same checks as the pipeline; `fmt` covers `examples/`; fuzz target exists.

## Public API (Implemented)

| Module | Exports |
|---|---|
| `auth.hmac` | `deriveHmacKey`, `computeRecordHmac`, `computeChainHash`, `verifyHmac`, `hmacToHex`, `hexToHmac`, `HkdfConfig`, `KeyValue` |
| `auth.api_keys` | `ApiKeyManager`, `parseApiKey`, `parseBearerToken`, `formatApiKey`, `Config`, `ApiKey`, `ParsedApiKey` |
| `auth.mfa` | `enroll`, `generateCode`, `verifyCode`, `base32Encode`, `base32Decode`, `MfaConfig`, `Enrollment` |
