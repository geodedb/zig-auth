# Application Security Code Review — `devnw/zig/auth` (ROUND 2, post-remediation)

**Reviewer:** AppSec code review (defensive, evidence-first)
**Date:** 2026-06-12
**Standards:** OWASP Top 10:2025, CIS Controls v8.1.2
**Repo:** `/home/benji/src/gl/gitlab.com/devnw/zig/auth` @ `main` (`a0de467`)
**Toolchain:** Zig 0.16.0 (verified `zig version`)
**Predecessor:** Round 1 report `docs/APPSEC_REVIEW_2026-06-12.md` (@ `3605f87`), 12 findings, all remediated/dispositioned across 28 commits `3605f87..a0de467`.

> **Maintainer disposition note (added on save):** AUTH-SUP-001-R2 below was
> investigated and dispositioned the same day — the fragment-pinned URL was
> verified to reproduce the pinned hash on a cold cache (gitlab issue #64,
> closed with evidence), and the upstream version-label lag is filed as
> devnw/zig/otel work item 169. The two Informational items were fixed in the
> commit that adds this report.

---

## 1. Scope & Assumptions

**In scope (all read in full at current `HEAD`):** `src/api_keys.zig`, `src/mfa.zig`, `src/hmac.zig`, `src/observability.zig`, `src/observability_init.zig`, `src/root.zig`; `tests/integration.zig`, `tests/observability_enabled_test.zig`, `tests/observability_disabled_test.zig`; `examples/basic.zig`; `build.zig`, `build.zig.zon`, `.gitlab-ci.yml`, `Makefile`, `docs/USAGE.md`. Also read for context: `docs/GAP_ANALYSIS.md`, Round-1 report.

**Method.** Fresh adversarial pass over the current tree with priority on code **changed** in the remediation (the new attack surface): (a) verified each Round-1 remediation is actually correct in situ, not merely present; (b) hunted for new defects introduced by the changes — error-path leaks, defer/errdefer ordering, integer overflow in new arithmetic, semantic regressions, dangerous docs, CI weakening; (c) ran targeted dynamic checks where static reasoning was insufficient.

**Dynamic verification performed (this review):**

- **Base32 decoder adversarial fuzz** — 5,000,000 iterations of random valid-charset strings, every length 0–80, under `-OReleaseSafe`: **no overflow panic, no OOB**. Confirmed `u8 << 6` etc. truncate (do not trap) in Zig 0.16, and the `@min(out_len - oi, 5)` clamp prevents output overrun.
- **Base32 encoder OOB check** — every input length 0–256 under `-OReleaseSafe`: no OOB on the `@memcpy`/`@memset` into `out`.
- **`verifyScratchCode` double-spend / cross-slot / resurrection** — duplicate-hash slots each consume exactly once; already-consumed slot cannot be re-matched; no double-spend.
- **`verifyCodeStep` highest-step + `verifyCodeOnce` replay** — traced the window-boundary clock-skew case; replay is correctly rejected.
- **Deterministic-MFA gate** — confirmed `enroll(.{.deterministic=true})` returns `error.DeterministicModeIsTestOnly` outside `zig test` (ran it standalone and got the error).
- **Build + full suite** — `zig build check` OK; `zig build test` 73/75 pass (2 skipped = enabled-otel tests); `zig build test-integration` 16/16; `zig build test -Doptimize=ReleaseSafe` OK.

**Assumptions / boundaries.**

- This is a **library**; exploitability is judged from a consuming production application's perspective.
- The reviewer did **not** fetch the `otel` remote (see maintainer disposition note above — the fetch verification was done separately).
- Concurrency reviewed statically plus the in-repo 4-thread stress test; no TSan run.
- Known/tracked items not re-reported: GAP-0020/#66 (telemetry seam hard-disabled), GAP-0035/#79 (`installGlobals` atomicity), AUTH-TEST-004/#11 (benchmarks deferred), four accepted-with-rationale perf items, and the documented default-no-pepper hashing choice (implementation verified sound).

---

## 2. Executive Summary

- **NEW findings this round, by severity: Critical 0 · High 0 · Medium 0 · Low 1 · Informational 2.** Another full remediation round is **not** warranted.
- **Every Round-1 finding is genuinely remediated — verified at the code level, not just by presence.** Credential generation uses `randomSecure` and fails closed; `MfaConfig.validate` enforces `digits 6..9 / step≠0 / window 0..64`; recovery codes are 160-bit CSPRNG, independent of the TOTP secret, with constant-time single-use `verifyScratchCode`; the deterministic path is compile-gated out of non-test builds; base32 is RFC 4648 with padding symmetry, exact-length decode, and is overflow/OOB-safe on adversarial input (fuzzed); `validateKey` returns owned deep copies with `freeValidatedKey`; `createKey` uses collision-safe `getOrPut` with a correct layered errdefer chain; `cleanupExpired` reclaims revoked tombstones; HMAC has a total (key,value) order; all public fallible functions carry explicit error sets.
- **The single NEW Low (AUTH-SUP-001-R2):** the `otel` pin's `hash` version label (`otel-0.1.9-…`) disagrees with the URL `ref` (`v0.1.10`) — `build.zig.zon:13-14`. *(Dispositioned: upstream label lag, filed as otel work item 169; pin verified correct — see note above.)*
- **Two NEW Informational items:** USAGE.md hashing-default wording; `.paths` packaging completeness. *(Both fixed on save.)*
- **The remediation's new code is clean.** New error paths unwind cleanly; new base32 arithmetic is overflow/OOB-safe; secrets are zeroized on every traced path; CI changes (digest pins, cache) strengthen rather than weaken supply-chain integrity.

**Overall confidence: High** for the source modules (read in full + dynamic verification).

---

## 3. Findings Table

| ID | Severity | Confidence | Title | Location | OWASP | Status |
|----|----------|-----------|-------|----------|-------|--------|
| AUTH-SUP-001-R2 | Low | Medium | `otel` dependency `hash` version label (`0.1.9`) disagrees with URL `ref` (`v0.1.10`) | `build.zig.zon:13-14` | A03 Supply Chain / CWE-1357 | Dispositioned (#64 closed; upstream otel#169) |
| AUTH-DOC-001-R2 | Info | High | USAGE.md implied HMAC at-rest hashing by default; default is bare SHA-256 | `docs/USAGE.md:30` | A09/A04 (doc) / CWE-1059 | Fixed on save |
| AUTH-PKG-001-R2 | Info | High | `build.zig.zon` `.paths` omits `tests`/`examples`/`docs` (packaging completeness) | `build.zig.zon:18-24` | A03 (hygiene) / CWE-1357 | Documented as src-only packaging on save |

No Critical/High/Medium findings in the current code.

---

## 4. Finding Details

### AUTH-SUP-001-R2 — `otel` pin `ref`/`hash` version-label disagreement (Low)

**Evidence (`build.zig.zon:12-16`):** URL pins ref `v0.1.10` at commit `a1afbfe…`, but the `hash` field encodes the label `otel-0.1.9-…`. Zig's `hash` embeds the dependency's *self-declared* version (from otel's own `build.zig.zon` `.version`), independent of the git tag — the most likely explanation is an upstream label/tag discrepancy, in which case Zig fetches and verifies correctly but the human-readable provenance label is misleading (CWE-1357). **Disposition:** verified separately — cold-cache fetch of the fragment-pinned URL reproduces the pinned hash exactly; upstream `.version` lag filed as devnw/zig/otel work item 169; consumers should always pin with commit fragments (this repo does).

### AUTH-DOC-001-R2 — USAGE.md overstated default at-rest hashing (Informational)

`docs/USAGE.md:30` said "Only an HMAC-SHA256 (or peppered variant) hash is retained" — but the default (no pepper) is **bare SHA-256** (`src/api_keys.zig` `hashSecret`). Risk: a reader assumes pepper protection is always present and declines to set `Config.pepper`. **Fixed:** reworded to state bare SHA-256 default / HMAC-with-pepper opt-in, with a defense-in-depth pointer.

### AUTH-PKG-001-R2 — `.paths` omits tests/examples/docs (Informational)

`build.zig.zon` packages only `src` + build files; a package consumer cannot run the library's own test/example suites from the fetched tree. Intentional src-only packaging is common. **Fixed:** documented as repo-only in USAGE.md.

---

## 5. Secure Design Notes (Round-1 remediations verified correct)

- **Fail-closed CSPRNG:** `try ioh().randomSecure(...)` on all credential paths (`api_keys.zig:186-187`, `mfa.zig:258,303`), errors propagated via explicit sets.
- **Recovery codes:** 160-bit independent CSPRNG (`mfa.zig:300-306`); `verifyScratchCode` full-length constant-time scan, single-use, release-mode length guard (`:116-130`); dynamically confirmed no double-spend/resurrection.
- **Deterministic switch:** compile-gated `if (comptime !builtin.is_test) return error.DeterministicModeIsTestOnly;` (`mfa.zig:252`) — physically unreachable in production builds (dynamically confirmed).
- **validateKey ownership:** owned deep copy + `freeValidatedKey` (`api_keys.zig:291-311`); survives concurrent revoke + cleanup (test-proven).
- **TOTP replay:** `verifyCodeStep` returns matched step (highest, no early exit); `verifyCodeOnce` enforces monotonic high-water mark (`mfa.zig:370-437`).
- **Base32 RFC 4648 rewrite:** padding symmetry, exact-length decode, impossible-length rejection; fuzzed 5M iterations — no overflow/OOB.
- **createKey:** collision-safe `getOrPut` (`error.TokenIdCollision`), correct layered errdefers, all work hoisted out of the lock.
- **cleanupExpired:** reclaims expired AND revoked tombstones — `max_keys` quota recovery; deep-copy returns make removal safe.
- **hashSecret pepper path:** `HmacSha256.create(out, secret, pepper)`; cross-pepper rejection test-proven.
- **HMAC total order (key,value):** duplicate keys deterministic; 128-prop cap errors (no panic).
- **Stack-buffer decode:** correct defer ordering (zeroize before heap free) on both fns.
- **Observability seam:** credential-safe by construction, comptime no-op by default; inertness documented (GAP-0020).
- **CI/supply chain:** digest-pinned images, SHA-256-verified Zig download preserved through the new cache, SAST/gitleaks/SBOM components, fuzz job.

---

## 6. Coverage Gaps & Questions

- `otel` remote not fetched by the reviewer (resolved separately — see disposition note).
- `verifyCodeStep` highest-step usability nuance: a one-step-ahead code advances the mark to N+1; user waits ≤1 step (~30 s) to authenticate again. Standard, documented tradeoff — not a bug.
- Shared `.zig-cache/` across CI jobs is a minor integrity surface (content-hash-keyed, toolchain SHA-256-verified before extraction) — standard practice.
- No TSan run; 4-thread stress test passes 200/200.
- No runtime entropy-starvation test (type-system guarantee is strong; an `Io.failing`-backed test would confirm end-to-end).

---

## 7. Prioritized Next Actions

1. ~~AUTH-SUP-001-R2~~ — dispositioned (#64 closed with cold-cache fetch evidence; upstream otel#169 filed).
2. ~~AUTH-DOC-001-R2~~ — fixed (USAGE.md reworded).
3. ~~AUTH-PKG-001-R2~~ — fixed (src-only packaging documented).
4. Optional hardening (not findings): `Io.failing`-backed entropy-starvation test; TSan CI job for the ApiKeyManager concurrency path.

**Bottom line.** No Critical/High/Medium issues in the current tree. Every Round-1 remediation is real and correct — verified by code reading plus targeted dynamic checks (base32 fuzz, scratch-code double-spend, replay-window trace, deterministic-gate execution, full test matrix). The remediation introduced **no** new exploitable defects. **No further remediation round is required.**
