# Performance Gap Analysis

**Repository:** `devnw/zig/auth`
**Last updated:** 2026-06-12 (post-remediation round 1+2)
**Methodology:** Static code analysis of `src/mfa.zig`, `src/api_keys.zig`, `src/hmac.zig`, `src/observability.zig`, `.gitlab-ci.yml`, `scripts/detect_diamond_deps.py`. Phase 4 (perf) of full audit; refreshed after the round-1 remediation (`db4c3b6..a0de467`).
**Scoring:** PerfScore = Impact(1-5) x Likelihood(1-5) x 4 (max 100)

> **Issue ops are owned by a separate agent.** This document references existing
> GitLab issue numbers (#NN) and audit Gap-IDs (GAP-NNNN) but does not create,
> edit, or close issues.
>
> **Measurement blocker (still in force):** No `zig build bench` harness exists
> in this repo. All resolutions below are verified by code inspection, not
> before/after numbers; all accepted-with-rationale dispositions are explicitly
> conditioned on the absence of measurement. Tracked by **#11** (AUTH-TEST-004,
> deferred — see [GAP_ANALYSIS.md](GAP_ANALYSIS.md)). Building the harness
> remains the highest-leverage *enabling* task.
>
> Round-2 verification: the post-remediation tree was re-reviewed in
> [`docs/APPSEC_REVIEW_2026-06-12_2.md`](./APPSEC_REVIEW_2026-06-12_2.md),
> which verified the perf-relevant remediations (stack-buffer decode,
> lock-hoisting, CI cache) correct in situ.

---

## Summary

| PerfSeverity | Open (actionable) | Accepted / gated | Resolved | Description |
|---|---|---|---|---|
| **P0 -- Critical** | 0 | 0 | 3 | SLO breach / outage risk; immediate |
| **P1 -- High** | 0 | 0 | 5 | Material user-facing impact; within sprint |
| **P2 -- Medium** | 0 | 2 | 4 | Moderate impact; next quarter |
| **P3 -- Low** | 0 | 5 | 4 | Minor optimization; backlog |
| **Totals** | **0** | **7** | **16** | |

**No actionable performance findings remain open.** Every previously open
item was either fixed in round 1 (9 items, commit evidence below) or
deliberately dispositioned as accepted-with-rationale / gated (7 items,
rationale below). The accepted items are conditioned on two blockers that
have not changed: no bench harness (#11) and the single-threaded io model.

---

## Accepted-with-Rationale / Gated (the only remaining items)

These were deliberately NOT implemented. Shared rationale (from the
GAP-0025 umbrella, [#70](https://gitlab.com/devnw/zig/auth/-/issues/70),
closed): no bench harness exists to prove a win (#11), and all affected
operations are admin-path (not hot-path) frequency. Reopen individually
only if profiling ever shows them to matter.

| ID | Sev | Item | Rationale / gate |
|---|---|---|---|
| PERF-P2-001 | P2 | O(n) full-map user scans (`revokeUserKeys`/`listUserKeys`) | Admin-path frequency; a per-user secondary index adds invariant-maintenance complexity with unproven benefit. Accepted. |
| PERF-P2-004 | P2 | No HashMap capacity pre-allocation | No measured allocation pressure; capacity guessing without data. Accepted. |
| PERF-P2-003 | P3 (demoted) | Two-pass `cleanupExpired` (collect-then-remove) | Janitor/maintenance path; two-pass is a defensible safe-iteration design; single-pass rewrite risks correctness for unmeasured gain. Accepted. |
| PR-005 / GAP-0042 | P3 | `ApiKey` two `?i64` fields → ~16B padding per key | **Won't Do** ([#86](https://gitlab.com/devnw/zig/auth/-/issues/86) closed 2026-06-12): optionals are the clearer API; saving unproven without a bench harness. |
| PR-008 / PR-009 | P3 (gated) | `RwLock` + atomic `last_used_at` for shared-mode `validateKey` | Gated on threaded io: every lock targets `std.Io.Threaded.global_single_threaded.io()` today, so contention wins are latent. Revisit when a multi-threaded executor is adopted. |
| PR-003 | P3 | `feedKv` issues 4 separate `hmac.update()` calls per property | SHA-256 internal block buffering likely absorbs the small updates; act only if a micro-bench (blocked on #11) shows it matters. Accepted. |
| **R2-1** | P3 (latent) | `validateKey` performs deep-copy allocations (name/scopes dupes) **under the lock** | **Conscious security tradeoff**, recorded round 2: copying under the lock is what guarantees the returned `ApiKey` can never alias freed memory under concurrent revoke/cleanup (the GAP-0019 fix, 5a36ff0). Moving the copies outside the lock would reintroduce the UAF window the fix exists to close. Lock-hold cost is latent under single-threaded io; recorded for the future threaded-io work (alongside PR-008/009). Subsumes the former PR-006 / GAP-0047 (`listUserKeys` copy-under-lock) for the same reason. |

> **Contention caveat (PR-008/009, R2-1):** every mutex site locks against
> `std.Io.Threaded.global_single_threaded.io()`. Lock-hold-time observations
> are **latent** — they pay off only once a multi-threaded executor is
> adopted, and any change must preserve the ownership guarantees above.

### Measurement note (blocked on #11)

Before/after numbers for any of the above require the `zig build bench`
harness tracked by [#11](https://gitlab.com/devnw/zig/auth/-/issues/11)
(AUTH-TEST-004, deferred). Until it lands, every disposition in this
table is evidence-by-inspection only, and none of the accepted items
should be implemented speculatively.

---

## Resolved Findings

### Round 1 remediation (2026-06-12)

The nine previously open findings below were fixed in round 1
(`db4c3b6..a0de467`); cross-domain log in
[GAP_ANALYSIS_RESOLVED.md](GAP_ANALYSIS_RESOLVED.md). Spot-checked
against the current tree (notes inline).

| ID | Sev | Finding | Resolution evidence (commit) |
|---|---|---|---|
| NEW-003 / GAP-0022 | P1 | `listUserKeys` leaked `copy.scopes` on append-OOM | 5a36ff0 -- errdefer covers the append-OOM window ([#67](https://gitlab.com/devnw/zig/auth/-/issues/67) closed) |
| PR-015 / GAP-0041 | P2 | Dead `subject_id` `bufPrint` on every hot auth path with otel compiled out | 5a36ff0 -- comptime-guarded subject-id bufPrints; zero cost when disabled ([#85](https://gitlab.com/devnw/zig/auth/-/issues/85) closed) |
| NEW-001 / GAP-0023 | P2 | `createKey` held mutex across CSPRNG + SHA256 + format + dupes | 5a36ff0 -- all work hoisted out of the lock; lock only around map mutation ([#68](https://gitlab.com/devnw/zig/auth/-/issues/68) closed) |
| PERF-P2-002 | P2 | Heap-alloc base32 decode on every TOTP generate/verify | 4a33957 -- stack-buffer decode on TOTP hot paths, zero heap per verify (verified: `base32DecodeInto` + 64-byte stack buffer at `src/mfa.zig`; the `DecodedSecret` extraction refactor of this code landed as round-2 cleanup 43b2ac3) |
| NEW-002 / GAP-0024 | P2 | `validateKey` called `Timestamp.now` twice under the lock | 5a36ff0 -- single `now()` read under lock ([#69](https://gitlab.com/devnw/zig/auth/-/issues/69) closed) |
| PERF-P3-001 | P3 | Unbounded key map growth (perf + DoS) | 5a36ff0 + bb3ab93 -- configurable `max_keys` cap; `cleanupExpired` reclaims revoked tombstones so the quota recovers |
| PERF-P3-002 | P3 | CI: no cache; 11 jobs each download Zig and recompile | 74232f4 -- toolchain + build cache keyed on `ZIG_VERSION` (verified: `cache:` block at `.gitlab-ci.yml:29-33` covering `zig-$ZIG_VERSION/` and `.zig-cache/`; covers #35/#36, both closed) |
| PR-001 / GAP-0043 | P3 | TOTP digit modulus recomputed per window step | 9023a54 -- modulus hoisted out of the window loop ([#87](https://gitlab.com/devnw/zig/auth/-/issues/87) closed) |
| PR-012 | P3 | `detect_diamond_deps.py` BFS `list.pop(0)` → O(n²) | 74232f4 -- `collections.deque` + `popleft()`, O(1) dequeue |

### Prior remediation pass (verified 2026-06-12, pre-round-1)

| ID | Issue | Severity | Finding | Resolution Evidence (current code) |
|---|---|---|---|---|
| PERF-P0-001 | #20 | P0 | `verifyCode` redundantly decoded the base32 secret on every window iteration (3x heap alloc/free per verify) | Secret decoded **once** before the loop; window loop uses the no-alloc `generateCodeFromRaw`. Superseded further by 4a33957 (fully stack-resident decode). |
| PERF-P0-002 | #21 | P0 | `computeRecordHmac` `@panic`'d when `props.len > 128` (process crash / DoS) | Returns `error{TooManyProperties}`; no `@panic` remains on the path. Boundary covered both sides (19f4a95). |
| PERF-P0-003 | #24 | P0 | SHA256 of the provided secret was computed *inside* the validation mutex | SHA256 runs **before** the lock; lock hygiene further tightened in 5a36ff0. |
| PERF-P1-001 | #27 | P1 | Hand-rolled 30-line HMAC-SHA1 duplicating stdlib | Replaced with stdlib `std.crypto.auth.hmac.HmacSha1`. |
| PERF-P1-002 | #31 | P1 | `cleanupExpired` swallowed OOM (`append catch continue`) | `cleanupExpired` is fallible; OOM propagates. Tombstone reclamation added in bb3ab93. |
| PERF-P1-003 | #33 | P1 | HKDF PRK re-`extract`'d inside the scratch-code loop | `extract` hoisted above the loop; loop body only `expand`s. |
| PERF-P1-004 | #37 | P1 | Secrets freed without zeroing | `crypto.secureZero` applied broadly across `mfa.zig`/`api_keys.zig`; round-2 review confirmed zeroization on every traced path, including the new stack-decode defer ordering (zeroize before free). |

---

## Verified Clean (do **not** "optimize")

These patterns were inspected and are intentional or already optimal.
Flagging them here to prevent a future pass from "fixing" them into
regressions.

| Item | Location | Why it is correct as-is |
|---|---|---|
| TOTP window has no early-exit on match | `src/mfa.zig` (`verifyCode`/`verifyCodeStep`) | **Deliberate timing-side-channel defense.** The loop always runs all `2*window+1` steps; short-circuiting would leak which window matched. Do not add a `break`. (Round-2 review re-verified, incl. `verifyCodeStep` highest-step semantics.) |
| `formatApiKey` single-allocation builder | `src/api_keys.zig` | Computes `total_len` up front and encodes prefix/id/secret into one buffer — zero intermediate allocations. |
| `BASE32_ALPHABET` is comptime | `src/mfa.zig` | Compile-time constant string; no runtime table build. |
| HKDF scratch `prk` hoisted | `src/mfa.zig` | Fixed form of PERF-P1-003; reused across scratch-code generation. |
| `lockUncancelable` usage | all mutex sites in `api_keys.zig` | Correct uncancelable lock on every site; all paired with `defer ...unlock`. The mutex/futex path delegates to real OS futexes in non-single-threaded builds (documented at `src/api_keys.zig:23`). |
| Observability seam call sites | `src/observability.zig` seam | The seam compiles to a comptime no-op when `-Dwith_otel=false` (default), **and** since 5a36ff0 the pre-seam subject-id `bufPrint` is comptime-guarded too — the entire telemetry path is now zero-cost when disabled. |
| Deep-copy under lock in `validateKey`/`listUserKeys` | `src/api_keys.zig` | Security-load-bearing (see R2-1 above): copying under the lock is what makes returned keys immune to concurrent revoke/cleanup. Do not hoist the copies out of the lock. |

---

## Findings by Area

### area::app

- **MFA module (`src/mfa.zig`):** all open items resolved — redundant
  decode, hand-rolled HMAC-SHA1, HKDF-in-loop (prior pass); heap-alloc
  decode (4a33957) and modulus recompute (9023a54) in round 1. Remaining:
  PR-003 `feedKv` granularity in hmac, accepted pending micro-bench.
- **API Keys module (`src/api_keys.zig`):** all open items resolved in
  round 1 — dead telemetry `bufPrint`, over-broad `createKey` lock, double
  `Timestamp.now`, scope leak, unbounded growth (5a36ff0/bb3ab93).
  Remaining: accepted O(n) scans (PERF-P2-001), pre-alloc (PERF-P2-004),
  two-pass cleanup (PERF-P2-003), `?i64` padding (Won't Do), and the
  gated/latent lock-granularity family (PR-008/009, R2-1).
- **HMAC module (`src/hmac.zig`):** clean; PR-003 accepted pending
  micro-bench.

### area::ci

Resolved: toolchain + build cache landed (74232f4); `.install-zig`
downloads are now cache hits and `.zig-cache` is reused across the test
jobs. No open CI perf findings.

### area::infra

Resolved: diamond-dep detector BFS is O(n) via `deque.popleft()`
(74232f4). No open tooling perf findings.

### area::db

No database-layer findings. This library has no persistence layer
(in-memory `AutoHashMap` only).

---

## Roadmap

All quick wins and medium items from the previous revision are done
(see Resolved tables above). What remains:

| Item | Status / gate |
|---|---|
| (prereq) #11 `zig build bench` harness | **The only enabling task left.** Unblocks measurement for every accepted item above. Deferred (AUTH-TEST-004). |
| PR-008/009 + R2-1 lock-granularity work | Gated on adopting a multi-threaded io executor; must preserve the deep-copy-under-lock ownership guarantee. |
| PERF-P2-001 / P2-003 / P2-004 / PR-005 / PR-003 | Accepted / Won't Do — reopen individually only with profiling evidence. |

---

## Issue / Gap-ID Cross-Reference

| Finding | Tracking | Status |
|---|---|---|
| PERF-P0-001 verifyCode redundant decode | #20 | Resolved (prior pass) |
| PERF-P0-002 computeRecordHmac panic | #21 | Resolved (prior pass) |
| PERF-P0-003 SHA256 inside mutex | #24 | Resolved (prior pass) |
| PERF-P1-001 hand-rolled HMAC-SHA1 | #27 | Resolved (prior pass) |
| PERF-P1-002 cleanupExpired silent OOM | #31 | Resolved (prior pass) |
| PERF-P1-003 HKDF PRK in loop | #33 | Resolved (prior pass) |
| PERF-P1-004 no secret zeroing | #37 | Resolved (prior pass) |
| NEW-003 listUserKeys scope leak | GAP-0022 / #67 | Resolved round 1 (5a36ff0) |
| PR-015 dead hot-path bufPrint | GAP-0041 / #85 | Resolved round 1 (5a36ff0) |
| NEW-001 createKey wide lock | GAP-0023 / #68 | Resolved round 1 (5a36ff0) |
| NEW-002 validateKey double now() | GAP-0024 / #69 | Resolved round 1 (5a36ff0) |
| PERF-P2-002 heap-alloc base32 decode | (GAP-0025 umbrella, #70) | Resolved round 1 (4a33957) |
| PERF-P3-001 unbounded key map | (GAP-0025 umbrella, #70) | Resolved round 1 (5a36ff0 + bb3ab93) |
| PERF-P3-002 CI no cache | #35 / #36 | Resolved round 1 (74232f4) |
| PR-001 TOTP modulus recompute | GAP-0043 / #87 | Resolved round 1 (9023a54) |
| PR-012 diamond detector O(n²) BFS | -- | Resolved round 1 (74232f4) |
| PERF-P2-001 O(n) user scans | (GAP-0025 umbrella, #70 closed) | Accepted with rationale |
| PERF-P2-003 two-pass cleanup | (GAP-0025 umbrella, #70 closed) | Accepted with rationale |
| PERF-P2-004 no HashMap pre-alloc | (GAP-0025 umbrella, #70 closed) | Accepted with rationale |
| PR-005 ApiKey ?i64 padding | GAP-0042 / #86 (closed) | Won't Do |
| PR-003 feedKv 4x update | -- | Accepted pending micro-bench (#11) |
| PR-008 / PR-009 RwLock + atomic last_used | -- | Gated on threaded io |
| R2-1 validateKey deep-copy under lock (subsumes PR-006 / GAP-0047) | -- | Recorded: conscious security tradeoff; revisit with threaded io |
| (harness) bench prerequisite | #11 (AUTH-TEST-004) | Deferred — blocks all measurement |

---

## Unknowns and Blockers

1. **No benchmark harness (`zig build bench`) exists.** Unchanged. This
   blocks before/after measurement for every accepted item above. Tracked
   by **#11** (deferred). Building it is the highest-leverage *enabling*
   task left in this domain.
2. **Single-threaded io masks lock-contention effects.** Unchanged.
   PR-008/009 and R2-1 stay latent until a multi-threaded executor is
   adopted; any future lock-granularity change must preserve the
   deep-copy-under-lock ownership guarantee (security tradeoff, R2-1).
3. **Production key-volume profile unknown.** The accepted dispositions
   for PERF-P2-001 (O(n) scans) and PERF-P2-004 (pre-alloc) assume
   admin-path frequency and modest key counts; a realistic load sample
   would confirm or reopen them.
4. **`feedKv` micro-cost unverified (PR-003).** SHA-256's internal block
   buffering may already absorb the four small `update()` calls per
   property; needs a micro-bench before any change. Accepted deliberately.
