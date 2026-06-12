# Performance Gap Analysis

**Repository:** `devnw/zig/auth`
**Last updated:** 2026-06-12
**Methodology:** Static code analysis of `src/mfa.zig`, `src/api_keys.zig`, `src/hmac.zig`, `src/observability.zig`, `.gitlab-ci.yml`, `scripts/detect_diamond_deps.py`. Phase 4 (perf) of full audit.
**Scoring:** PerfScore = Impact(1-5) x Likelihood(1-5) x 4 (max 100)

> **Issue ops are owned by a separate agent.** This document references existing
> GitLab issue numbers (#NN) and audit Gap-IDs (GAP-NNNN) but does not create,
> edit, or close issues. New findings below carry NEW-/PR- working IDs plus the
> Gap-ID assigned by the gap audit where one exists.
>
> **Measurement blocker:** No `zig build bench` harness exists in this repo.
> Every "validation plan" below that references a benchmark is therefore a
> *plan*, not a result — no before/after numbers can be captured until a harness
> lands. All MFA/API-key findings are scored on code evidence + path frequency,
> not measured deltas. Tracked by **#11** (preserve MFA benchmark references).
> Confidence tags reflect this: `confidence::confirmed` = unambiguous code
> evidence; `confidence::suspected` = needs profiling/load to quantify the win.

---

## Summary

| PerfSeverity | Open | Resolved | Description |
|---|---|---|---|
| **P0 -- Critical** | 0 | 3 | SLO breach / outage risk; immediate |
| **P1 -- High** | 1 | 4 | Material user-facing impact; within sprint |
| **P2 -- Medium** | 6 | 0 | Moderate impact; next quarter |
| **P3 -- Low** | 8 | 0 | Minor optimization; backlog |
| **Open total** | **15** | | |
| **Resolved total** | | **7** | All P0s + all original P1s closed |

### Top 5 Open Risks by Expected Impact

1. **NEW-003 / GAP-0022** -- `listUserKeys` leaks `copy.scopes` on append-OOM (P1 **correctness** bug surfaced during perf review; cross-referenced to quality domain). Allocation leak, not a slowdown, but it lives on the per-user list path.
2. **PR-015 / GAP-0041** -- Dead `subject-id` `bufPrint` runs on every hot-path auth call (`createKey`/`validateKey`/`revokeKey`/`revokeUserKeys`) even when telemetry is compiled out. Hottest path, trivial comptime-guard fix. P2.
3. **NEW-001 / GAP-0023** -- `createKey` holds the manager mutex across 2x CSPRNG draws + SHA256 + timestamp + key formatting + 2 dupes; only `keys.put` needs the lock. Latent contention. P2.
4. **PERF-P2-001** -- O(n) full-map scans in `revokeUserKeys` / `listUserKeys`; cost grows with total key count, not the user's key count. P2.
5. **PERF-P2-004** + **PERF-P2-002** -- No HashMap pre-allocation (resize churn on load) and heap-allocated base32 decode on every TOTP generate/verify when a private no-alloc `base32DecodeInto` already exists. P2.

> **Contention caveat (applies to NEW-001, NEW-002, PR-006, PR-008/009):** every
> mutex site currently locks against `std.Io.Threaded.global_single_threaded.io()`.
> Under the single-threaded IO model in use today, lock-hold-time wins are
> **latent** — they pay off only once a multi-threaded executor is adopted.
> Scored on that basis (lower Likelihood), not dismissed: the fixes are cheap and
> the model is expected to change.

---

## Stack-Ranked Open Findings

| Rank | Severity | PerfScore | Finding | Component | Evidence | Measurement | Issue / Gap-ID | Fix Summary | Owner | SLA | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | P1 | 40 | `listUserKeys` leaks `copy.scopes` if `list.append` OOMs (dupe'd after the `errdefer cloned_count` window opens but counted only after append) | `src/api_keys.zig:314-315` | `copy.scopes = try dupeScopes(...)` then `try list.append(...)`; on append failure the just-dup'd scopes are unreachable by the `cloned_count`-bounded errdefer | `confidence::confirmed` -- code inspection (correctness; cross-ref quality domain) | NEW-003 / GAP-0022 | Free `copy.name`+`copy.scopes` in a local `errdefer` before append, or append-then-populate | <benji@vester.by> | Within sprint | Open |
| 2 | P2 | 36 | Dead `subject_id` `bufPrint` on hot auth paths runs even when otel is compiled out (`-Dwith_otel=false` default) | `src/api_keys.zig:101-102,168-169,209,246-247,273-274` | `std.fmt.bufPrint(&subject_buf, "{d}", .{user_id})` executes unconditionally; the seam that consumes it is a comptime no-op by default | `confidence::confirmed` -- code inspection | PR-015 / GAP-0041 | Guard the `bufPrint` behind the same comptime otel-enabled flag the seam uses; zero cost when disabled | <benji@vester.by> | Next quarter | Open |
| 3 | P2 | 36 | `createKey` holds mutex across 2x `io().random` + SHA256 + `Timestamp.now` + `formatApiKey` + `dupe(name)` + `dupeScopes`; only `keys.put` needs the lock | `src/api_keys.zig:105-151` | `lock` at :105, `put` at :147; all crypto/alloc/format between them is independent of shared state | `confidence::suspected` -- latent under single-threaded io; load test to quantify | NEW-001 / GAP-0023 | Move random/hash/format/dupe before `lock`; hold lock only around `keys.put` | <benji@vester.by> | Next quarter | Open |
| 4 | P2 | 32 | O(n) full-map scan keyed on total key count for per-user ops | `src/api_keys.zig:281-288` (`revokeUserKeys`), `:309-318` (`listUserKeys`) | both iterate the entire `keys` map filtering by `user_id` | `confidence::suspected` -- needs load test (impact scales with total keys) | PERF-P2-001 | Add secondary index `HashMap(u64, ArrayList([16]u8))` user→token-ids | <benji@vester.by> | Next quarter | Open |
| 5 | P2 | 32 | Heap-alloc base32 decode on every TOTP generate/verify although a no-alloc decoder exists privately | `src/mfa.zig:192` (`generateCode`), `:237` (`verifyCode`) | both call `base32Decode` (heap alloc); `base32DecodeInto` (no-alloc, `:98`) is already implemented but private; TOTP secret is fixed 20 bytes | `confidence::confirmed` -- code inspection | PERF-P2-002 | Decode into a `[20]u8` stack buffer via `base32DecodeInto`; drop the allocator from these paths | <benji@vester.by> | Next quarter | Open |
| 6 | P2 | 24 | `validateKey` calls `Timestamp.now` twice under the lock (expiry check + last-used stamp) | `src/api_keys.zig:192,202` | two separate `std.Io.Timestamp.now(...).toSeconds()` calls inside the locked region | `confidence::suspected` -- latent under single-threaded io | NEW-002 / GAP-0024 | Read `now` once before/at lock entry, reuse for both checks | <benji@vester.by> | Next quarter | Open |
| 7 | P2 | 24 | No HashMap capacity pre-allocation | `src/api_keys.zig:66` | `std.AutoHashMap(...).init(allocator)` starts at zero capacity; first inserts trigger repeated resizes | `confidence::suspected` -- needs allocation tracing | PERF-P2-004 | Accept an initial-capacity hint in `init`, or `ensureTotalCapacity` on first batch | <benji@vester.by> | Next quarter | Open |
| 8 | P3 | 24 | Unbounded key map growth (no `max_keys`); also flagged as a DoS vector | `src/api_keys.zig:59,66` | map has no upper bound; an authenticated issuer can grow it without limit | `confidence::suspected` -- needs production sizing | PERF-P3-001 | Add configurable `max_keys`; return error on exceed (closes perf + DoS) | <benji@vester.by> | Backlog | Open |
| 9 | P3 | 16 | CI has no cache; 11 jobs each download Zig (~60MB) and test jobs recompile from scratch (no artifact reuse) | `.gitlab-ci.yml` (`.install-zig` template + 10 local jobs + components) | no `cache:` block anywhere; every job runs `*install-zig` then rebuilds | `confidence::confirmed` -- CI config inspection | PERF-P3-002 (covers #35/#36) | Add `cache:` for `zig-${ZIG_VERSION}/` keyed on `ZIG_VERSION`; reuse `.zig-cache` build artifacts across test jobs via cache or `needs:artifacts` | <benji@vester.by> | Backlog | Open |
| 10 | P3 | 12 | Two-pass cleanup (collect-then-remove) under the mutex | `src/api_keys.zig:336-354` | first pass appends expiring ids to `to_remove`, second pass `fetchRemove`s them; both under lock | `confidence::suspected` -- **demoted P2→P3 per reviewer**: janitor/cleanup path, two-pass is a defensible safe-iteration design | PERF-P2-003 | Leave as-is unless cleanup shows up under load; single-pass `swapRemove` is the option | <benji@vester.by> | Backlog | Open |
| 11 | P3 | 12 | TOTP digit modulus recomputed per window step | `src/mfa.zig:216-219` | `generateCodeFromRaw` rebuilds `mod = 10^digits` via a loop on every call; `verifyCode` calls it `2*window+1` times | `confidence::confirmed` -- code inspection | PR-001 / GAP-0043 | Compute `mod` once in `verifyCode` (or comptime/lookup) and pass to the inner routine | <benji@vester.by> | Backlog | Open |
| 12 | P3 | 12 | `ApiKey` carries two `?i64` (`expires_at`,`last_used_at`) → ~16B optional padding per key; bloats scan-heavy paths | `src/api_keys.zig:40-41` | two `?i64` fields each cost 16B (tag+pad) vs 8B; multiplied across every map entry the scans walk | `confidence::suspected` -- needs `@sizeOf` + scan profiling | PR-005 / GAP-0042 | Sentinel-encode (`0`/`i64.min` = "none") to shrink struct and improve scan cache behavior | <benji@vester.by> | Backlog | Open |
| 13 | P3 | 12 | `listUserKeys` deep-copies (name + scopes) under the lock and appends to an un-presized `ArrayList` | `src/api_keys.zig:308-319` | `dupe`/`dupeScopes` + `list.append` all inside the locked region; list starts `.empty` | `confidence::suspected` -- latent under single-threaded io | PR-006 / GAP-0047 | Collect cheap refs under lock, deep-copy after unlock; `ensureTotalCapacity` before the loop | <benji@vester.by> | Backlog | Open |
| 14 | P3 | 8 | `feedKv` issues 4 separate `hmac.update()` calls per property | `src/hmac.zig:95-103` | klen, key, vlen, value each fed individually; many small `update`s per record | `confidence::suspected` -- needs micro-bench; SHA-256 block buffering may already absorb this | PR-003 | Only act if a bench shows it matters; could pack len-prefix+data into one buffer | <benji@vester.by> | Backlog | Open |
| 15 | P3 | 6 | `detect_diamond_deps.py` BFS uses `list.pop(0)` → O(n²) queue drain | `scripts/detect_diamond_deps.py:191` | `queue: List[Path]`; `queue.pop(0)` is O(n) each call inside the `while queue` loop | `confidence::confirmed` -- code inspection | PR-012 | Use `collections.deque` + `popleft()` for O(1) dequeue | <benji@vester.by> | Backlog | Open |

---

## Resolved Findings

All seven items below were verified fixed in the current tree on 2026-06-12.
Moved here from the open table; retained for audit history.

| ID | Issue | Severity | Finding | Resolution Evidence (current code) |
|---|---|---|---|---|
| PERF-P0-001 | #20 | P0 | `verifyCode` redundantly decoded the base32 secret on every window iteration (3x heap alloc/free per verify) | `base32Decode` now called **once** before the loop — `src/mfa.zig:237` ("Decode the secret once (not per-iteration)"); the window loop calls the no-alloc `generateCodeFromRaw(secret_raw, ...)` at `:257` |
| PERF-P0-002 | #21 | P0 | `computeRecordHmac` `@panic`'d when `props.len > 128` (process crash / DoS) | Now returns `error{TooManyProperties}` — signature `src/hmac.zig:60`, `return error.TooManyProperties` at `:67`; no `@panic` remains on the path |
| PERF-P0-003 | #24 | P0 | SHA256 of the provided secret was computed *inside* the validation mutex, serializing concurrent validations behind crypto | SHA256 now runs **before** the lock — `crypto.hash.sha2.Sha256.hash(&parsed.secret, &provided_hash, ...)` at `src/api_keys.zig:181`; `mutex.lockUncancelable(...)` not until `:184` |
| PERF-P1-001 | #27 | P1 | Hand-rolled 30-line HMAC-SHA1 (ipad/opad) duplicating stdlib | Replaced with stdlib alias `const HmacSha1 = std.crypto.auth.hmac.HmacSha1;` — `src/mfa.zig:16`; used via `HmacSha1.create` at `:207` |
| PERF-P1-002 | #31 | P1 | `cleanupExpired` swallowed OOM (`append catch continue`) → expired keys accumulate silently | Now `pub fn cleanupExpired(self: *Self) !usize` (`src/api_keys.zig:332`) with `try to_remove.append(...)` at `:344`; OOM propagates to the caller |
| PERF-P1-003 | #33 | P1 | HKDF PRK re-`extract`'d inside the scratch-code loop (salt+ikm invariant) | `extract` hoisted above the loop — `var prk = HkdfSha256.extract(config.salt, raw_secret);` at `src/mfa.zig:170`; loop body only calls `expand` at `:179` |
| PERF-P1-004 | #37 | P1 | Secrets freed without zeroing | `crypto.secureZero` now applied broadly: `mfa.zig` `Enrollment.deinit` (:50), `enroll` raw secret (:155), `scratch_bytes` (:176), `prk` (:171), generate/verify `secret_raw` (:194,:239), inner `h` (:208); `api_keys.zig` `secret` (:117), parsed `secret` (:173), `provided_hash` (:182) |

---

## Verified Clean (do **not** "optimize")

These patterns were inspected and are intentional or already optimal. Flagging
them here to prevent a future pass from "fixing" them into regressions.

| Item | Location | Why it is correct as-is |
|---|---|---|
| TOTP window has no early-exit on match | `src/mfa.zig:248-262` (`verifyCode`) | **Deliberate timing-side-channel defense.** The loop always runs all `2*window+1` steps and OR-accumulates `match`; short-circuiting on first match would leak which window matched. Do not add a `break`. |
| `formatApiKey` single-allocation builder | `src/api_keys.zig:381-400` | Computes `total_len` up front and encodes prefix/id/secret into one buffer — exemplary, zero intermediate allocations. |
| `BASE32_ALPHABET` is comptime | `src/mfa.zig:55` | Compile-time constant string; no runtime table build. |
| HKDF scratch `prk` hoisted | `src/mfa.zig:170` | Already the fixed form of PERF-P1-003; reused across scratch-code generation. |
| `lockUncancelable` usage | all 7 mutex sites (`api_keys.zig:72,105,184,250,277,295,333`) | Correct uncancelable lock against the single-threaded io on every site; no missed-unlock paths (all paired with `defer ...unlock`). |
| Observability seam call itself | `src/observability.zig` seam, called from `mfa.zig`/`api_keys.zig` | The seam compiles to a comptime no-op when `-Dwith_otel=false` (default) — the *call* is zero-cost. (The pre-seam `bufPrint` is **not** zero-cost — that is PR-015 above, a separate issue from the seam.) |

---

## Findings by Area

### area::app (13 open findings)

- **MFA module (`src/mfa.zig`):** heap-alloc base32 decode on generate/verify despite an existing no-alloc decoder (P2, PERF-P2-002); per-call modulus recompute (P3, PR-001). All three original MFA P0/P1 items (redundant decode, hand-rolled HMAC-SHA1, HKDF-in-loop) are **resolved**.
- **API Keys module (`src/api_keys.zig`):** dead telemetry `bufPrint` on hot paths (P2, PR-015 — highest-leverage open item); over-broad mutex in `createKey` (P2, NEW-001) and double `Timestamp.now` in `validateKey` (P2, NEW-002); O(n) per-user scans (P2, PERF-P2-001); no HashMap pre-alloc (P2, PERF-P2-004); unbounded growth (P3, PERF-P3-001); two-pass cleanup (P3, demoted, PERF-P2-003); struct padding (P3, PR-005); deep-copy-under-lock + un-presized list (P3, PR-006); and the `listUserKeys` scope-leak correctness bug (P1, NEW-003).
- **HMAC module (`src/hmac.zig`):** `feedKv` per-field `update` calls (P3 suspected, PR-003). The original P0 panic is **resolved**.

### area::ci (1 open finding)

| Finding | Details |
|---|---|
| No CI cache; Zig re-downloaded + recompiled per job (PERF-P3-002) | `.install-zig` runs in all jobs; no `cache:` block; covers #35/#36. Add toolchain cache keyed on `ZIG_VERSION` and reuse `.zig-cache` build artifacts across the 8 test/fuzz jobs. |

### area::infra (1 open finding, tooling)

| Finding | Details |
|---|---|
| O(n²) BFS in diamond-dep detector (PR-012) | `scripts/detect_diamond_deps.py:191` `list.pop(0)`; switch to `deque.popleft()`. Build/release tooling, not runtime auth, hence P3. |

### area::db

No database-layer findings. This library has no persistence layer (in-memory `AutoHashMap` only).

---

## Roadmap

### Quick Wins (< 1 day)

| Item | Finding | Effort | Impact |
|---|---|---|---|
| PR-015 / GAP-0041 | Comptime-guard hot-path `bufPrint` | ~1 hr | Removes a `bufPrint` from every auth call when otel is off (the default) — hottest path, trivial fix |
| NEW-003 / GAP-0022 | Fix `listUserKeys` scope-leak errdefer window | ~1 hr | Closes a real allocation-leak correctness bug |
| NEW-002 / GAP-0024 | Read `now` once in `validateKey` | ~30 min | One fewer syscall under lock |
| PR-001 / GAP-0043 | Hoist TOTP modulus out of inner routine | ~30 min | Saves a 6-iter loop per window step in verify |
| PR-012 | `deque.popleft()` in diamond detector | ~15 min | O(n²)→O(n) BFS in CI tooling |
| PERF-P3-002 | Add CI toolchain + build cache | ~1 hr | ~30-60s saved per job across ~11 jobs |

### Medium (1-5 days)

| Item | Finding | Effort | Impact |
|---|---|---|---|
| PERF-P2-002 | No-alloc `base32DecodeInto` into `[20]u8` for generate/verify | ~3 hr | Drops a heap alloc/free from every TOTP op (decoder already exists) |
| NEW-001 / GAP-0023 | Shrink `createKey` lock to just `keys.put` | ~3 hr | Removes crypto+alloc+format from the locked region (latent until multi-threaded io) |
| PR-006 / GAP-0047 | Deep-copy `listUserKeys` after unlock + presize list | ~3 hr | Shortens lock hold; fewer ArrayList resizes |
| PERF-P2-004 | HashMap `ensureTotalCapacity` / init hint | ~1 day | Removes resize churn on initial load |
| PR-005 / GAP-0042 | Sentinel-encode the two `?i64` fields | ~1-2 days | Smaller `ApiKey`, better cache behavior on scans (pairs with PERF-P2-001) |

### Strategic (> 5 days)

| Item | Finding | Effort | Impact |
|---|---|---|---|
| PERF-P2-001 | Secondary user→token-id index | ~2-3 days | O(user-keys) instead of O(total-keys) for `revokeUserKeys`/`listUserKeys` |
| PERF-P3-001 | Enforce `max_keys` bound | ~1-2 days | Caps unbounded growth (perf + DoS) |
| PR-008 / PR-009 | `RwLock` + atomic `last_used_at` for shared-mode `validateKey` | gated | Only meaningful once a multi-threaded executor replaces `global_single_threaded.io()`; revisit then |
| (prereq) #11 | Build a `zig build bench` harness | ~2-3 days | **Unblocks before/after measurement for everything above** |

---

## Issue / Gap-ID Cross-Reference

| Finding | Tracking |
|---|---|
| PERF-P0-001 verifyCode redundant decode | #20 (resolved) |
| PERF-P0-002 computeRecordHmac panic | #21 (resolved) |
| PERF-P0-003 SHA256 inside mutex | #24 (resolved) |
| PERF-P1-001 hand-rolled HMAC-SHA1 | #27 (resolved) |
| PERF-P1-002 cleanupExpired silent OOM | #31 (resolved) |
| PERF-P1-003 HKDF PRK in loop | #33 (resolved) |
| PERF-P1-004 no secret zeroing | #37 (resolved) |
| PERF-P2-001 O(n) user scans | open, untracked |
| PERF-P2-002 heap-alloc base32 decode | open, untracked |
| PERF-P2-003 two-pass cleanup (demoted P3) | open, untracked |
| PERF-P2-004 no HashMap pre-alloc | open, untracked |
| PERF-P3-001 unbounded key map | open, untracked (also DoS) |
| PERF-P3-002 CI no cache | open; covers #35 / #36 |
| NEW-001 createKey wide lock | GAP-0023 |
| NEW-002 validateKey double now() | GAP-0024 |
| NEW-003 listUserKeys scope leak | GAP-0022 (correctness; cross-ref quality) |
| PR-001 TOTP modulus recompute | GAP-0043 |
| PR-003 feedKv 4x update | open, untracked |
| PR-005 ApiKey ?i64 padding | GAP-0042 |
| PR-006 listUserKeys copy-under-lock | GAP-0047 |
| PR-008 / PR-009 RwLock + atomic last_used | open, gated/future |
| PR-012 diamond detector O(n²) BFS | open, untracked |
| PR-015 dead hot-path bufPrint | GAP-0041 |
| (harness) bench prerequisite | #11 |

> Issue creation/update for the untracked rows is owned by the issue-ops agent.

---

## Unknowns and Blockers

1. **No benchmark harness (`zig build bench`) exists.** This blocks all
   before/after measurement for every MFA / API-key finding. Every "Measurement"
   cell tagged `confidence::suspected` stays suspected until a harness lands.
   Tracked by **#11**. Building it is the highest-leverage *enabling* task.
2. **Single-threaded io masks lock-contention wins.** NEW-001, NEW-002, PR-006,
   PR-008/009 all reduce mutex hold time, but every lock targets
   `std.Io.Threaded.global_single_threaded.io()` today, so the contention is
   latent. These were scored with lower Likelihood, not dropped — they become
   real wins the moment a multi-threaded executor is adopted. Confirm the
   intended concurrency model before prioritizing them above quick wins.
3. **Production key-volume profile unknown.** PerfScores for PERF-P2-001 (O(n)
   scans), PERF-P2-004 (pre-alloc), and PR-005 (struct size) depend on typical
   total key count and keys-per-user. A realistic load sample would confirm or
   adjust these.
4. **`feedKv` micro-cost unverified (PR-003).** SHA-256's internal block
   buffering may already absorb the four small `update()` calls per property;
   needs a micro-bench before any change. Left P3/suspected deliberately.
