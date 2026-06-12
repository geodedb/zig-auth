# Security Gap Analysis

Last updated: 2026-06-12

## Overview

Security gap analysis for the `auth` library (`devnw/zig/auth`) at `main` (`3605f87`),
Zig 0.16.0. This document was **fully regenerated** against the current tree after a
remediation pass. The authoritative deep-dive backing every finding here is
[`docs/APPSEC_REVIEW_2026-06-12.md`](./APPSEC_REVIEW_2026-06-12.md) (OWASP Top 10:2025 +
CIS Controls v8.1.2). Cross-reference it for full evidence, exploit scenarios, and
remediation code.

The prior revision of this document (dated 2026-03-23) was **stale**: its line numbers
pointed at pre-remediation code and it asserted Criticals (SEC-001 deterministic-by-default
secrets, SEC-002 no zeroization) that are now fixed. **9 of the 13 original findings
(SEC-001…SEC-013) are remediated** and have been moved to the [Resolved](#resolved-findings)
section with current evidence. The residual risks from those findings, plus new findings
surfaced by the appsec review and Phase 3 delta, are tracked below with stable Gap-IDs.

This is a **library**, not a running service — there is no network listener, no in-repo
privilege boundary. "Exploitability" is assessed from the perspective of a consuming
production application and an attacker who can interact with it or read its process
memory/host.

> Issue operations (create/update/close) are owned by a separate agent. This document
> only references Gap-IDs and existing issue numbers; it does not create issues.

## Summary

| Severity | Open | Resolved | SLA |
|----------|-----:|---------:|-----|
| Critical | 0 | 0 | 7 days |
| High | 3 | 0 | 30 days |
| Medium | 9 | 0 | 90 days |
| Low | 6 | 0 | 180 days |
| Info | 1 | 0 | backlog |
| Resolved (SEC-001…SEC-013) | — | 11 | — |
| **Open total** | **19** | | |

No Critical findings in current code. The two prior Criticals (deterministic-by-default
TOTP secrets; no zeroization) are remediated. The residual risk is the **misuse switch**
that can re-enable the deterministic path, tracked at Medium as GAP-0016.

### Top 5 Open Risks

1. **GAP-0030 / SR-004** (High, RS 60) — `MfaConfig.digits = 0` makes every TOTP code `0`; silent, total MFA bypass with no error (`mfa.zig:216-219`).
2. **GAP-0007 / AUTH-RNG-001** (High, RS 60) — credential generation uses `io.random()`, which silently falls back to a low-entropy seed (pid + clock + ASLR) on entropy failure; should be `randomSecure()` (`api_keys.zig:111-112`, `mfa.zig:135`).
3. **GAP-0008 / AUTH-MFA-002** (High, RS 60) — recovery codes carry only 40 bits of entropy **and have no verification/consumption API**, so single-use cannot be enforced (`mfa.zig:173-184`).
4. **GAP-0019 / AUTH-AKEY-002** (Medium, RS 48) — `validateKey` returns borrowed `name`/`scopes` slices the manager still owns and frees; concurrent revoke/cleanup → use-after-free during authorization (`api_keys.zig:212`, `hasScope:228`).
5. **GAP-0032 / SR-001** (Medium, RS 48) — `createKey` does `keys.put` with no collision check; an ID collision clobbers the prior entry, leaking its heap allocations and silently invalidating a live key (`api_keys.zig:147`).

## Scanner Results

| Scanner | Scope | Result |
|---------|-------|--------|
| gitleaks | HEAD + full history | Clean — no secrets detected |
| semgrep | `p/python`, `p/secrets`, `p/ci-cd-security` | Clean — no findings |
| vuln-mcp (advisory DB) | dependency manifest | No advisories (Zig ecosystem not indexed; treat as no-coverage, not no-risk) |
| Zig toolchain download | `.gitlab-ci.yml` | SHA-256 verification against signed `ziglang.org` index confirmed sound |

Note: vuln-mcp does not index the Zig ecosystem, so absence of advisories is **lack of
coverage**, not evidence of safety. Supply-chain risk is tracked via GAP-0018 and the
CI/pin findings below.

## Stack-Ranked Open Findings

Sorted by risk score descending. `Risk Score = Impact(1-5) x Likelihood(1-5) x 4`.

| Rank | Severity | RS | Finding | Component | CWE / OWASP | Evidence | Gap-ID / Issue | Fix |
|-----:|----------|:--:|---------|-----------|-------------|----------|----------------|-----|
| 1 | High | 60 | `MfaConfig.digits=0` → every TOTP code is `0`; silent MFA bypass | mfa | CWE-1284 / A04:2025 | `src/mfa.zig:216-219` | GAP-0030 / SR-004 | Validate `digits` in `1..=8`; reject at config boundary |
| 2 | High | 60 | Credential generation uses fallible `io.random()` (silent low-entropy fallback) instead of `randomSecure()` | api_keys, mfa | CWE-330, CWE-338 / A02:2025, A04:2025 | `src/api_keys.zig:111-112`, `src/mfa.zig:135` | GAP-0007 / AUTH-RNG-001 | Use `io.randomSecure()`, propagate `error.EntropyUnavailable` |
| 3 | High | 60 | Recovery codes ~40-bit **and no verify/consume API** | mfa | CWE-330, CWE-654 / A07:2025 | `src/mfa.zig:173-184` | GAP-0008 / AUTH-MFA-002 | Generate ≥128-bit via `randomSecure`, store hashed, add single-use `verifyScratchCode` |
| 4 | Medium | 48 | `validateKey` returns borrowed `name`/`scopes` slices; UAF under concurrent revoke/cleanup | api_keys | CWE-825, CWE-362 / A04:2025 | `src/api_keys.zig:212`, `:228` | GAP-0019 / AUTH-AKEY-002 | Deep-copy slices on return (mirror `listUserKeys`); add `freeValidatedKey` |
| 5 | Medium | 48 | `createKey` `keys.put` clobbers on ID collision — overwrite + heap leak | api_keys | CWE-401, CWE-694 / A04:2025 | `src/api_keys.zig:147` | GAP-0032 / SR-001 | Use `getOrPut`; on collision regenerate or return error |
| 6 | Medium | 48 | API-key secret hashed with bare SHA-256, no server pepper/KDF | api_keys | CWE-916 / A04:2025 | `src/api_keys.zig:116`, `:181` | GAP-0015 / AUTH-AKEY-001 (#40) | `HMAC-SHA256(server_pepper, secret)` using repo's `hmac` module |
| 7 | Medium | 48 | `MfaConfig` unvalidated: `window<0` silent lockout; `step_seconds=0` div-by-zero panic; `digits>=10` overflow panic; window extremes overflow | mfa | CWE-369, CWE-190, CWE-617 / A04:2025 | `src/mfa.zig:202`, `:216-218`, `:247-254` | GAP-0031 / SR-005+SR-006 | Add a `validate()` on `MfaConfig`; bound all fields, fail closed |
| 8 | Medium | 36 | `deterministic` config switch fully defeats MFA if set in prod; default public salt; guarded only by comment | mfa | CWE-1188 / A06:2025 | `src/mfa.zig:36-40`, `:128-138` | GAP-0016 / AUTH-MFA-001 (re-scope of SEC-001, #23) | Gate behind `builtin.is_test`/comptime; drop default salt |
| 9 | Medium | 36 | No TOTP replay protection; matched step not exposed | mfa | CWE-294 / A07:2025 | `src/mfa.zig:231-265` | GAP-0017 / AUTH-MFA-003 (#43) | Return matched timestep; ship `verifyCodeOnce(..., last_used_step)` |
| 10 | Medium | 36 | `otel` dep `ref`/`hash` mismatch — cold CI fetch will fail | build | CWE-1357 / A03:2025 | `build.zig.zon:13-14` | GAP-0018 / AUTH-SUP-001 | Re-run `zig fetch` and paste emitted hash; add CI assertion ref↔hash version match |
| 11 | Medium | 24 | `installGlobals` unsynchronized global pointers (gated on otel re-enable) | observability_init | CWE-825, CWE-362 / A04:2025 | `src/observability_init.zig:87-96` | GAP-0035 / SR-011 | Synchronize/Once-guard global install; revisit when otel re-enabled |
| 12 | Medium | 36 | No adversarial / concurrency security tests | tests | CWE-1390 / A04:2025 | `tests/integration.zig` | GAP-0036 / SR-012 | Add entropy-starvation, replay, UAF-under-revoke, config-fuzz tests |
| 13 | Low | 24 | Duplicate-key HMAC is order-dependent | hmac | CWE-1023 / A04:2025 | `src/hmac.zig:79-84` | GAP-0033 / SR-008 | Reject/canonicalize duplicate keys before HMAC |
| 14 | Low | 24 | `key_prefix` `.` separator unenforced | api_keys | CWE-20 / A04:2025 | `src/api_keys.zig:28-30` | GAP-0034 / SR-003 | Validate `key_prefix` excludes `.` (parse delimiter) |
| 15 | Low | 24 | Base32 encode/decode length asymmetry (no-pad encode, block-strict decode) | mfa | CWE-131 / A04:2025 | `src/mfa.zig:61-95` | GAP-0021 / AUTH-MFA-004 (#44) | RFC 4648 padding or return true decoded length |
| 16 | Low | 24 | Telemetry hard-disabled; no auth security events emitted | observability | CWE-778 / A09:2025 | `src/observability.zig:44` | GAP-0020 / AUTH-OBS-001 | Restore `enabled = build_options.with_otel` or document inert + add `-Dwith_otel=true` CI job |
| 17 | Low | 24 | Default HKDF salts hardcoded (public) | hmac, mfa | CWE-1188 / A04:2025 | `src/hmac.zig:33-35`, `src/mfa.zig:40` | GAP-0007-rel / QGA-009 | Require caller-supplied salt or document as domain-separation-only (non-secret) |
| 18 | Low | 12 | `minimum_zig_version` understated (`0.15.1` vs real 0.16) | build | CWE-1104 / A03:2025 | `build.zig.zon:5` | GAP-0013 / AUTH-SUP-002 | Set `minimum_zig_version = "0.16.0"` |
| 19 | Low (suspected) | 16 | `debian:bookworm-slim` not digest-pinned (9 CI jobs) | ci | CWE-1357 / A03:2025 | `.gitlab-ci.yml` (9 jobs) | CI-IMG-001 | Pin base image by `@sha256:` digest |
| 20 | Info | 8 | pre-commit + CI component tags not SHA-pinned | ci | CWE-1357 / A03:2025 | `.pre-commit-config.yaml`, `.gitlab-ci.yml` | PC-PIN-001 / CI-COMP-001 | Pin pre-commit hooks and CI components by SHA |

## Open Findings — Detail

Full evidence, exploit scenarios, and remediation code for each are in
[`docs/APPSEC_REVIEW_2026-06-12.md`](./APPSEC_REVIEW_2026-06-12.md). Summarized here.

### GAP-0030 / SR-004 — `MfaConfig.digits = 0` produces all-zero TOTP codes (High)

- **CWE/OWASP:** CWE-1284 (improper validation of specified quantity) / A04:2025 Insecure Design.
- **Evidence (`src/mfa.zig:216-219`):** `var mod: u32 = 1; while (i < config.digits) : (i += 1) mod *= 10; return bin_code % mod;` — with `digits = 0` the loop never executes, `mod` stays `1`, and `bin_code % 1 == 0` for every input. Every generated and verified code is `0`.
- **Impact:** A misconfigured (or attacker-influenced, if config is deserialized) `digits = 0` makes the system accept `0` as the valid TOTP for every user at every timestep — silent, total MFA bypass with no error surfaced. Part of the broader unvalidated-config cluster (GAP-0031).
- **Remediation:** Validate `digits` (e.g. `1..=8`) at the config boundary; reject `0` and out-of-range values with an explicit error. Add a regression test asserting rejection.

### GAP-0007 / AUTH-RNG-001 — Credential generation uses fallible `io.random()` (High)

- **CWE/OWASP:** CWE-330, CWE-338 / A02:2025 Security Misconfiguration, A04:2025 Cryptographic Failures.
- **Evidence:** `src/api_keys.zig:111-112` (`io().random(&id)`, `io().random(&secret)`); `src/mfa.zig:135` (TOTP secret). Per the Zig 0.16 stdlib, `io.random()` may reuse stored process-memory RNG state and **silently falls back to a low-entropy seed (`pid + clock_gettime + ASLR`) on entropy-source failure, surfacing no error**. `io.randomSecure()` always makes a fresh syscall and returns `error.EntropyUnavailable` instead of weak bytes.
- **Impact:** On early boot / minimal containers / seccomp-restricted / some CI environments, token IDs, 32-byte API-key secrets, and 20-byte TOTP secrets can be derived from a few-dozen-bit attacker-correlatable seed, with no signal to the consumer. On a healthy host the practical risk is low, but this is a credential path that must fail closed.
- **Remediation:** Switch all three call sites (plus recovery-code generation) to `io.randomSecure()` and propagate `error.EntropyUnavailable`. Add an `Io.failing`-backed entropy-starvation test.

### GAP-0008 / AUTH-MFA-002 — Recovery codes low-entropy and unverifiable (High)

- **CWE/OWASP:** CWE-330, CWE-654 / A07:2025 Authentication Failures.
- **Evidence (`src/mfa.zig:173-184`):** each of 8 chars is `scratch_bytes[j] & 0x1F` → 5 bits/char → **40 bits/code**, default count 2. All codes derive from `HKDF-expand(prk, "scratch-code-{d}")` where `prk = HKDF-extract(salt, raw_secret)`, so under deterministic mode (GAP-0016) they are fully predictable from public inputs. `mfa.zig` exposes **no** `verifyScratchCode` / consumed-set — there is no supported way to verify a recovery code or enforce single-use.
- **Impact:** Recovery codes are the highest-value MFA-bypass path. They are both guessable (40 bits; predictable under the misuse switch) and unenforceable (no single-use). They are effectively decorative as shipped.
- **Remediation:** Generate ≥128-bit codes from `randomSecure` independent of the TOTP secret; store only hashes; add a constant-time, single-use `verifyScratchCode(stored_hashes, presented) -> ?index`. Document recovery codes as MFA-bypass credentials.

### GAP-0019 / AUTH-AKEY-002 — `validateKey` returns borrowed `name`/`scopes` (Medium)

- **CWE/OWASP:** CWE-825, CWE-362 / A04:2025.
- **Evidence (`src/api_keys.zig:212`):** `return key.*` shallow-copies `ApiKey`; its `name: []const u8` and `scopes: []const []const u8` still alias manager-owned heap. After the lock releases, a concurrent `revokeKey`/`cleanupExpired`/`deinit` can free those allocations, leaving the returned value's slices dangling. `hasScope` (`:228`) iterates `key.scopes`, reading freed memory during authorization. The pointer-level SEC-004 dangling-`*ApiKey` bug is fixed; this slice-aliasing residual is not.
- **Impact:** Concurrency-dependent use-after-free during authorization in a manager whose explicit purpose is thread-safe concurrent use.
- **Remediation:** Deep-copy `name`/`scopes` on return (mirror `listUserKeys` at `:312-314`) and provide `freeValidatedKey`; or return a struct with no heap slices.

### GAP-0032 / SR-001 — `createKey` clobbers on ID collision (Medium)

- **CWE/OWASP:** CWE-401, CWE-694 / A04:2025.
- **Evidence (`src/api_keys.zig:147`):** `try self.keys.put(id, key);` — unconditional insert. A duplicate `id` (RNG collision, or correlated weak IDs per GAP-0007) overwrites the prior entry. The replaced `ApiKey`'s `name`/`scopes` allocations are leaked (never freed) and a previously-issued, still-valid key is silently invalidated.
- **Impact:** Memory leak plus silent loss of a live credential on collision. Low likelihood with strong RNG, compounded if GAP-0007 weakens ID entropy.
- **Remediation:** Use `getOrPut`; on collision regenerate the ID (bounded retries) or return an explicit error. Never overwrite an existing entry.

### GAP-0015 / AUTH-AKEY-001 — Bare SHA-256 for API-key secret, no pepper (Medium)

- **CWE/OWASP:** CWE-916 / A04:2025. Issue #40.
- **Evidence (`src/api_keys.zig:116`, `:181`):** `Sha256.hash(&secret, ...)` on store and verify. Partially mitigated because the secret is a full 32-byte CSPRNG value (offline brute force infeasible) and the compare is constant-time (`:198`). But there is **no server-side pepper**, so a read-only key-store disclosure yields directly-correlatable hashes with no defense-in-depth, and any future change shortening the secret or importing user-influenced key material becomes an offline-cracking exposure.
- **Remediation:** Replace with `HMAC-SHA256(server_pepper, secret)` using the repo's own `hmac` module; keep the constant-time compare. `server_pepper` held outside the key store.

### GAP-0031 / SR-005 + SR-006 — `MfaConfig` is unvalidated (Medium)

- **CWE/OWASP:** CWE-369, CWE-190, CWE-617 / A04:2025.
- **Evidence:** `step_seconds = 0` → `timestamp_ms / (0 * 1000)` div-by-zero panic (`src/mfa.zig:202`); `digits >= 10` → `mod *= 10` u32 overflow panic (`:216-218`, and the all-zero case at `digits=0` is GAP-0030); `window < 0` → loop `-window..=window` never accepts, silent permanent lockout; window extremes → `delta_ms` multiply overflow (`:247-254`).
- **Impact:** A single bad config field panics the process (DoS) or silently disables verification. No `MfaConfig` validation exists anywhere.
- **Remediation:** Add `MfaConfig.validate()` bounding `digits` (`1..=8`), `step_seconds` (`>= 1`), `window` (`0..=N`), and reject at construction. Fail closed with explicit errors, never panic.

### GAP-0016 / AUTH-MFA-001 — `deterministic` misuse switch + default public salt (Medium)

- **CWE/OWASP:** CWE-1188 / A06:2025. Re-scope of resolved SEC-001 (#23).
- **Evidence (`src/mfa.zig:36-40`, `:128-138`):** the default is now random (SEC-001 remediated, good). Residual: a single `deterministic: bool = false` field, if ever set `true` in production, makes every user's TOTP secret `HKDF(username, "auth-mfa-salt-v1")` — both inputs public. Guarded only by a doc comment; no build-mode gate, no distinct type, default salt shipped.
- **Impact:** Total MFA bypass for all users if the flag reaches a real deployment. "Misuse" likelihood, complete blast radius.
- **Remediation:** Gate the deterministic branch behind `@import("builtin").is_test` (or a comptime build option) so it cannot run in release; remove the default salt (require caller-supplied) if runtime toggling must remain; rename the field to scream "insecure/test-only."

### GAP-0017 / AUTH-MFA-003 — No TOTP replay protection (Medium)

- **CWE/OWASP:** CWE-294 / A07:2025. Issue #43.
- **Evidence (`src/mfa.zig:231-265`):** `verifyCode` is stateless and does not return or accept a "last-used step," so a valid code is accepted on every call within its `(2*window+1)`-step window (default 90 s) and a consumer **cannot** enforce single-use. Comparison is correctly constant-time and does not early-return on match (good).
- **Impact:** An intercepted/over-the-shoulder code is replayable for up to the window duration — the canonical TOTP replay weakness — and the library prevents the consumer from fixing it.
- **Remediation:** Return the matched timestep on success (`?u64`) so callers can persist and reject `step <= last_used_step`; ship a `verifyCodeOnce(..., last_used_step: *u64)` helper.

### GAP-0018 / AUTH-SUP-001 — `otel` dependency `ref`/`hash` mismatch (Medium, CONFIRMED)

- **CWE/OWASP:** CWE-1357 / A03:2025 Software Supply Chain Failures.
- **Evidence (`build.zig.zon:13-14`):** URL pins `ref=v0.1.10#a1afbfe…` but `hash = "otel-0.1.9-B0v3ltxe…"`. **Confirmed:** `zig fetch …?ref=v0.1.10` emits `otel-0.1.9-B0v3lphe…`, which disagrees with the pinned `…B0v3ltxe…`. A cold CI fetch (no warm cache) will fail hash verification. The active diamond-dep auto-rewrite tooling (recent commits `16216b8`, `3605f87`) is the likely source of the skew.
- **Impact:** Cold-cache builds under `-Dwith_otel=true` fail to fetch (reliability break); the human-readable version label is internally inconsistent, undermining the pin's audit value. Lowered exposure today because the dep is `lazy` and telemetry is inert (GAP-0020), but a future enablement hits it.
- **Remediation:** Re-run `zig fetch` and paste the emitted hash so `ref`, commit, and `hash` describe one tree. Add a CI/`detect_diamond_deps.py` assertion that each `hash`'s embedded version matches its `ref`.

### GAP-0035 / SR-011 — `installGlobals` unsynchronized global pointers (Medium, suspected)

- **CWE/OWASP:** CWE-825, CWE-362 / A04:2025. Gated on otel re-enable.
- **Evidence (`src/observability_init.zig:87-96`):** global provider/exporter pointers installed without synchronization; concurrent or repeated install races. Currently unreachable because telemetry is hard-disabled (GAP-0020), so this is latent.
- **Impact:** If/when otel is re-enabled, a data race on global init could read/install dangling or half-initialized pointers. Suspected — confirm with a concurrency test once the seam is live.
- **Remediation:** Guard global install with a `std.once`/atomic CAS; document single-init contract. Revisit when GAP-0020 restores telemetry.

### GAP-0036 / SR-012 — No adversarial / concurrency security tests (Medium)

- **CWE/OWASP:** CWE-1390 / A04:2025.
- **Evidence (`tests/integration.zig`):** tests cover functional happy paths but no entropy-starvation, TOTP replay, UAF-under-concurrent-revoke, or config-fuzz cases — exactly the failure modes above.
- **Impact:** The highest-risk behaviors (GAP-0007, GAP-0017, GAP-0019, GAP-0030/0031) are unexercised, so regressions would pass CI.
- **Remediation:** Add adversarial tests: `Io.failing` entropy starvation, replay rejection, validate-then-revoke race (ThreadSanitizer if available), and `MfaConfig` boundary fuzzing.

### GAP-0033 / SR-008 — Duplicate-key HMAC is order-dependent (Low)

- **CWE/OWASP:** CWE-1023 / A04:2025.
- **Evidence (`src/hmac.zig:79-84`):** when a record contains duplicate property keys, the HMAC output depends on input ordering rather than canonical content, so semantically equal records can produce different MACs (or vice versa).
- **Remediation:** Reject duplicate keys, or canonicalize (sort + dedupe with explicit policy) before feeding the HMAC.

### GAP-0034 / SR-003 — `key_prefix` `.` separator unenforced (Low)

- **CWE/OWASP:** CWE-20 / A04:2025.
- **Evidence (`src/api_keys.zig:28-30`):** the configured `key_prefix` is not validated to exclude the `.` delimiter used by the key parser. A prefix containing `.` produces ambiguous parsing of `prefix.id.secret`.
- **Remediation:** Validate `key_prefix` at config time to reject the `.` delimiter (and empty prefix).

### GAP-0021 / AUTH-MFA-004 — Base32 encode/decode asymmetry (Low)

- **CWE/OWASP:** CWE-131 / A04:2025. Issue #44.
- **Evidence (`src/mfa.zig:61-95`):** `base32Encode` emits no-padding output and zero-pads partial groups; `base32Decode` requires `len % 8 == 0` and silently zero-pads. The 20-byte TOTP secret (multiple of 5) round-trips exactly, so the production path is fine, but non-mod-5 inputs through these helpers silently gain trailing zero bytes the caller must know to trim — a latent length-confusion hazard.
- **Remediation:** Implement RFC 4648 padding (encode + accept/strip on decode) or return the true decoded length.

### GAP-0020 / AUTH-OBS-001 — Telemetry hard-disabled, no auth security events (Low)

- **CWE/OWASP:** CWE-778 / A09:2025 Logging & Alerting Failures.
- **Evidence (`src/observability.zig:44`):** `pub const enabled: bool = false;` collapses all spans to no-ops regardless of `-Dwith_otel`. Auth call sites are wired to emit authn/authz success/failure spans (`api_keys.zig:163`, `mfa.zig:149,232`) but emit nothing. The "enabled" test (`tests/observability_enabled_test.zig:30`) skips, so the enabled path is untested.
- **Impact:** Loss of authentication-failure / authz-denial signal — a logging-and-alerting gap for a credential library. Low directly (consumers can log around it), but it nullifies an advertised feature.
- **Remediation:** Restore `enabled = build_options.with_otel` once the Zig 0.16 module-dedup issue is resolved, or document prominently that telemetry is inert; add a `-Dwith_otel=true` CI job exercising the enabled path.

### GAP-0007-related / QGA-009 — Default HKDF salts hardcoded (Low)

- **CWE/OWASP:** CWE-1188 / A04:2025.
- **Evidence (`src/hmac.zig:33-35`, `src/mfa.zig:40`):** default HKDF salts are hardcoded public constants. Acceptable for domain separation (salts need not be secret), but shipping a usable default invites reuse where a unique/secret salt was intended, and ties into the GAP-0016 deterministic-mode predictability.
- **Remediation:** Require a caller-supplied salt where it functions as a security boundary, or document explicitly that these salts are domain-separation labels, not secrets.

### GAP-0013 / AUTH-SUP-002 — `minimum_zig_version` understated (Low)

- **CWE/OWASP:** CWE-1104 / A03:2025.
- **Evidence (`build.zig.zon:5`):** `minimum_zig_version = "0.15.1"` while the code pervasively uses 0.16 APIs (`std.Io.Mutex`, `std.Io.Threaded.global_single_threaded`, `std.Io.Timestamp`) and CI pins `0.16.0`. A consumer on 0.15.x gets cryptic compile errors instead of a clean version error.
- **Remediation:** Set `minimum_zig_version = "0.16.0"`.

### CI-IMG-001 — `debian:bookworm-slim` not digest-pinned (Low, suspected)

- **CWE/OWASP:** CWE-1357 / A03:2025.
- **Evidence:** 9 CI jobs use `debian:bookworm-slim` by tag, not `@sha256:` digest. A retagged/poisoned upstream image would be pulled silently.
- **Remediation:** Pin the base image by digest; refresh via a controlled, reviewed update.

### PC-PIN-001 / CI-COMP-001 — pre-commit + CI component tags not SHA-pinned (Info)

- **CWE/OWASP:** CWE-1357 / A03:2025.
- **Evidence:** pre-commit hooks (`.pre-commit-config.yaml`) and GitLab CI components (`.gitlab-ci.yml`) reference mutable tags rather than SHAs.
- **Remediation:** Pin all pre-commit hooks and CI components by commit SHA; update via Renovate/Dependabot-style controlled bumps.

## Findings by Area

### Authentication (MFA / TOTP)

| Gap-ID | Severity | Finding | CWE |
|--------|----------|---------|-----|
| GAP-0030 | High | `digits=0` → all-zero codes, MFA bypass | CWE-1284 |
| GAP-0008 | High | Recovery codes 40-bit + no verify API | CWE-330, CWE-654 |
| GAP-0031 | Medium | `MfaConfig` unvalidated (panic/lockout/overflow) | CWE-369, CWE-190, CWE-617 |
| GAP-0016 | Medium | Deterministic misuse switch + public salt | CWE-1188 |
| GAP-0017 | Medium | No TOTP replay protection | CWE-294 |
| GAP-0021 | Low | Base32 encode/decode asymmetry | CWE-131 |
| QGA-009 | Low | Hardcoded default HKDF salts | CWE-1188 |

### Authentication (API Keys)

| Gap-ID | Severity | Finding | CWE |
|--------|----------|---------|-----|
| GAP-0019 | Medium | `validateKey` borrowed-slice UAF | CWE-825, CWE-362 |
| GAP-0032 | Medium | `createKey` ID-collision clobber + leak | CWE-401, CWE-694 |
| GAP-0015 | Medium | Bare SHA-256, no pepper | CWE-916 |
| GAP-0034 | Low | `key_prefix` `.` unenforced | CWE-20 |

### Cryptographic Primitives (HMAC)

| Gap-ID | Severity | Finding | CWE |
|--------|----------|---------|-----|
| GAP-0033 | Low | Duplicate-key HMAC order-dependent | CWE-1023 |

### RNG / Entropy (Cross-Cutting)

| Gap-ID | Severity | Finding | CWE |
|--------|----------|---------|-----|
| GAP-0007 | High | `io.random()` low-entropy fallback | CWE-330, CWE-338 |

### Observability / Detection

| Gap-ID | Severity | Finding | CWE |
|--------|----------|---------|-----|
| GAP-0035 | Medium | Unsynchronized global install (gated) | CWE-825, CWE-362 |
| GAP-0020 | Low | Telemetry hard-disabled, no auth events | CWE-778 |
| GAP-0036 | Medium | No adversarial/concurrency tests | CWE-1390 |

### Supply Chain / CI

| Gap-ID | Severity | Finding | CWE |
|--------|----------|---------|-----|
| GAP-0018 | Medium | `otel` ref/hash mismatch (cold fetch fails) | CWE-1357 |
| GAP-0013 | Low | `minimum_zig_version` understated | CWE-1104 |
| CI-IMG-001 | Low | base image not digest-pinned | CWE-1357 |
| PC-PIN-001 | Info | pre-commit/CI tags not SHA-pinned | CWE-1357 |

## Remediation Roadmap

### Quick Wins (< 1 day each)

| Gap-ID | Task |
|--------|------|
| GAP-0030 | Validate `digits` range; reject `0` and `>8` |
| GAP-0031 | Add `MfaConfig.validate()`; bound `step_seconds`, `window`, `digits`; fail closed |
| GAP-0034 | Validate `key_prefix` excludes `.` |
| GAP-0013 | Set `minimum_zig_version = "0.16.0"` |
| GAP-0018 | Re-run `zig fetch`, paste emitted hash, reconcile `ref`/`hash` |
| CI-IMG-001 | Pin `debian:bookworm-slim` by digest |
| PC-PIN-001 | SHA-pin pre-commit hooks and CI components |

### Medium Effort (1-5 days)

| Gap-ID | Task |
|--------|------|
| GAP-0007 | Switch credential generation to `io.randomSecure()`, propagate `error.EntropyUnavailable`, add starvation test |
| GAP-0019 | Deep-copy `name`/`scopes` in `validateKey`; add `freeValidatedKey` |
| GAP-0032 | `getOrPut` with collision regenerate/error in `createKey` |
| GAP-0015 | `HMAC-SHA256(server_pepper, secret)` for API-key hashing |
| GAP-0017 | Return matched timestep; add `verifyCodeOnce` replay-rejection helper |
| GAP-0016 | Gate deterministic branch behind `builtin.is_test`/comptime; drop default salt |
| GAP-0033 | Reject/canonicalize duplicate HMAC keys |
| GAP-0021 | Symmetric base32 padding or return true decoded length |
| GAP-0036 | Add adversarial/concurrency test suite |

### Strategic (> 5 days)

| Gap-ID | Task |
|--------|------|
| GAP-0008 | Redesign recovery codes: ≥128-bit via `randomSecure`, hashed at rest, single-use `verifyScratchCode` API |
| GAP-0020 / GAP-0035 | Restore telemetry seam (resolve Zig module-dedup), synchronize global install, add `-Dwith_otel=true` CI job |

## Immediate Actions Required

No leaked secrets and no active RCE — gitleaks is clean on HEAD and full history. No
finding requires emergency credential rotation. The highest-priority defensive actions
before any production MFA deployment:

1. **GAP-0030** — `digits=0` is a silent total MFA bypass. Validate config before shipping MFA.
2. **GAP-0007** — Move credential generation to `io.randomSecure()` so a credential path fails closed under entropy starvation.
3. **GAP-0008** — Recovery codes are unusable as shipped (40-bit, no verify path). Do not advertise recovery-code MFA until a hashed, single-use, high-entropy implementation exists.
4. **GAP-0018** — Reconcile the `otel` pin before relying on `-Dwith_otel=true` in CI; a cold fetch currently fails hash verification.

## Resolved Findings

The following findings from the prior (2026-03-23) revision were verified **remediated**
against the current tree (`main` @ `3605f87`). Evidence is the current code location of
the fix. Confirmed in [`docs/APPSEC_REVIEW_2026-06-12.md`](./APPSEC_REVIEW_2026-06-12.md) §5.

| ID | Issue | Original Severity | Finding | Remediation Evidence (current) | Residual |
|----|-------|-------------------|---------|--------------------------------|----------|
| SEC-001 | #19 | Critical | Deterministic-by-default TOTP secret from public inputs | Default is now **random** via CSPRNG (`src/mfa.zig:38`, branch at `:134-135`) | Misuse switch → GAP-0016 |
| SEC-002 | #22 | Critical | No secret zeroization anywhere | `crypto.secureZero` broadly applied: `api_keys.zig:117,173,182`; `mfa.zig:155-157,193-196,238-241`; `hmac.zig:44,208` | none |
| SEC-003 | #25 | High | Non-constant-time TOTP code comparison | `std.crypto.timing_safe.eql([4]u8, …)` (`src/mfa.zig:259`) | none |
| SEC-004 | #29 | High | `validateKey` returns dangling `*ApiKey` after mutex release | Returns owned value copy `key.*` (`src/api_keys.zig:212`) | Slice aliasing → GAP-0019 |
| SEC-005 | #34 | High | `listUserKeys` shallow-copies borrowed slices | Deep-clones `name`/`scopes` with partial-failure cleanup (`src/api_keys.zig:312-314`) | none |
| SEC-006 | #38 | Medium | `@panic` on >128 properties (DoS) | Returns `error.TooManyProperties`, stack-only (`src/hmac.zig:67`) | none |
| SEC-007 | #39 | Medium | Key prefix not validated against config | Prefix equality check (`src/api_keys.zig:176`) | none |
| SEC-009 | #41 | Medium | Silent error swallowing in `cleanupExpired` | Errors propagated, collect-then-remove (`src/api_keys.zig:332-356`) | none |
| SEC-010 | #42 | Medium | Integer truncation panic on large key/value lengths | Guarded by the 128-property cap (`src/hmac.zig:67`) | none |
| SEC-013 | #45 | Low | Custom HMAC-SHA1 implementation | Uses stdlib `std.crypto.auth.hmac.HmacSha1` (`src/mfa.zig:16`) | none |

Notes:

- **SEC-008** (SHA-256 without KDF) and **SEC-011** (no TOTP replay protection) and **SEC-012** (base32 trailing garbage) from the prior doc remain **open** under new Gap-IDs **GAP-0015**, **GAP-0017**, and **GAP-0021** respectively — they were not remediated, only re-scoped with current evidence.
- SEC-001 and SEC-004 are **partially** resolved: the specific Critical/High defect is fixed, but a narrower residual (misuse switch / slice aliasing) is tracked as GAP-0016 / GAP-0019.

## Scoring Methodology

Risk scores use `Risk Score = Impact(1-5) x Likelihood(1-5) x 4`, producing a 0-100 scale.

| Scale | 1 | 2 | 3 | 4 | 5 |
|-------|---|---|---|---|---|
| Impact | Hardening | Info leak | Data tampering | PII/credential leak / auth bypass | RCE / priv-esc / cross-tenant |
| Likelihood | Theoretical | Rare / misconfig | Requires auth | Remote, constrained | Pre-auth, trivial |

Confidence: all findings are `confidence::confirmed` (verified via current source code review
with file:line evidence) except **GAP-0035** and **CI-IMG-001**, which are
`confidence::suspected` (GAP-0035 is gated behind disabled telemetry; CI-IMG-001 awaits a
registry-state check). GAP-0018 is `confidence::confirmed` — the `zig fetch` hash mismatch
was reproduced.
