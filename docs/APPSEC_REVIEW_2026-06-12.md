# Application Security Code Review — `devnw/zig/auth`

**Reviewer:** AppSec code review (defensive, evidence-first)
**Date:** 2026-06-12
**Standards:** OWASP Top 10:2025, CIS Controls v8.1.2
**Repo:** `/home/benji/src/gl/gitlab.com/devnw/zig/auth` @ `main` (`3605f87`)
**Toolchain:** Zig 0.16.0 (verified `zig version`)

---

## 1. Scope & Assumptions

**In scope (all read in full):** `src/api_keys.zig`, `src/hmac.zig`, `src/mfa.zig`, `src/observability.zig`, `src/observability_init.zig`, `src/root.zig`; `tests/integration.zig`, `tests/observability_disabled_test.zig`, `tests/observability_enabled_test.zig`; `examples/basic.zig`; `build.zig`, `build.zig.zon`, `.gitlab-ci.yml`; `scripts/detect_diamond_deps.py`, `scripts/sync_diamond_deps.py`; `.pre-commit-config.yaml`, `.gitleaks.toml`; `docs/REQUIREMENTS.md`, `docs/SECURITY_GAP_ANALYSIS.md`, `SECURITY.md`, `README.md`.

**Assumptions / notes:**

- **`docs/SECURITY_GAP_ANALYSIS.md` is stale.** It was committed in `80458c0 "extract auth primitives ... with full audit remediation"` and its line numbers (e.g. `src/mfa.zig:102-107`, `src/api_keys.zig:137-163`) point to **pre-remediation** code. I verified each of its 13 findings (SEC-001…SEC-013) against the *current* tree and report only what current code shows. Most of those findings **are genuinely remediated** (documented in §5); I do not re-report them. Two are **not fully resolved** and are re-reported with fresh evidence.
- I verified RNG semantics by reading the Zig 0.16 stdlib (`std/Io.zig`, `std/Io/Threaded.zig`) rather than relying on naming. This is the basis of the top finding.
- This is a **library**; there is no running service, no network listener, no privilege boundary inside the repo. "Exploitability" is assessed from the perspective of a consuming production application and an attacker who can interact with that application or read its process memory/host.
- I did not execute the code or fuzzers. Findings are static, each with file:line evidence.

---

## 2. Executive Summary

- **Overall posture is good and materially improved over the stale gap analysis.** The hot paths use constant-time comparison (`std.crypto.timing_safe.eql`) for API-key hashes and TOTP codes, secrets are zeroized on most paths with `crypto.secureZero`, `validateKey` returns an owned value copy (no dangling pointer), `listUserKeys` deep-clones, and HKDF provides domain separation. The observability seam is carefully designed to never receive credential material and is a compile-time no-op by default.
- **Highest risk (AUTH-RNG-001, High):** all key/secret/TOTP-secret generation uses `std.Io...io().random()`, which per the stdlib contract **may use stored process-memory RNG state and silently falls back to a low-entropy seed (`pid + clock + ASLR`) if the OS entropy source is unavailable**, with no error surfaced. For a credential generator the correct primitive is `io.randomSecure()` (no fallback, fresh syscall). On a healthy Linux host the practical risk is low; under early boot / constrained containers / seccomp it produces guessable secrets and recovery codes.
- **Recovery ("scratch") codes are weak (AUTH-MFA-002, High):** each code carries only **40 bits** of entropy (8 chars × 5 bits) **and there is no verification path for them at all** — `mfa.zig` generates scratch codes but exposes no function to consume/verify/invalidate them, so a consumer cannot implement single-use semantics. They are effectively decorative.
- **TOTP has no replay protection (AUTH-MFA-003, Medium)** and the **verification window is asymmetric/observable** — design-level gaps a consumer cannot easily compensate for because the needed state (last-used step) is not exposed.
- **API-key secret hashing uses bare SHA-256 (AUTH-AKEY-001, Medium):** acceptable *only because* the secret is a full 32-byte CSPRNG value, but there is no server-side pepper, so a stolen key store is directly usable and offers no defense-in-depth.
- **Supply chain has two concrete issues (Medium/Low):** the `otel` dependency's pinned `ref=v0.1.10` **disagrees with its `hash` (`otel-0.1.9-…`)** in `build.zig.zon`, and `minimum_zig_version = "0.15.1"` is wrong (the code requires 0.16 `std.Io`). CI security tooling (SAST, gitleaks, SBOM, dependency scanning, SHA-256-verified Zig download) is otherwise strong.
- **API-misuse resistance is the weakest design axis:** `MfaConfig.deterministic` is a single bool that, if ever set true in production, **completely destroys MFA security** (TOTP secret derived deterministically from public `username + default public salt`). It is guarded only by a doc-comment.

No Critical findings in the current code. The two Criticals in the stale doc (deterministic-by-default secrets; no zeroization) are remediated; the residual risk is the **misuse switch** that re-enables the deterministic path, tracked as AUTH-MFA-001.

---

## 3. Findings Table

| ID | Title | Severity | OWASP / CWE | Location |
|----|-------|----------|-------------|----------|
| AUTH-RNG-001 | Key/secret/TOTP-secret generation uses fallible `io.random()` (process-memory state + silent low-entropy fallback) instead of `randomSecure()` | **High** | A02 Security Misconfiguration / A04 Cryptographic Failures · CWE-330, CWE-338 | `api_keys.zig:111-112`, `mfa.zig:135` |
| AUTH-MFA-002 | Recovery (scratch) codes: ~40-bit entropy **and no verification/consumption API** | **High** | A07 Authentication Failures · CWE-330, CWE-654 | `mfa.zig:173-184`, `mfa.zig` (no verify fn) |
| AUTH-MFA-001 | `deterministic` config switch fully defeats MFA if enabled in prod; default public salt; guarded only by comment | **Medium** | A06 Insecure Design / A07 · CWE-1188, CWE-330 | `mfa.zig:36-40`, `mfa.zig:128-138` |
| AUTH-AKEY-001 | API-key secret hashed with bare SHA-256, no server pepper/KDF | **Medium** | A04 Cryptographic Failures · CWE-916 | `api_keys.zig:116`, `api_keys.zig:181` |
| AUTH-MFA-003 | No TOTP replay protection; asymmetric verification window; last-used step not exposed | **Medium** | A07 Authentication Failures · CWE-294 | `mfa.zig:231-265` |
| AUTH-SUP-001 | `otel` dependency `ref` (v0.1.10) disagrees with pinned `hash` (otel-0.1.9-…) | **Medium** | A03 Software Supply Chain Failures · CWE-1357 | `build.zig.zon:13-14` |
| AUTH-AKEY-002 | `validateKey` returns map value copy with **borrowed `name`/`scopes` slices** that mutate/free under the lock after return | **Medium** | A04 / CWE-362, CWE-825 | `api_keys.zig:212`, `:187-213` |
| AUTH-OBS-001 | otel seam permanently hard-disabled (`enabled=false`); auth security events cannot be emitted even with `-Dwith_otel=true` | **Low** | A09 Logging & Alerting Failures · CWE-778 | `observability.zig:44` |
| AUTH-SUP-002 | `minimum_zig_version = "0.15.1"` understates the real 0.16 requirement | **Low** | A03 / CWE-1104 | `build.zig.zon:5` |
| AUTH-MFA-004 | `base32Encode` emits no-padding output but decoder requires 8-char blocks; round-trip silently zero-pads (length confusion) | **Low** | A04 / CWE-131 | `mfa.zig:61-95` |
| AUTH-DOS-001 | `computeRecordHmac` hard-caps at 128 props returning an error (good), but callers feeding untrusted prop counts get a functional DoS with no streaming path | **Info** | A10 Mishandling Exceptional Conditions · CWE-400 | `hmac.zig:60-69` |
| AUTH-AKEY-003 | `parseBearerToken` returns a slice aliasing caller memory; no length cap on token | **Info** | A04 / CWE-doc | `api_keys.zig:436-443` |

---

## 4. Finding Details

### AUTH-RNG-001 — Credential generation uses `io.random()`, not `io.randomSecure()` (High)

**Evidence — API keys (`src/api_keys.zig:108-112`):**

```zig
// Generate cryptographically random token ID and secret.
var id: [TOKEN_ID_SIZE]u8 = undefined;
var secret: [SECRET_SIZE]u8 = undefined;
std.Io.Threaded.global_single_threaded.io().random(&id);
std.Io.Threaded.global_single_threaded.io().random(&secret);
```

**Evidence — TOTP secret (`src/mfa.zig:135`):**

```zig
} else {
    std.Io.Threaded.global_single_threaded.io().random(secret);
}
```

**Why this matters — verified against the Zig 0.16 stdlib.** `Io.random` is documented (`std/Io.zig:2456-2470`):
> "The implementation *may* store RNG state in process memory… The randomness is seeded by `randomSecure`, **or a less secure mechanism upon failure**."

The `Threaded` implementation (`std/Io/Threaded.zig:16942-16964`) lazily seeds a userspace `DefaultCsprng` (ChaCha) once, then `fill`s from it. On seed failure it calls `fallbackSeed` → `fallbackSeedPosix` (`:16978-16993`), which seeds **only** from `getpid()`, `clock_gettime(REALTIME)` seconds+nanoseconds, and the caller's ASLR address — **and surfaces no error to the caller**. By contrast `io.randomSecure()` (`std/Io.zig:2472-2487`): "Always makes a syscall… Does not rely on stored RNG state. Does not have any fallback mechanisms; returns `error.EntropyUnavailable` if any problems occur."

**Impact.** In a credential generator, the difference is security-load-bearing. If the OS entropy source is unavailable (early boot, minimal containers, certain sandboxes/seccomp policies, some VM/CI environments), `io.random()` silently produces token IDs, 32-byte API-key secrets, **and 20-byte TOTP secrets** derived from a ~few-dozen-bit, attacker-correlatable seed (pid + wall-clock + ASLR). Because nothing fails, the consuming app has no signal that its keys are predictable. Secondarily, reusing in-process CSPRNG state (vs. a fresh syscall) is a weaker posture for long-lived signing/credential material and is the exact distinction the stdlib draws.

**Exploit scenario.** A CI job or a freshly-booted minimal container provisions the first batch of API keys / enrolls the first MFA users before the kernel CSPRNG is fully seeded; entropy probe fails; `fallbackSeedPosix` seeds the PRNG from pid+clock. An attacker who can observe approximate issuance time and constrain pid brute-forces the seed space offline and reconstructs issued secrets/TOTP seeds.

**Remediation.** Use the no-fallback primitive and propagate failure (this is a credential path — failing closed is correct):

```zig
// api_keys.createKey — make the fn already-`!`, so just bubble the error:
try std.Io.Threaded.global_single_threaded.io().randomSecure(&id);
try std.Io.Threaded.global_single_threaded.io().randomSecure(&secret);

// mfa.generateSecret (random branch):
try std.Io.Threaded.global_single_threaded.io().randomSecure(secret);
```

Add a unit/integration assertion that secret generation returns `error.EntropyUnavailable` rather than weak bytes when entropy is denied (can be simulated with the `Io.failing` instance, `std/Io.zig:2512`, whose `randomSecure` always errors).

---

### AUTH-MFA-002 — Recovery codes are low-entropy and have no verification path (High)

**Evidence (`src/mfa.zig:173-184`):**

```zig
while (allocated < config.scratch_code_count) : (allocated += 1) {
    const code = try allocator.alloc(u8, 8);
    var scratch_bytes: [8]u8 = undefined;
    ...
    HkdfSha256.expand(&scratch_bytes, info, prk);
    for (0..8) |j| {
        code[j] = BASE32_ALPHABET[@as(usize, scratch_bytes[j] & 0x1F)];
    }
    scodes[allocated] = code;
}
```

**Two distinct problems:**

1. **Entropy.** Each character is `scratch_bytes[j] & 0x1F` → one of 32 symbols → **5 bits/char × 8 chars = 40 bits per code**. Default `scratch_code_count = 2` (`mfa.zig:34`). 40 bits is below the ≥ ~64-bit bar expected for an authentication recovery secret, and recovery codes are an MFA-bypass credential. Worse, all codes for an enrollment derive from the same `prk` via `HKDF-expand(prk, "scratch-code-{d}")`, and `prk = HKDF-extract(salt, raw_secret)` — so in **deterministic mode** (AUTH-MFA-001) the recovery codes are fully predictable from public inputs.

2. **No verification API.** `mfa.zig` exports `enroll`, `generateCode`, `verifyCode`, `base32Encode/Decode` — **but nothing that accepts a recovery code**. There is no `verifyScratchCode`, no consumed-set, no single-use bookkeeping. A consumer is handed `Enrollment.scratch_codes` with no supported way to verify one against an account, and certainly no way to enforce single-use. Either consumers roll their own comparison (likely non-constant-time, likely multi-use) or the codes are dead weight. This is a missing security control (CWE-654 / CWE-1390-adjacent).

**Impact.** MFA-recovery — the highest-value bypass path in any MFA system — is both guessable (40 bits, and predictable under the misuse switch) and unenforceable (no single-use). An attacker who obtains one recovery code can likely reuse it; an attacker who can grind 2^40 against an account with weak rate limiting can bypass MFA.

**Remediation.**

- Generate recovery codes from `randomSecure` (see AUTH-RNG-001), not HKDF-of-secret, so they are independent of the TOTP secret. Target ≥ 128 bits per code (e.g. 10 base32 chars × ~5 bits ≈ 50 bits is still low — prefer 20+ chars or hex of 16 random bytes).
- **Store only hashes** of recovery codes in the `Enrollment`/account model and expose `verifyScratchCode(stored_hashes, presented) -> ?index` using `timing_safe.eql`, plus a consumed-flag so verification is single-use.
- Document that recovery codes are MFA-bypass credentials and must be hashed at rest.

---

### AUTH-MFA-001 — `deterministic` switch defeats MFA; default public salt (Medium)

**Evidence (`src/mfa.zig:36-40`):**

```zig
/// If true, derive the secret deterministically from username + salt
/// (for testing only). If false (default), generate a random secret.
deterministic: bool = false,
/// Salt for deterministic derivation. Ignored when `deterministic` is false.
salt: []const u8 = "auth-mfa-salt-v1",
```

**(`src/mfa.zig:128-138`):**

```zig
fn generateSecret(allocator: Allocator, username: []const u8, config: MfaConfig) ![]u8 {
    const secret = try allocator.alloc(u8, 20);
    if (config.deterministic) {
        var prk = HkdfSha256.extract(config.salt, username);
        defer crypto.secureZero(u8, &prk);
        HkdfSha256.expand(secret[0..20], "totp-secret-v1", prk);
    } else { ... }
}
```

**Why this matters.** This is the **remediated** form of the stale doc's Critical SEC-001 — the default is now random, which is correct and good. The residual risk is **API misuse resistance**: a single boolean field flips the entire library from secure to fully broken. If `deterministic = true` reaches production (copy-paste from a test, a config that defaults the struct field through deserialization, a "make tests reproducible" toggle that leaks), then **every user's TOTP secret = `HKDF(username, "auth-mfa-salt-v1")`** — computable by anyone, since both inputs are public (the salt is a hardcoded constant). The same switch makes recovery codes (AUTH-MFA-002) predictable. There is no runtime guard, no build-mode gate, no separate type — only a doc comment (`mfa.zig:9-11`, `:37`).

**Impact.** Total MFA bypass for all users if the flag is ever true in a real deployment. Likelihood is "misuse," but the blast radius is complete, and the library makes the unsafe state reachable with `.{ .deterministic = true }`.

**Remediation (defense by construction):**

- Gate the deterministic branch behind `builtin.is_test` (or a `comptime` build option) so it physically cannot run in a release build:

  ```zig
  if (config.deterministic) {
      if (!@import("builtin").is_test) @compileError("deterministic MFA secrets are test-only");
      ...
  }
  ```

  (If runtime configurability is required, at minimum require a distinct non-default salt and log a loud warning, and rename the field to `INSECURE_deterministic_testing_only`.)
- Never ship a usable default salt; if deterministic mode survives, make `salt` have no default so the caller must supply one.

---

### AUTH-AKEY-001 — API-key secret stored as bare SHA-256, no pepper/KDF (Medium)

**Evidence (`src/api_keys.zig:114-116`):**

```zig
var secret_hash: [32]u8 = undefined;
crypto.hash.sha2.Sha256.hash(&secret, &secret_hash, .{});
```

**Verify side (`src/api_keys.zig:180-181`, `:198`):**

```zig
crypto.hash.sha2.Sha256.hash(&parsed.secret, &provided_hash, .{});
...
if (!std.crypto.timing_safe.eql([32]u8, provided_hash, key.secret_hash)) {
```

**Why this matters.** Fast bare SHA-256 over a credential is normally a CWE-916 problem. Here it is **partially mitigated** because the secret is a full 32-byte CSPRNG value (`SECRET_SIZE = 32`), so offline brute force is infeasible regardless of hash speed — that's a deliberate, defensible design choice and the constant-time compare is correct. **However**, there is no server-side pepper/HMAC key. Consequence: a read-only disclosure of the key store (backup leak, SQLi-style read, log of the struct) yields `secret_hash` values that an attacker can match offline against captured key strings without any additional secret, and there is zero defense-in-depth if a future change ever shortens the secret or accepts user-influenced key material.

**Impact.** Medium: no break today given 32-byte random secrets, but the construction provides no margin and no pepper, so a store leak is directly correlatable and a single upstream change (shorter secret, imported keys) would turn this into a real offline-cracking exposure.

**Remediation.** Replace `Sha256.hash(secret)` with `HMAC-SHA256(server_pepper, secret)` (the `hmac` module in this very repo already wraps `HmacSha256`), where `server_pepper` is a deployment secret held outside the key store. This keeps verification O(1) (fine for high-entropy secrets) while ensuring a store leak alone is not usable.

---

### AUTH-MFA-003 — No TOTP replay protection; asymmetric, observable window (Medium)

**Evidence (`src/mfa.zig:231-265`):**

```zig
pub fn verifyCode(allocator, secret_base32, timestamp_ms, code, config) !bool {
    ...
    var idx: i32 = -config.window;
    while (idx <= config.window) : (idx += 1) {
        const t = if (idx < 0) blk: {
            const delta_ms = @as(u64, @intCast(-idx)) * config.step_seconds * 1000;
            if (delta_ms > timestamp_ms) continue;           // (a)
            break :blk timestamp_ms - delta_ms;
        } else blk: {
            break :blk timestamp_ms + @as(u64, @intCast(idx)) * config.step_seconds * 1000;
        };
        const candidate = generateCodeFromRaw(secret_raw, t, config);
        const candidate_bytes = std.mem.toBytes(candidate);
        if (std.crypto.timing_safe.eql([4]u8, code_bytes, candidate_bytes)) {
            match = true;                                     // (b) no early return — good
        }
    }
    ok = match;
    return match;
}
```

**What's correct:** comparison is constant-time (`timing_safe.eql`, remediating stale SEC-003), the loop does **not** early-return on match (avoids a timing oracle on *which* window matched), and the secret is decoded once and zeroized (`:237-241`).

**Gaps:**

1. **No replay protection (CWE-294).** A valid code is accepted on every call within its window. The function is stateless and exposes no "last accepted step," so a consumer **cannot** implement single-use even if they want to — the needed state is hidden. A captured code is replayable for up to `(2*window+1)` steps (default 90 s).
2. **Asymmetric window.** Branch (a) skips past-windows when `delta_ms > timestamp_ms` (only relevant for near-epoch timestamps), so for tiny clocks the accepted set is asymmetric; minor, but the window semantics differ from a clean `[-window, +window]` over `timestep`.
3. **Window applied in milliseconds around `timestamp_ms` then re-divided** — correct here, but means callers passing already-stepped values would misbehave; not exploitable, noted for API clarity.

**Impact.** Within a 30–90 s window an intercepted/over-the-shoulder code is reusable — the canonical TOTP replay weakness. Medium because it requires code interception and a short window, and because the library *prevents* the consumer from fixing it.

**Remediation.** Return the matched timestep on success (e.g. `?u64` of the accepted step) so the caller can persist and reject `step <= last_used_step`. Provide a documented `verifyCodeOnce(..., last_used_step: *u64)` helper that enforces monotonic step advancement.

---

### AUTH-SUP-001 — `otel` dependency `ref`/`hash` disagree (Medium)

**Evidence (`build.zig.zon:12-16`):**

```zig
.otel = .{
    .url = "git+https://gitlab.com/devnw/zig/otel.git?ref=v0.1.10#a1afbfe672d5c0894969d0aa49efa7a66510eda3",
    .hash = "otel-0.1.9-B0v3ltxeNgB4mGDRS7r1dapusir8f7_ISb-MvzYltW1h",
    .lazy = true,
},
```

The URL pins **ref `v0.1.10`** and commit `a1afbfe…`, but the content `hash` encodes **`otel-0.1.9-…`**. The recent commit log (`16216b8 "converge tls onto v0.1.9 (GAP-0838 diamond sync)"`, `3605f87 "add sync_diamond_deps diamond auto-resolver"`) shows active automated pin-rewriting, which is exactly the kind of process that produces a tag/hash skew.

**Why this matters.** Zig verifies the fetched content against `hash`, so a *mismatched* hash means either (a) the build fails to fetch (the `v0.1.10` tree won't match a `0.1.9` hash) — a reliability break — or (b) if `v0.1.10` and the `0.1.9`-named tarball coincidentally share content, the human-readable version label is now lying, defeating the integrity/audit value of the pin. Either way the pin is internally inconsistent and undermines the supply-chain control it exists to provide (CIS v8.1.2: trusted/inventoried third-party components). This dependency is `lazy` and only fetched under `-Dwith_otel=true`, which lowers exposure (and given AUTH-OBS-001 it is effectively never built), but a future enablement will hit it.

**Remediation.** Re-run `zig fetch git+https://gitlab.com/devnw/zig/otel.git?ref=v0.1.10` and paste the **emitted** hash so `ref`, commit, and `hash` all describe one tree. Add a CI check (or extend `detect_diamond_deps.py`) that asserts the version label embedded in each `hash` matches the `ref` in the same entry.

---

### AUTH-AKEY-002 — `validateKey` returns borrowed `name`/`scopes` that the manager still owns (Medium)

**Evidence (`src/api_keys.zig:184-213`):**

```zig
self.mutex.lockUncancelable(...);
defer self.mutex.unlock(...);
const key = self.keys.getPtr(parsed.id) orelse return null;
...
key.last_used_at = ...;
...
ok = true;
return key.*;          // value copy of ApiKey
```

`ApiKey` (`:34-44`) contains `name: []const u8` and `scopes: []const []const u8` — **pointers into manager-owned heap allocations**. `return key.*` shallow-copies the struct: the returned `ApiKey`'s `name`/`scopes` still alias the map's allocations. The pointer-level dangling bug from stale SEC-004 is fixed (a value is returned, not `*ApiKey`), but **the slices inside that value are not deep-copied** (unlike `listUserKeys`, which correctly dupes at `:312-314`).

**Why this matters.** After `validateKey` returns and the lock is released, another thread calling `revokeKey`/`cleanupExpired`/`deinit` can `fetchRemove` that entry and `freeScopes`/`free(name)` (`:351-353`, `:77-81`). The previously-returned `ApiKey`'s `name`/`scopes` now point to freed memory → use-after-free / CWE-825 read of `k.name`, `k.scopes` (e.g. in `hasScope`, which iterates `key.scopes` at `:228`). The struct is documented as "a copy of the associated key info" (`:153`), so callers will reasonably read those fields after releasing the conceptual borrow.

**Impact.** Concurrency-dependent UAF when a key is validated and concurrently removed; reads of attacker-influenced freed memory during authorization (`hasScope`). Medium: requires concurrent revoke/cleanup, but this is a thread-safe-by-design manager (`std.Io.Mutex`) whose whole point is concurrent use.

**Remediation.** Deep-copy on return, mirroring `listUserKeys`, and give callers a `freeValidatedKey`. Or return a struct that excludes the heap slices (e.g. only `id`, `user_id`, `expires_at`, fixed-size scope flags). Document ownership explicitly.

---

### AUTH-OBS-001 — Security-event telemetry permanently disabled (Low)

**Evidence (`src/observability.zig:36-46`):**

```zig
// 2026-05-02: hardcoded enabled=false and removed the build_options
// import ... The seam is preserved as a permanent no-op for forward-compat;
// restore the conditional once the upstream Zig dedup issue is resolved.
pub const enabled: bool = false;
```

`Span` (`:52-56`) and all helpers then collapse to no-ops, so `startAuthnSpan/endAuthnSpan/startAuthzSpan/endAuthzSpan` emit nothing **regardless of `-Dwith_otel`**. Note `tests/observability_enabled_test.zig:30` and `tests/observability_disabled_test.zig` both `return error.SkipZigTest` unless `enabled`, so the "enabled" test never actually runs — the enabled path is currently untested.

**Why this matters (A09 / CIS audit-log controls).** The auth call sites are wired to record authn/authz successes and failures (`api_keys.zig:99,163,224`; `mfa.zig:149,232`), which is good design for detecting credential abuse and authz probing. But because `enabled` is hard-`false`, **a consumer who deliberately sets `-Dwith_otel=true` still gets zero auth security events.** The instrumentation is dead. For a credential library, loss of authentication-failure/authz-denial signal is a logging-and-alerting gap.

**Impact.** Low directly (a consumer can log around the library), but it silently nullifies an advertised security-observability feature and leaves the enabled path unexercised by tests.

**Remediation.** Restore `enabled = build_options.with_otel` once the Zig 0.16 module-dedup issue is resolved, or document prominently that telemetry is currently inert so consumers know they must add their own auth-event logging. Make at least one enabled-mode test run in CI (a `-Dwith_otel=true` job) so the path is covered.

---

### AUTH-SUP-002 — `minimum_zig_version` understated (Low)

**Evidence (`build.zig.zon:5`):** `.minimum_zig_version = "0.15.1",` while the code pervasively uses `std.Io.Mutex`, `std.Io.Threaded.global_single_threaded`, `std.Io.Timestamp` (`api_keys.zig:60,67,111,119`), which are **0.16** APIs; CI pins `ZIG_VERSION: "0.16.0"` (`.gitlab-ci.yml:27`); commit history is full of "zig 0.16.0 compat" fixes. A consumer on 0.15.x will get cryptic compile failures instead of a clean version error.

**Impact.** Low (build-time, not runtime), but a misleading floor weakens the toolchain-integrity story (CIS supported-components). **Remediation:** set `.minimum_zig_version = "0.16.0"`.

---

### AUTH-MFA-004 — Base32 length confusion between encoder and decoder (Low)

**Evidence (`src/mfa.zig:61-95`).** `base32Encode` always emits `((raw.len + 4) / 5) * 8` chars with **no padding** and zero-pads the final partial group's bits. `base32Decode` requires `encoded.len % 8 == 0` (`:89`) and produces `(len/8)*5` bytes, so a 20-byte secret (multiple of 5) round-trips exactly — the production path is fine. But for non-mod-5 inputs the decoder returns trailing zero bytes the caller must know to trim (the test at `:280-281` documents this: `decoded[0..raw.len]`). This is the remediated-but-still-sharp form of stale SEC-012.

**Impact.** Low. No break for the 20-byte TOTP secret. But the asymmetric contract (no-padding encode, block-strict decode, silent zero-pad) is a latent correctness/length-confusion hazard (CWE-131) for any consumer who base32s other data through these helpers. **Remediation:** either implement RFC 4648 padding on encode and accept/strip it on decode, or return the true decoded length so callers don't guess.

---

### AUTH-DOS-001 — HMAC property cap (Info)

**Evidence (`src/hmac.zig:60-69`):** `computeRecordHmac` returns `error.TooManyProperties` for `> 128` props (stack-only, no allocation). This is the **remediated** form of stale SEC-006 (`@panic` → error) and is good — no DoS-by-panic. Noted only because a consumer passing attacker-controlled property counts gets a hard functional ceiling with no streaming/heap fallback; if record sizes are adversary-controlled, document the 128 cap as a contract. No action required beyond awareness.

### AUTH-AKEY-003 — `parseBearerToken` aliasing + no length cap (Info)

**Evidence (`src/api_keys.zig:436-443`):** returns `auth_header[prefix.len..]` trimmed — a slice **into the caller's buffer**, not a copy. Correct and zero-alloc, but undocumented aliasing; a caller that frees/reuses the header invalidates the token. No size bound on the returned token (downstream `parseApiKey` bounds it via base64 size checks, so not exploitable here). Document that the result borrows the input.

---

## 5. Secure Design Notes (what the code does well)

The current tree has clearly absorbed a remediation pass. Concretely verified:

- **Constant-time comparison on all secret comparisons.** API-key hash compare uses `std.crypto.timing_safe.eql([32]u8, …)` (`api_keys.zig:198`); TOTP compare uses `timing_safe.eql([4]u8, …)` over byte arrays (`mfa.zig:259`); HMAC verify uses `timing_safe.eql` (`hmac.zig:130`). This remediates stale SEC-003/SEC-014.
- **Secret zeroization is broadly applied.** `crypto.secureZero` on the API-key plaintext secret (`api_keys.zig:117`), parsed secret (`:173`), provided hash (`:182`); on the TOTP raw secret (`mfa.zig:155-157,193-196,238-241`), HKDF `prk` (`:132,171`), scratch bytes (`:176`), and HMAC output `h` (`:208`); on HKDF `prk` in `deriveHmacKey` (`hmac.zig:44`); and `Enrollment.deinit` zeroizes `secret_base32` before free (`mfa.zig:50`). This remediates stale SEC-002 on the paths I traced. (Minor residual: the base32 `secret_base32` returned from `enroll` lives until the caller calls `deinit`; that's by design and the deinit zeroizes it.)
- **`validateKey` no longer returns a raw `*ApiKey`** (returns `key.*` value, `:212`) — the dangling-*pointer* class of stale SEC-004 is gone (the residual slice-aliasing issue is AUTH-AKEY-002).
- **`listUserKeys` deep-clones** `name` and `scopes` with correct partial-failure cleanup (`:300-319`), remediating stale SEC-005.
- **Careful allocation/error-path hygiene.** `createKey` formats the key string *before* inserting into the map with layered `errdefer`s (`:122-147`); `dupeScopes`/`freeScopes` handle partial failure (`:361-378`); `cleanupExpired` collects-then-removes to avoid iterator invalidation (`:336-356`). Tests run under `std.testing.allocator` (leak-checked) across unit + integration + ReleaseSafe/Fast/Small CI matrices.
- **HKDF domain separation** with configurable salt/info (`hmac.zig:42-48`, `mfa.zig` deterministic path), and **length-prefixed, key-sorted, count-bound** record/chain HMAC encoding that is explicitly designed against truncation and ambiguity attacks (`hmac.zig:50-123`).
- **Observability seam is security-conscious by construction.** It only ever receives method labels, action/resource policy vocabulary, and the post-success subject id; failed auth attaches **no** subject id (`observability.zig:157-170`); the design doc and tests assert credentials never enter the seam (`observability.zig:12-27`, both observability tests). The default build compiles it to a comptime no-op.
- **Strong CI/supply-chain baseline.** GitLab CI includes SAST, dependency scanning, secrets + gitleaks, SBOM generate/scan, and a **SHA-256-verified** Zig toolchain download against the signed `ziglang.org` index (`.gitlab-ci.yml:38-77`). Dependencies are hash-pinned and the `otel` dep is `lazy`. Pre-commit runs shellcheck, ruff, a private-key detector, large-file guard, and a custom diamond-dependency integrity check. The Python diamond tooling is careful (comment-aware tokenizer, no `eval`, no shell-injection in the detector).

---

## 6. Coverage Gaps & Questions

- **Runtime RNG behavior unconfirmed.** I established the `io.random()` fallback semantics from the stdlib source (strong evidence) but did not run a test under simulated entropy starvation. Recommend an `Io.failing`-backed test to confirm AUTH-RNG-001's failure mode empirically.
- **Recovery-code lifecycle.** I confirmed there is **no** scratch-code verification function in `mfa.zig`. If consumption is expected to live in a *consumer* repo (e.g. Geode), that's out of this repo's scope — but then this library ships an unusable credential. Question for the owner: where is recovery-code verification meant to happen, and is single-use enforced there?
- **`otel` pin.** I did not fetch the remote to confirm whether `v0.1.10` and the `0.1.9` hash actually resolve to the same tree; flagged as inconsistent on its face. Please run `zig fetch …?ref=v0.1.10` and reconcile.
- **`scripts/sync_diamond_deps.py` (`--apply`/`--cascade`)** auto-commits/tags/pushes across sibling repos and rewrites `build.zig.zon` pins via regex. It is maintainer-run, not in the library's trust boundary, but it is a **supply-chain-mutating automation**: a bug in `rewrite_pin` (regex `.url`/`.hash` substitution, `:231-262`) or a mis-resolved `zig_pkg_hash` could silently land an unintended pin. Out of scope to audit exhaustively here; recommend a separate review since it directly writes the integrity-bearing `build.zig.zon`. No injection found in the paths I read (`subprocess.run` uses list-args, no `shell=True`).
- **Concurrency model.** `std.Io.Mutex` + `global_single_threaded` IO are used together; I reviewed the lock discipline statically (locks held around map mutation; AUTH-AKEY-002 is the one return-after-unlock aliasing issue). I did not run ThreadSanitizer/race testing.
- **No threat model document** ships with the repo (`docs/SECURITY_GAP_ANALYSIS.md` is stale and project-mislabeled in places). A current threat model would sharpen severity assignments.

---

## 7. Prioritized Next Actions

1. **AUTH-RNG-001 (High) — switch credential generation to `io.randomSecure()` and propagate `error.EntropyUnavailable`.** Three call sites (`api_keys.zig:111-112`, `mfa.zig:135`, and recovery-code generation). Add an entropy-starvation test. *Fail closed on a credential path.*
2. **AUTH-MFA-002 (High) — fix recovery codes:** generate from `randomSecure` independent of the TOTP secret, raise to ≥128-bit, store hashed, and **add a constant-time, single-use `verifyScratchCode` API.** Without a verify path these codes are unusable security theater.
3. **AUTH-MFA-001 (Medium) — make the deterministic path unreachable in release builds** (`@compileError` under `!builtin.is_test`) or, if it must stay runtime-toggleable, remove the default salt and rename the field to scream "insecure/test-only."
4. **AUTH-AKEY-002 (Medium) — deep-copy `name`/`scopes` in `validateKey`** (mirror `listUserKeys`) and document ownership + a `freeValidatedKey`.
5. **AUTH-AKEY-001 (Medium) — pepper the API-key hash:** `HMAC-SHA256(server_pepper, secret)` using the repo's own `hmac` module; keep the existing constant-time compare.
6. **AUTH-MFA-003 (Medium) — return the matched timestep so consumers can implement TOTP replay rejection;** ship a `verifyCodeOnce(..., last_used_step)` helper.
7. **AUTH-SUP-001 (Medium) — reconcile the `otel` `ref`/`hash`** and add a CI assertion that the hash's embedded version matches the URL `ref`.
8. **AUTH-OBS-001 / AUTH-SUP-002 / AUTH-MFA-004 (Low) — restore (or clearly document) the disabled telemetry seam and run an enabled-mode CI job; set `minimum_zig_version = "0.16.0"`; make base32 padding symmetric or return the true decoded length.**
9. **Hygiene — regenerate `docs/SECURITY_GAP_ANALYSIS.md`** against the current tree (it is stale and partially mislabeled) so it stops asserting already-fixed Criticals and reflects the findings above.

**Bottom line:** No confirmed Critical vulnerabilities in the current code; the prior Criticals are remediated. The library is close to shippable for a healthy-host deployment, but for a credential library I would not ship until **AUTH-RNG-001** (fail-closed secure RNG) and **AUTH-MFA-002** (real, single-use, high-entropy recovery codes) are fixed, and **AUTH-MFA-001** is made unreachable in production builds.
