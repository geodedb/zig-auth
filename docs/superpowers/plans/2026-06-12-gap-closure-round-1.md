# Gap Closure Round 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all actionable gaps from the 2026-06-12 audit (GAP-0002..GAP-0045, GitLab #55–#89 plus kept-open #12/#13/#14/#23/#28/#30/#35/#36/#40/#43/#44) with real code, tests, and docs, so the next `/security:appsec-review` + `/codepros:audit` round finds no new issues.

**Architecture:** Zig 0.16.0 library, three core modules (`src/api_keys.zig`, `src/mfa.zig`, `src/hmac.zig`) plus an inert observability seam. Changes are grouped per-module to minimize cross-task conflicts: MFA hardening first (config validation, secure RNG, recovery codes, replay protection, base32 padding), then API-key manager hardening (thread-safe mutex, owned returns, pepper, lock hygiene), then HMAC determinism, then docs/meta/CI. Breaking API changes are acceptable (0.x library): `validateKey` returns owned copies, scratch codes become 32 chars, `enroll`/`generateCode`/`verifyCode` gain config validation errors.

**Tech Stack:** Zig 0.16.0 (`zig build test`, `zig build test-integration`, `zig fmt`), pre-commit, GitLab CI, `glab` CLI.

**Verification commands (used by every task):**

- `zig build test --summary all` → expect all pass (counts grow as tasks add tests)
- `zig build test-integration --summary all` → expect 12+ pass
- `zig fmt --check src/ tests/ examples/ build.zig` → exit 0

**Commit convention:** conventional commits, one commit per task, message ends with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`. Pre-commit hooks run automatically; if a hook auto-fixes files, re-stage and re-commit.

---

## Task 1: MFA config validation + comptime TOTP constants (GAP-0030 #74, GAP-0031 #75, GAP-0043 #87, GAP-0044 #88)

**Files:**

- Modify: `src/mfa.zig`

- [x] **Step 1: Write failing tests** — append to the test section of `src/mfa.zig`:

```zig
test "MfaConfig validation rejects digits=0 (silent MFA bypass)" {
    const allocator = std.testing.allocator;
    const cfg = MfaConfig{ .deterministic = true, .digits = 0 };
    try std.testing.expectError(error.InvalidMfaConfig, enroll(allocator, "mallory", cfg));
    try std.testing.expectError(error.InvalidMfaConfig, generateCode(allocator, "MZXW6YTBMZXW6YTBMZXW6YTBMZXW6YTB", 1_700_000_000_000, cfg));
    try std.testing.expectError(error.InvalidMfaConfig, verifyCode(allocator, "MZXW6YTBMZXW6YTBMZXW6YTBMZXW6YTB", 1_700_000_000_000, 0, cfg));
}

test "MfaConfig validation rejects out-of-range digits, step, window" {
    const allocator = std.testing.allocator;
    const secret = "MZXW6YTBMZXW6YTBMZXW6YTBMZXW6YTB";
    const ts: u64 = 1_700_000_000_000;
    // digits > 9 would overflow u32 modulus
    try std.testing.expectError(error.InvalidMfaConfig, verifyCode(allocator, secret, ts, 0, .{ .digits = 10 }));
    // digits < 6 below RFC 4226 minimum
    try std.testing.expectError(error.InvalidMfaConfig, verifyCode(allocator, secret, ts, 0, .{ .digits = 5 }));
    // step_seconds == 0 division by zero
    try std.testing.expectError(error.InvalidMfaConfig, verifyCode(allocator, secret, ts, 0, .{ .step_seconds = 0 }));
    // window < 0 silently rejects every code (lockout)
    try std.testing.expectError(error.InvalidMfaConfig, verifyCode(allocator, secret, ts, 0, .{ .window = -1 }));
    // window absurdly large risks u64 overflow in delta arithmetic
    try std.testing.expectError(error.InvalidMfaConfig, verifyCode(allocator, secret, ts, 0, .{ .window = 65 }));
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all 2>&1 | head -30`
Expected: compile error (`error.InvalidMfaConfig` never returned) or test failures.

- [x] **Step 3: Implement.** In `src/mfa.zig`:

(a) Add after the `MfaConfig` struct fields (inside the struct, after `salt`):

```zig
    /// Validate configuration invariants. Called by `enroll`,
    /// `generateCode`, `verifyCode`, and `verifyCodeOnce`.
    ///
    /// - `digits` must be 6..9: below 6 violates RFC 4226 minimum
    ///   strength; 0 would make every code `0` (modulus 1 — total MFA
    ///   bypass); above 9 overflows the u32 code space.
    /// - `step_seconds` must be nonzero (timestep division).
    /// - `window` must be 0..64: negative silently rejects every code;
    ///   larger windows defeat the purpose of TOTP and risk overflow.
    pub fn validate(self: MfaConfig) error{InvalidMfaConfig}!void {
        if (self.digits < 6 or self.digits > 9) return error.InvalidMfaConfig;
        if (self.step_seconds == 0) return error.InvalidMfaConfig;
        if (self.window < 0 or self.window > 64) return error.InvalidMfaConfig;
    }
```

(b) Add a comptime power-of-10 table at file scope (near `BASE32_ALPHABET`), replacing the runtime modulus loop:

```zig
/// 10^n for n in 0..=9 — comptime table so the TOTP modulus is a
/// single indexed load (digits are validated to 6..9).
const POW10 = [_]u32{ 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000 };
```

(c) In `generateCodeFromRaw`, replace the modulus loop (`var mod: u32 = 1; var i: u8 = 0; while (i < config.digits) : (i += 1) mod *= 10;`) with:

```zig
    const mod = POW10[config.digits];
```

and add a comptime assertion pinning the RFC 4226 assumption, right after `var h: [HmacSha1.mac_length]u8 = undefined;`:

```zig
    comptime std.debug.assert(HmacSha1.mac_length == 20); // RFC 4226 dynamic truncation reads h[19]
```

(d) Add `try config.validate();` as the FIRST statement of `enroll`, `generateCode`, and `verifyCode` (in `enroll`, place it before the span start so invalid config does not emit a span).

- [x] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all` → all pass. Run `zig fmt src/mfa.zig`.

- [x] **Step 5: Commit**

```bash
git add src/mfa.zig
git commit -m "fix(mfa)!: validate MfaConfig — reject digits=0 silent bypass and panic-inducing configs

Closes GAP-0030 (#74), GAP-0031 (#75), GAP-0043 (#87), GAP-0044 (#88)"
```

---

## Task 2: Secure RNG for all credential generation (GAP-0007 #56)

**Files:**

- Modify: `src/mfa.zig` (generateSecret), `src/api_keys.zig` (createKey)

- [x] **Step 1: Write failing test** — append to `src/mfa.zig` tests:

```zig
test "generateSecret uses randomSecure (error union surfaces)" {
    // randomSecure returns error{EntropyUnavailable,Canceled}!void; this
    // test pins the API choice: enroll must be able to surface
    // error.EntropyUnavailable instead of silently degrading.
    const allocator = std.testing.allocator;
    const e = try enroll(allocator, "secure-rng-user", .{});
    defer e.deinit(allocator);
    try std.testing.expect(e.secret_base32.len == 32);
}
```

(The behavioral guarantee is the call-site change; the type-level proof is that `enroll`'s error set now includes `EntropyUnavailable` — verified by Step 3 compiling with `try`.)

- [x] **Step 2: Implement.**

(a) `src/mfa.zig` `generateSecret` random branch — replace:

```zig
    } else {
        std.Io.Threaded.global_single_threaded.io().random(secret);
    }
```

with:

```zig
    } else {
        // Fail closed: no silent low-entropy fallback on a credential path.
        try std.Io.Threaded.global_single_threaded.io().randomSecure(secret);
    }
```

and add `errdefer allocator.free(secret);` immediately after `const secret = try allocator.alloc(u8, 20);` (the new `try` creates an error path after the alloc).

(b) `src/api_keys.zig` `createKey` — replace:

```zig
        std.Io.Threaded.global_single_threaded.io().random(&id);
        std.Io.Threaded.global_single_threaded.io().random(&secret);
```

with:

```zig
        // Fail closed: no silent low-entropy fallback on a credential path.
        try std.Io.Threaded.global_single_threaded.io().randomSecure(&id);
        try std.Io.Threaded.global_single_threaded.io().randomSecure(&secret);
```

- [x] **Step 3: Run all tests**

Run: `zig build test --summary all && zig build test-integration --summary all` → all pass.

- [x] **Step 4: Commit**

```bash
git add src/mfa.zig src/api_keys.zig
git commit -m "fix(security): use io.randomSecure for credential generation — fail closed on entropy starvation

Closes GAP-0007 (#56)"
```

---

## Task 3: Recovery codes — 160-bit, independent, hashable, single-use verifiable (GAP-0008 #57)

**Files:**

- Modify: `src/mfa.zig`, `tests/integration.zig`

- [x] **Step 1: Write failing tests** — append to `src/mfa.zig`:

```zig
test "scratch codes are 32 chars and independent of the TOTP secret" {
    const allocator = std.testing.allocator;
    const e1 = try enroll(allocator, "rc-user", .{});
    defer e1.deinit(allocator);
    for (e1.scratch_codes) |code| {
        try std.testing.expectEqual(@as(usize, 32), code.len);
        for (code) |c| try std.testing.expect((c >= 'A' and c <= 'Z') or (c >= '2' and c <= '7'));
    }
    // Deterministic enrollments must still produce DIFFERENT scratch codes
    // (codes come from the CSPRNG, not from HKDF(secret)).
    const cfg = MfaConfig{ .deterministic = true };
    const e2 = try enroll(allocator, "rc-user2", cfg);
    defer e2.deinit(allocator);
    const e3 = try enroll(allocator, "rc-user2", cfg);
    defer e3.deinit(allocator);
    try std.testing.expect(!std.mem.eql(u8, e2.scratch_codes[0], e3.scratch_codes[0]));
}

test "verifyScratchCode: constant-time match, single-use consumption" {
    const allocator = std.testing.allocator;
    const e = try enroll(allocator, "rc-verify", .{ .scratch_code_count = 3 });
    defer e.deinit(allocator);

    var hashes: [3][32]u8 = undefined;
    for (e.scratch_codes, 0..) |code, i| hashes[i] = hashScratchCode(code);
    var consumed = [_]bool{ false, false, false };

    // Correct code verifies and is consumed.
    const idx = verifyScratchCode(&hashes, &consumed, e.scratch_codes[1]);
    try std.testing.expectEqual(@as(?usize, 1), idx);
    try std.testing.expect(consumed[1]);

    // Same code again: rejected (single-use).
    try std.testing.expectEqual(@as(?usize, null), verifyScratchCode(&hashes, &consumed, e.scratch_codes[1]));

    // Wrong code: rejected.
    try std.testing.expectEqual(@as(?usize, null), verifyScratchCode(&hashes, &consumed, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));

    // Other codes still work.
    try std.testing.expectEqual(@as(?usize, 0), verifyScratchCode(&hashes, &consumed, e.scratch_codes[0]));
}
```

Also update the existing test `"enroll produces Base32 secret and scratch codes"`: change `expectEqual(@as(usize, 8), code.len)` to `expectEqual(@as(usize, 32), code.len)`.

- [x] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all 2>&1 | head -20` → compile errors (`hashScratchCode` undefined).

- [x] **Step 3: Implement.** In `src/mfa.zig`:

(a) Replace the scratch-code generation loop in `enroll` (the `prk`/HKDF block AND the while loop) with:

```zig
    // Scratch (recovery) codes are MFA-bypass credentials: generate each
    // from the CSPRNG, INDEPENDENT of the TOTP secret, at 160 bits
    // (20 random bytes -> 32 base32 chars). Store only hashes at rest
    // (see `hashScratchCode` / `verifyScratchCode`).
    while (allocated < config.scratch_code_count) : (allocated += 1) {
        var raw: [SCRATCH_CODE_RAW_LEN]u8 = undefined;
        defer crypto.secureZero(u8, &raw);
        try std.Io.Threaded.global_single_threaded.io().randomSecure(&raw);
        const code = try base32Encode(allocator, &raw);
        scodes[allocated] = code;
    }
```

(The old `var prk = HkdfSha256.extract(config.salt, raw_secret); defer crypto.secureZero(u8, &prk);` block before the loop is deleted — scratch codes no longer derive from the secret.)

(b) Add constants and the new public API near `Enrollment`:

```zig
/// Raw entropy per scratch code: 20 bytes = 160 bits.
pub const SCRATCH_CODE_RAW_LEN: usize = 20;
/// Encoded scratch-code length: 20 raw bytes -> 32 base32 chars.
pub const SCRATCH_CODE_LEN: usize = 32;

/// Hash a scratch code for at-rest storage. Store ONLY these hashes;
/// never persist plaintext recovery codes.
pub fn hashScratchCode(code: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(code, &out, .{});
    return out;
}

/// Verify a presented recovery code against stored hashes, enforcing
/// single use. Scans ALL hashes with constant-time comparison (no early
/// exit) so timing does not reveal which slot matched. On match of an
/// unconsumed slot, marks it consumed and returns its index; otherwise
/// returns null. `hashes` and `consumed` must be the same length.
pub fn verifyScratchCode(hashes: []const [32]u8, consumed: []bool, presented: []const u8) ?usize {
    std.debug.assert(hashes.len == consumed.len);
    var presented_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(presented, &presented_hash, .{});
    defer crypto.secureZero(u8, &presented_hash);

    var matched: ?usize = null;
    for (hashes, 0..) |h, i| {
        const eq = std.crypto.timing_safe.eql([32]u8, presented_hash, h);
        if (eq and !consumed[i] and matched == null) matched = i;
    }
    if (matched) |i| consumed[i] = true;
    return matched;
}
```

- [x] **Step 4: Run all tests**

Run: `zig build test --summary all && zig build test-integration --summary all` → all pass (fix any integration test asserting 8-char codes; `tests/integration.zig` MFA test asserts scratch code count only — verify).

- [x] **Step 5: Commit**

```bash
git add src/mfa.zig tests/integration.zig
git commit -m "feat(mfa)!: 160-bit CSPRNG recovery codes + single-use constant-time verifyScratchCode

Closes GAP-0008 (#57)"
```

---

## Task 4: Deterministic mode test-only gate (GAP-0016 #23)

**Files:**

- Modify: `src/mfa.zig`

- [x] **Step 1: Implementation note.** `config.deterministic` is runtime data, so a `@compileError` is impossible; the gate is `@import("builtin").is_test` — in any non-test build the deterministic branch returns an error before deriving anything. Tests continue to work unchanged (they ARE test builds).

In `src/mfa.zig` add near the imports:

```zig
const builtin = @import("builtin");
```

In `generateSecret`, at the top of the `if (config.deterministic)` branch (before the HKDF extract):

```zig
    if (config.deterministic) {
        // Deterministic secrets are derivable by anyone who knows the
        // username + salt. Physically unreachable outside `zig test`
        // builds: misuse in production would destroy MFA for all users.
        if (comptime !builtin.is_test) return error.DeterministicModeIsTestOnly;
        ...existing HKDF code...
```

Update the `deterministic` field doc comment to:

```zig
    /// TEST-ONLY: derive the secret deterministically from username +
    /// salt. Returns `error.DeterministicModeIsTestOnly` in non-test
    /// builds — this switch cannot be enabled in production.
    deterministic: bool = false,
```

- [x] **Step 2: Run all tests** (they run under `is_test`, so deterministic fixtures keep working)

Run: `zig build test --summary all && zig build && zig build test-integration --summary all` → pass. The plain `zig build` proves the library still compiles in non-test mode with the comptime branch.

- [x] **Step 3: Commit**

```bash
git add src/mfa.zig
git commit -m "fix(security): gate deterministic MFA secrets to test builds only

Closes GAP-0016 (#23)"
```

---

## Task 5: TOTP replay protection — matched step exposure + verifyCodeOnce (GAP-0017 #43)

**Files:**

- Modify: `src/mfa.zig`

- [x] **Step 1: Write failing tests** — append to `src/mfa.zig`:

```zig
test "verifyCodeStep returns the matched timestep" {
    const allocator = std.testing.allocator;
    const cfg = deterministicConfig();
    const e = try enroll(allocator, "step-user", cfg);
    defer e.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const code = try generateCode(allocator, e.secret_base32, ts, cfg);
    const step = try verifyCodeStep(allocator, e.secret_base32, ts, code, cfg);
    try std.testing.expectEqual(@as(?u64, ts / (cfg.step_seconds * 1000)), step);

    const bad = try verifyCodeStep(allocator, e.secret_base32, ts, code +% 1, cfg);
    try std.testing.expectEqual(@as(?u64, null), bad);
}

test "verifyCodeOnce rejects replay of the same step" {
    const allocator = std.testing.allocator;
    const cfg = deterministicConfig();
    const e = try enroll(allocator, "replay-user", cfg);
    defer e.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const code = try generateCode(allocator, e.secret_base32, ts, cfg);

    var last_used_step: u64 = 0;
    try std.testing.expect(try verifyCodeOnce(allocator, e.secret_base32, ts, code, &last_used_step, cfg));
    // Replay: same code, same window — must be rejected.
    try std.testing.expect(!try verifyCodeOnce(allocator, e.secret_base32, ts, code, &last_used_step, cfg));
}
```

- [x] **Step 2: Run tests to verify they fail** (compile error: `verifyCodeStep` undefined).

- [x] **Step 3: Implement.** In `src/mfa.zig`, restructure verification:

(a) Rename the body of `verifyCode` into a new public `verifyCodeStep` that returns the matched timestep, and make `verifyCode` a thin wrapper:

```zig
/// Verify a TOTP code and return the matched timestep on success
/// (`null` on rejection). The returned step lets callers implement
/// replay rejection: persist the last accepted step and reject any
/// step <= it (see `verifyCodeOnce`). Constant-time comparison; the
/// window loop never exits early, so timing does not reveal WHICH
/// window position matched. If multiple window positions match, the
/// HIGHEST step is returned (most conservative for replay tracking).
pub fn verifyCodeStep(allocator: Allocator, secret_base32: []const u8, timestamp_ms: u64, code: u32, config: MfaConfig) !?u64 {
    try config.validate();
    const span = observability.startAuthnSpan("mfa");
    var ok: bool = false;
    defer observability.endAuthnSpan(span, ok, null);

    // Decode the secret once (not per-iteration).
    const secret_raw = try base32Decode(allocator, secret_base32);
    defer {
        crypto.secureZero(u8, secret_raw);
        allocator.free(secret_raw);
    }

    // Convert the provided code to bytes for constant-time comparison.
    const code_bytes = std.mem.toBytes(code);
    var matched_step: ?u64 = null;

    var idx: i32 = -config.window;
    while (idx <= config.window) : (idx += 1) {
        const t = if (idx < 0) blk: {
            const delta_ms = @as(u64, @intCast(-idx)) * config.step_seconds * 1000;
            if (delta_ms > timestamp_ms) continue;
            break :blk timestamp_ms - delta_ms;
        } else blk: {
            break :blk timestamp_ms + @as(u64, @intCast(idx)) * config.step_seconds * 1000;
        };

        const candidate = generateCodeFromRaw(secret_raw, t, config);
        const candidate_bytes = std.mem.toBytes(candidate);
        if (std.crypto.timing_safe.eql([4]u8, code_bytes, candidate_bytes)) {
            matched_step = t / (config.step_seconds * 1000);
        }
    }
    ok = matched_step != null;
    return matched_step;
}

/// Verify a TOTP code (boolean form). Prefer `verifyCodeOnce` (or
/// `verifyCodeStep` + your own persistence) in production: this form
/// alone cannot reject replayed codes within the window.
pub fn verifyCode(allocator: Allocator, secret_base32: []const u8, timestamp_ms: u64, code: u32, config: MfaConfig) !bool {
    return (try verifyCodeStep(allocator, secret_base32, timestamp_ms, code, config)) != null;
}

/// Verify a TOTP code with replay rejection. `last_used_step` is the
/// caller-persisted high-water mark (use 0 for a fresh enrollment); a
/// code is accepted only if its matched step is strictly greater, and
/// the mark is advanced on acceptance. Callers must persist the
/// updated value atomically with the login.
pub fn verifyCodeOnce(allocator: Allocator, secret_base32: []const u8, timestamp_ms: u64, code: u32, last_used_step: *u64, config: MfaConfig) !bool {
    const step = (try verifyCodeStep(allocator, secret_base32, timestamp_ms, code, config)) orelse return false;
    if (step <= last_used_step.*) return false;
    last_used_step.* = step;
    return true;
}
```

(Note: the existing doc comment block above the old `verifyCode` describing telemetry moves to `verifyCodeStep`. The `try config.validate();` added in Task 1 lives in `verifyCodeStep` now; `verifyCode` delegates.)

- [x] **Step 4: Run all tests** → pass. `zig fmt src/mfa.zig`.

- [x] **Step 5: Commit**

```bash
git add src/mfa.zig
git commit -m "feat(mfa): expose matched TOTP timestep + verifyCodeOnce replay rejection

Closes GAP-0017 (#43)"
```

---

## Task 6: RFC 4648 base32 padding symmetry + full test vectors (GAP-0021 #44, GAP-0006 #55)

**Files:**

- Modify: `src/mfa.zig`

- [x] **Step 1: Write failing tests** — REPLACE the existing `"base32 RFC 4648 test vectors (mod-5 inputs)"` test with:

```zig
test "base32 RFC 4648 Section 10 test vectors — all 7, encode and decode" {
    const allocator = std.testing.allocator;
    const vectors = [_]struct { raw: []const u8, encoded: []const u8 }{
        .{ .raw = "", .encoded = "" },
        .{ .raw = "f", .encoded = "MY======" },
        .{ .raw = "fo", .encoded = "MZXQ====" },
        .{ .raw = "foo", .encoded = "MZXW6===" },
        .{ .raw = "foob", .encoded = "MZXW6YQ=" },
        .{ .raw = "fooba", .encoded = "MZXW6YTB" },
        .{ .raw = "foobar", .encoded = "MZXW6YTBOI======" },
    };
    for (vectors) |v| {
        const encoded = try base32Encode(allocator, v.raw);
        defer allocator.free(encoded);
        try std.testing.expectEqualSlices(u8, v.encoded, encoded);

        const decoded = try base32Decode(allocator, v.encoded);
        defer allocator.free(decoded);
        try std.testing.expectEqualSlices(u8, v.raw, decoded);
    }
}

test "base32Decode accepts unpadded input and returns exact length" {
    const allocator = std.testing.allocator;
    const decoded = try base32Decode(allocator, "MZXW6YQ"); // "foob" without padding
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, "foob", decoded);
}

test "base32Decode rejects invalid lengths and misplaced padding" {
    const allocator = std.testing.allocator;
    // 1, 3, 6 chars (mod 8) are not producible by base32.
    try std.testing.expectError(error.InvalidBase32, base32Decode(allocator, "M"));
    try std.testing.expectError(error.InvalidBase32, base32Decode(allocator, "MZX"));
    try std.testing.expectError(error.InvalidBase32, base32Decode(allocator, "MZXW6Y"));
    // Padding in the middle is invalid.
    try std.testing.expectError(error.InvalidBase32, base32Decode(allocator, "M=XW6YTB"));
}

test "base32Decode empty input returns empty slice" {
    const allocator = std.testing.allocator;
    const decoded = try base32Decode(allocator, "");
    defer allocator.free(decoded);
    try std.testing.expectEqual(@as(usize, 0), decoded.len);
}
```

Also UPDATE the existing `"base32 round-trip"` test — exact round-trip now holds:

```zig
test "base32 round-trip" {
    const allocator = std.testing.allocator;
    const raw = "Hello, World!!!!"; // 16 bytes, not divisible by 5
    const encoded = try base32Encode(allocator, raw);
    defer allocator.free(encoded);
    const decoded = try base32Decode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, raw, decoded);
}
```

And UPDATE `"base32Decode rejects non-block-aligned input"` — `"ABCDE"` (5 chars, mod 8 = 5) is now a VALID unpadded length; change it to assert decoding succeeds with len 3, and keep rejection for the truly invalid length 6:

```zig
test "base32Decode accepts valid non-block lengths, rejects impossible ones" {
    const allocator = std.testing.allocator;
    const ok = try base32Decode(allocator, "ABCDE"); // 5 chars -> 3 bytes
    defer allocator.free(ok);
    try std.testing.expectEqual(@as(usize, 3), ok.len);
    try std.testing.expectError(error.InvalidBase32, base32Decode(allocator, "ABCDEF")); // 6 chars impossible
}
```

- [x] **Step 2: Run tests to verify they fail.**

- [x] **Step 3: Implement.** In `src/mfa.zig` replace `base32Encode`, `base32Decode`, and `base32DecodeInto`:

```zig
/// Encode raw bytes to Base32 per RFC 4648 Section 6, WITH '='
/// padding to an 8-character block boundary.
pub fn base32Encode(allocator: Allocator, raw: []const u8) Allocator.Error![]u8 {
    const out_len = ((raw.len + 4) / 5) * 8;
    const out = try allocator.alloc(u8, out_len);
    var bi: usize = 0;
    var oi: usize = 0;
    while (bi < raw.len) {
        const remain = raw.len - bi;
        const b0: u8 = raw[bi];
        const b1: u8 = if (remain > 1) raw[bi + 1] else 0;
        const b2: u8 = if (remain > 2) raw[bi + 2] else 0;
        const b3: u8 = if (remain > 3) raw[bi + 3] else 0;
        const b4: u8 = if (remain > 4) raw[bi + 4] else 0;
        var block: [8]u8 = undefined;
        block[0] = BASE32_ALPHABET[(b0 >> 3) & 0x1F];
        block[1] = BASE32_ALPHABET[((b0 << 2) | (b1 >> 6)) & 0x1F];
        block[2] = BASE32_ALPHABET[(b1 >> 1) & 0x1F];
        block[3] = BASE32_ALPHABET[((b1 << 4) | (b2 >> 4)) & 0x1F];
        block[4] = BASE32_ALPHABET[((b2 << 1) | (b3 >> 7)) & 0x1F];
        block[5] = BASE32_ALPHABET[(b3 >> 2) & 0x1F];
        block[6] = BASE32_ALPHABET[((b3 << 3) | (b4 >> 5)) & 0x1F];
        block[7] = BASE32_ALPHABET[b4 & 0x1F];
        // RFC 4648: number of data chars per trailing-byte count.
        const data_chars: usize = switch (remain) {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            else => 8,
        };
        @memcpy(out[oi..][0..data_chars], block[0..data_chars]);
        @memset(out[oi + data_chars ..][0..(8 - data_chars)], '=');
        bi += 5;
        oi += 8;
    }
    return out;
}

/// Decode Base32 (RFC 4648) to raw bytes. Accepts both padded and
/// unpadded input; returns exactly the original byte length.
pub fn base32Decode(allocator: Allocator, encoded: []const u8) (Allocator.Error || error{InvalidBase32})![]u8 {
    // Strip trailing padding.
    var data_len = encoded.len;
    while (data_len > 0 and encoded[data_len - 1] == '=') data_len -= 1;
    const data = encoded[0..data_len];

    const out_len = try base32DecodedLen(data.len);
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    base32DecodeInto(out, data) catch {
        allocator.free(out);
        return error.InvalidBase32;
    };
    return out;
}

/// Exact decoded byte length for an UNPADDED base32 char count.
/// Rejects char counts that base32 cannot produce (1, 3, 6 mod 8).
fn base32DecodedLen(data_chars: usize) error{InvalidBase32}!usize {
    const rem = data_chars % 8;
    const bytes_for_rem: usize = switch (rem) {
        0 => 0,
        2 => 1,
        4 => 2,
        5 => 3,
        7 => 4,
        else => return error.InvalidBase32,
    };
    return (data_chars / 8) * 5 + bytes_for_rem;
}

/// Decode UNPADDED Base32 into a caller-provided buffer (no allocation).
/// `out.len` must be at least `base32DecodedLen(encoded.len)`.
fn base32DecodeInto(out: []u8, encoded: []const u8) error{InvalidBase32}!void {
    const out_len = try base32DecodedLen(encoded.len);
    if (out.len < out_len) return error.InvalidBase32;

    var ei: usize = 0;
    var oi: usize = 0;
    while (ei < encoded.len) {
        const chunk = @min(encoded.len - ei, 8);
        var vals = [_]u8{0} ** 8;
        for (0..chunk) |j| {
            const c = encoded[ei + j];
            if (c >= 'A' and c <= 'Z') {
                vals[j] = c - 'A';
            } else if (c >= '2' and c <= '7') {
                vals[j] = c - '2' + 26;
            } else {
                return error.InvalidBase32;
            }
        }
        var block: [5]u8 = undefined;
        block[0] = (vals[0] << 3) | (vals[1] >> 2);
        block[1] = (vals[1] << 6) | (vals[2] << 1) | (vals[3] >> 4);
        block[2] = (vals[3] << 4) | (vals[4] >> 1);
        block[3] = (vals[4] << 7) | (vals[5] << 2) | (vals[6] >> 3);
        block[4] = (vals[6] << 5) | vals[7];
        const bytes = @min(out_len - oi, 5);
        @memcpy(out[oi..][0..bytes], block[0..bytes]);
        ei += chunk;
        oi += bytes;
    }
}
```

Note: 20-byte TOTP secrets (mod-5) encode without padding — `enroll` output and all stored secrets are unchanged. Callers of `base32DecodeInto` (`verifyCodeStep`/`generateCode` use `base32Decode`) are unaffected.

- [x] **Step 4: Run all tests** → pass.

- [x] **Step 5: Commit**

```bash
git add src/mfa.zig
git commit -m "fix(mfa): RFC 4648 base32 padding symmetry + exact-length decode + all 7 test vectors

Closes GAP-0021 (#44), GAP-0006 (#55)"
```

---

## Task 7: ApiKeyManager — thread-safe mutex, owned returns, lock hygiene, collision safety, pepper, max_keys, prefix enforcement (GAP-0019 #65, GAP-0022 #67, GAP-0023 #68, GAP-0024 #69, GAP-0032 #76, GAP-0034 #78, GAP-0015 #40, GAP-0039 #83, GAP-0040 #84, GAP-0041 #85, parts of GAP-0025 #70)

This is the largest task. All changes are in `src/api_keys.zig` plus test updates.

**Files:**

- Modify: `src/api_keys.zig`, `tests/integration.zig`

- [x] **Step 1: Write failing tests** — append to `src/api_keys.zig`:

```zig
test "validateKey returns owned deep copy safe after revoke" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const ks = try manager.createKey(7, "owned-key", &[_][]const u8{ "a:read", "b:write" }, null);
    defer allocator.free(ks);

    const key = (try manager.validateKey(ks)).?;
    defer manager.freeValidatedKey(key);

    // Destroy the manager's copy; the returned key must remain valid.
    const parsed = try parseApiKey(ks);
    _ = manager.revokeKey(parsed.id);
    _ = try manager.cleanupExpired();

    try std.testing.expectEqualStrings("owned-key", key.name);
    try std.testing.expect(ApiKeyManager.hasScope(&key, "a:read"));
}

test "createKey rejects key_prefix containing '.'" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{ .key_prefix = "my.app" });
    defer manager.deinit();
    try std.testing.expectError(error.InvalidKeyPrefix, manager.createKey(1, "x", &[_][]const u8{"r"}, null));
}

test "createKey enforces max_keys limit" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{ .max_keys = 2 });
    defer manager.deinit();
    const k1 = try manager.createKey(1, "a", &[_][]const u8{"r"}, null);
    defer allocator.free(k1);
    const k2 = try manager.createKey(1, "b", &[_][]const u8{"r"}, null);
    defer allocator.free(k2);
    try std.testing.expectError(error.KeyLimitReached, manager.createKey(1, "c", &[_][]const u8{"r"}, null));
}

test "pepper changes stored hash semantics" {
    const allocator = std.testing.allocator;
    const pepper: [32]u8 = @splat(0x42);
    var manager = ApiKeyManager.init(allocator, .{ .pepper = &pepper });
    defer manager.deinit();
    const ks = try manager.createKey(1, "peppered", &[_][]const u8{"r"}, null);
    defer allocator.free(ks);

    // Validates with the same pepper.
    const key = (try manager.validateKey(ks)).?;
    manager.freeValidatedKey(key);

    // A manager with a DIFFERENT pepper must reject the same key string.
    const other_pepper: [32]u8 = @splat(0x43);
    var other = ApiKeyManager.init(allocator, .{ .pepper = &other_pepper });
    defer other.deinit();
    const ks2 = try other.createKey(1, "peppered", &[_][]const u8{"r"}, null);
    defer allocator.free(ks2);
    // Cross-validate: key from `manager` against `other` (same prefix) fails on hash.
    try std.testing.expect((try other.validateKey(ks)) == null);
}

test "expiry boundary: expires_in_seconds=0 is immediately expired (inclusive >=)" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();
    const ks = try manager.createKey(1, "boundary", &[_][]const u8{"r"}, 0);
    defer allocator.free(ks);
    try std.testing.expect((try manager.validateKey(ks)) == null);
}

test "createKey accepts empty name and empty scopes" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();
    const ks = try manager.createKey(1, "", &[_][]const u8{}, null);
    defer allocator.free(ks);
    const key = (try manager.validateKey(ks)).?;
    defer manager.freeValidatedKey(key);
    try std.testing.expectEqual(@as(usize, 0), key.scopes.len);
    try std.testing.expectEqual(@as(usize, 0), key.name.len);
}

test "ApiKeyManager: concurrent create/validate/revoke under std.Thread" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const Worker = struct {
        fn run(mgr: *ApiKeyManager, alloc: std.mem.Allocator, uid: u64) void {
            var i: usize = 0;
            while (i < 50) : (i += 1) {
                const ks = mgr.createKey(uid, "t", &[_][]const u8{"r"}, null) catch return;
                defer alloc.free(ks);
                if (mgr.validateKey(ks) catch null) |key| {
                    mgr.freeValidatedKey(key);
                }
                const parsed = parseApiKey(ks) catch return;
                _ = mgr.revokeKey(parsed.id);
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &manager, allocator, @as(u64, i) });
    }
    for (&threads) |*t| t.join();
}
```

- [x] **Step 2: Run tests to verify they fail** (compile errors: `freeValidatedKey`, `max_keys`, `pepper` undefined).

- [x] **Step 3: Implement.** In `src/api_keys.zig`:

(a) **Helpers + Config.** Add private helpers near the top of the file (after the imports) and extend `Config`:

```zig
/// Single accessor for the process-global IO used for timestamps and
/// CSPRNG. Centralized so a future injectable-clock refactor touches
/// one site.
inline fn ioh() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Wall-clock seconds (UTC).
fn nowSeconds() i64 {
    return std.Io.Timestamp.now(ioh(), .real).toSeconds();
}
```

```zig
/// Configuration for the API key system.
pub const Config = struct {
    /// Version prefix for formatted key strings (e.g. "ak1", "myapp1").
    /// Must not contain '.' — enforced by `createKey`
    /// (`error.InvalidKeyPrefix`).
    key_prefix: []const u8 = "ak1",
    /// Optional server-side pepper. When set, stored secret hashes are
    /// `HMAC-SHA256(pepper, secret)` instead of bare SHA-256, so a
    /// key-store disclosure alone is not matchable against captured
    /// key strings. The pepper must live outside the key store and
    /// outlive the manager. Changing it invalidates all stored keys.
    pepper: ?*const [32]u8 = null,
    /// Optional hard cap on stored keys. `createKey` returns
    /// `error.KeyLimitReached` at the cap (DoS guard for unbounded
    /// key-map growth).
    max_keys: ?usize = null,
};
```

(b) **Secret hashing with optional pepper** — add next to the helpers:

```zig
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Hash a raw secret for at-rest storage, peppered when configured.
fn hashSecret(config: Config, secret: *const [SECRET_SIZE]u8, out: *[32]u8) void {
    if (config.pepper) |p| {
        HmacSha256.create(out, secret, p);
    } else {
        crypto.hash.sha2.Sha256.hash(secret, out, .{});
    }
}
```

(c) **Thread-safe mutex.** Replace `mutex: std.Io.Mutex` with `mutex: std.Thread.Mutex`, `.mutex = std.Io.Mutex.init` with `.mutex = .{}`, and every

```zig
self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());
```

with

```zig
self.mutex.lock();
defer self.mutex.unlock();
```

(7 sites: deinit, createKey, validateKey, revokeKey, revokeUserKeys, listUserKeys, cleanupExpired). Rationale (record in the struct doc, see (h)): `std.Io.Mutex` bound to the single-threaded IO executor hits an `unreachable` futex path under real cross-thread contention; `std.Thread.Mutex` provides actual OS-thread safety.

(d) **createKey** — hoist all generation/allocation OUT of the lock, validate prefix, enforce max_keys, collision-safe insert, comptime-guard the telemetry bufPrint:

```zig
    pub fn createKey(
        self: *Self,
        user_id: u64,
        name: []const u8,
        scopes: []const []const u8,
        expires_in_seconds: ?i64,
    ) ![]u8 {
        const span = observability.startAuthnSpan("api_key.issue");
        var ok: bool = false;
        var subject_buf: [32]u8 = undefined;
        const subject_id: []const u8 = if (comptime observability.enabled)
            std.fmt.bufPrint(&subject_buf, "{d}", .{user_id}) catch ""
        else
            "";
        defer observability.endAuthnSpan(span, ok, if (ok) subject_id else null);

        // Reject prefixes that would corrupt the '.'-delimited format.
        if (std.mem.indexOfScalar(u8, self.config.key_prefix, '.') != null)
            return error.InvalidKeyPrefix;

        // Everything below until the lock is pure local work — RNG,
        // hashing, formatting, and duplication happen OUTSIDE the
        // critical section so concurrent validates are not stalled.
        var id: [TOKEN_ID_SIZE]u8 = undefined;
        var secret: [SECRET_SIZE]u8 = undefined;
        // Fail closed: no silent low-entropy fallback on a credential path.
        try ioh().randomSecure(&id);
        try ioh().randomSecure(&secret);
        defer crypto.secureZero(u8, &secret);

        var secret_hash: [32]u8 = undefined;
        hashSecret(self.config, &secret, &secret_hash);

        const now = nowSeconds();
        const expires_at: ?i64 = if (expires_in_seconds) |exp| now + exp else null;

        // Format key string BEFORE inserting into map.
        const key_string = try formatApiKey(self.allocator, self.config.key_prefix, &id, &secret);
        errdefer self.allocator.free(key_string);

        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);

        const scopes_dup = try dupeScopes(self.allocator, scopes);
        errdefer freeScopes(self.allocator, scopes_dup);

        const key = ApiKey{
            .id = id,
            .secret_hash = secret_hash,
            .user_id = user_id,
            .name = name_dup,
            .created_at = now,
            .expires_at = expires_at,
            .last_used_at = null,
            .scopes = scopes_dup,
            .is_active = true,
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.config.max_keys) |limit| {
            if (self.keys.count() >= limit) return error.KeyLimitReached;
        }

        // Collision-safe insert: a duplicate random ID must never
        // silently overwrite (and leak) another user's key.
        const gop = try self.keys.getOrPut(id);
        if (gop.found_existing) return error.TokenIdCollision;
        gop.value_ptr.* = key;

        ok = true;
        return key_string;
    }
```

(e) **validateKey** — deep-copy on success, single `nowSeconds()`, comptime-guarded bufPrint; update the doc comment to state ownership:

```zig
    /// Validate an API key and return an OWNED deep copy of the
    /// associated key info — `name` and `scopes` are duplicated with
    /// the manager's allocator and remain valid after concurrent
    /// revoke/cleanup. Release with `freeValidatedKey`.
    /// Returns `null` if the key is invalid, expired, revoked, or has
    /// the wrong prefix.
    ///
    /// Telemetry: emits one `auth.api_key` span per call (see prior
    /// comment — unchanged).
    pub fn validateKey(self: *Self, key_string: []const u8) !?ApiKey {
        const span = observability.startAuthnSpan("api_key");
        var ok: bool = false;
        var subject_buf: [32]u8 = undefined;
        var subject_id: ?[]const u8 = null;
        defer observability.endAuthnSpan(span, ok, subject_id);

        var parsed = try parseApiKey(key_string);
        defer crypto.secureZero(u8, &parsed.secret);

        if (!std.mem.eql(u8, parsed.prefix, self.config.key_prefix)) return null;

        // Hash the provided secret BEFORE acquiring the lock to reduce
        // mutex hold time under concurrent validation.
        var provided_hash: [32]u8 = undefined;
        hashSecret(self.config, &parsed.secret, &provided_hash);
        defer crypto.secureZero(u8, &provided_hash);

        // One wall-clock read serves both the expiry check and the
        // last_used_at update.
        const now = nowSeconds();

        self.mutex.lock();
        defer self.mutex.unlock();

        const key = self.keys.getPtr(parsed.id) orelse return null;

        if (!key.is_active) return null;

        if (key.expires_at) |exp| {
            if (now >= exp) {
                key.is_active = false;
                return null;
            }
        }

        if (!std.crypto.timing_safe.eql([32]u8, provided_hash, key.secret_hash)) {
            return null;
        }

        key.last_used_at = now;

        var copy = key.*;
        copy.name = try self.allocator.dupe(u8, key.name);
        errdefer self.allocator.free(copy.name);
        copy.scopes = try dupeScopes(self.allocator, key.scopes);

        if (comptime observability.enabled) {
            const sid = std.fmt.bufPrint(&subject_buf, "{d}", .{key.user_id}) catch null;
            if (sid) |s| subject_id = s;
        }
        ok = true;
        return copy;
    }

    /// Free a key returned by `validateKey`.
    pub fn freeValidatedKey(self: *Self, key: ApiKey) void {
        self.allocator.free(key.name);
        freeScopes(self.allocator, key.scopes);
    }
```

(f) **listUserKeys** — fix the scopes leak (GAP-0022): after `copy.scopes = try dupeScopes(...)` add the missing errdefer before the append:

```zig
                copy.scopes = try dupeScopes(allocator, entry.value_ptr.scopes);
                errdefer freeScopes(allocator, copy.scopes);
                try list.append(allocator, copy);
```

Also extend its doc comment: `/// The same allocator passed here MUST be passed to freeKeyList — mixing allocators is undefined behavior.`

(g) **revokeKey / revokeUserKeys** — wrap their `bufPrint` subject-id rendering in `if (comptime observability.enabled) { ... }` exactly as in (d)/(e) (GAP-0041). For `revokeUserKeys`, the pattern matches (d): `const subject_id: []const u8 = if (comptime observability.enabled) std.fmt.bufPrint(...) catch "" else "";`.

(h) **Ownership/threading contract docs (GAP-0040)** — replace the bare `/// API Key Manager.` doc with:

```zig
/// API Key Manager.
///
/// ## Threading
/// All public methods are safe to call from multiple OS threads: a
/// `std.Thread.Mutex` serializes every access to the key map.
///
/// ## Ownership
/// - The manager owns all stored key data (`name`/`scopes`), freed by
///   `deinit`/`cleanupExpired`/`revoke*`.
/// - `validateKey` returns an OWNED deep copy — release with
///   `freeValidatedKey`.
/// - `listUserKeys` returns owned deep copies allocated from the
///   allocator argument — release with `freeKeyList`, passing the SAME
///   allocator.
/// - `createKey` returns an owned key string allocated from the
///   manager's allocator — caller frees it.
```

(i) **deinit/cleanupExpired** — switch to `nowSeconds()` in `cleanupExpired` (replace the inline `std.Io.Timestamp.now(...)` call).

(j) **Update existing tests** for the new ownership contract. Every existing test that holds a `validateKey` result beyond a null-check must free it:

- `"create and validate key"`: `if (key) |k| { defer manager.freeValidatedKey(k); ... }`
- `"custom prefix"`: `const key = try manager.validateKey(key_string); try std.testing.expect(key != null); if (key) |k| manager.freeValidatedKey(k);`
- `"revoke key"`: first `validateKey` result needs freeing: `var key = try manager.validateKey(key_string); try std.testing.expect(key != null); if (key) |k| manager.freeValidatedKey(k);`
- `"hasScope checks correctly"` and `"wildcard scope grants all"`: `const key = (try manager.validateKey(key_string)).?; defer manager.freeValidatedKey(key);`
- GAP-0005 tests (`revokeUserKeys revokes all...`, `cleanupExpired removes...`): wrap the boolean-only checks: `try std.testing.expect((try manager.validateKey(k1)) == null);` stays; for non-null asserts use `if (try manager.validateKey(k3)) |k| { manager.freeValidatedKey(k); } else return error.TestUnexpectedResult;`
- In `tests/integration.zig`, apply the same pattern to every `validateKey` use (search `validateKey`).

- [x] **Step 4: Run all tests** → all pass including the new concurrency test (run it 3× to shake out flakiness: `zig build test --summary all` thrice). Run `zig build test -Doptimize=ReleaseSafe --summary all` once — the concurrency test must pass there too.

- [x] **Step 5: Commit**

```bash
git add src/api_keys.zig tests/integration.zig
git commit -m "fix(api_keys)!: thread-safe mutex, owned validateKey copies, collision-safe insert, optional pepper + max_keys, lock hygiene

Closes GAP-0015 (#40), GAP-0019 (#65), GAP-0022 (#67), GAP-0023 (#68), GAP-0024 (#69), GAP-0032 (#76), GAP-0034 (#78), GAP-0039 (#83), GAP-0040 (#84), GAP-0041 (#85)"
```

---

## Task 8: HMAC canonical ordering for duplicate keys + boundary tests (GAP-0033 #77, part of GAP-0036 #80)

**Files:**

- Modify: `src/hmac.zig`

- [x] **Step 1: Write failing tests** — append to `src/hmac.zig`:

```zig
test "computeRecordHmac is order-independent even with duplicate keys" {
    const key: [32]u8 = @splat(0x11);
    const props_ab = [_]KeyValue{
        .{ .key = "dup", .value = "a" },
        .{ .key = "dup", .value = "b" },
    };
    const props_ba = [_]KeyValue{
        .{ .key = "dup", .value = "b" },
        .{ .key = "dup", .value = "a" },
    };
    const h1 = try computeRecordHmac(&key, &props_ab);
    const h2 = try computeRecordHmac(&key, &props_ba);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "computeRecordHmac accepts exactly 128 properties (inclusive boundary)" {
    const key: [32]u8 = @splat(0x22);
    var props: [128]KeyValue = undefined;
    for (&props) |*p| p.* = .{ .key = "k", .value = "v" };
    _ = try computeRecordHmac(&key, &props);
}

test "computeRecordHmac distinguishes empty-key/empty-value pairs" {
    const key: [32]u8 = @splat(0x33);
    const a = [_]KeyValue{.{ .key = "", .value = "" }};
    const b = [_]KeyValue{.{ .key = "", .value = "x" }};
    const ha = try computeRecordHmac(&key, &a);
    const hb = try computeRecordHmac(&key, &b);
    try std.testing.expect(!std.mem.eql(u8, &ha, &hb));
}
```

- [x] **Step 2: Run to verify the duplicate-key test fails** (unstable sort gives order-dependent results — it may pass by luck on 2 elements; if it passes, the fix in Step 3 is still required and pinned by the test).

- [x] **Step 3: Implement.** In `src/hmac.zig`, the sort context `lessThan` (line ~79) compares only keys. Make the order total by tie-breaking on value:

```zig
        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            const ka = ctx.kvs[ctx.indices[a]].key;
            const kb = ctx.kvs[ctx.indices[b]].key;
            switch (std.mem.order(u8, ka, kb)) {
                .lt => return true,
                .gt => return false,
                .eq => return std.mem.order(u8, ctx.kvs[ctx.indices[a]].value, ctx.kvs[ctx.indices[b]].value) == .lt,
            }
        }
```

(Adapt the exact context field names to the existing code — read `src/hmac.zig:79-84` first; only the comparison body changes.) Update the `computeRecordHmac` doc comment: "Deterministic regardless of input order, including duplicate keys (total order over key then value)."

- [x] **Step 4: Run all tests** → pass.

- [x] **Step 5: Commit**

```bash
git add src/hmac.zig
git commit -m "fix(hmac): total sort order (key,value) — deterministic HMAC for duplicate keys; boundary tests

Closes GAP-0033 (#77)"
```

---

## Task 9: Explicit error sets across public API (GAP-0037 #81)

**Files:**

- Modify: `src/api_keys.zig`, `src/mfa.zig`

- [x] **Step 1: Implement** (type-level change; existing tests are the safety net).

`src/api_keys.zig`:

```zig
/// Errors from `parseApiKey`.
pub const ParseError = error{InvalidApiKeyFormat};

/// Errors from `ApiKeyManager.createKey`.
pub const CreateKeyError = Allocator.Error || std.Io.Cancelable || error{
    EntropyUnavailable,
    InvalidKeyPrefix,
    KeyLimitReached,
    TokenIdCollision,
};

/// Errors from `ApiKeyManager.validateKey`.
pub const ValidateKeyError = Allocator.Error || ParseError;
```

Change signatures:

- `pub fn parseApiKey(key_string: []const u8) ParseError!ParsedApiKey`
- `pub fn createKey(...) CreateKeyError![]u8`
- `pub fn validateKey(self: *Self, key_string: []const u8) ValidateKeyError!?ApiKey`
- `pub fn listUserKeys(self: *Self, allocator: Allocator, user_id: u64) Allocator.Error![]ApiKey`
- `pub fn cleanupExpired(self: *Self) Allocator.Error!usize`
- `pub fn formatApiKey(...) Allocator.Error![]u8`

(If `std.Io.Cancelable` is not the correct public name for randomSecure's cancel component, check with `grep -n "pub const Cancelable" ~/.local/share/mise/installs/zig/0.16.0/lib/std/Io.zig` and use the exact set — it is `error{Canceled}`.)

`src/mfa.zig`:

```zig
/// Errors from MFA configuration validation.
pub const ConfigError = error{InvalidMfaConfig};

/// Errors from `enroll`.
pub const EnrollError = Allocator.Error || std.Io.Cancelable || ConfigError || error{
    EntropyUnavailable,
    DeterministicModeIsTestOnly,
};

/// Errors from `generateCode`, `verifyCode`, `verifyCodeStep`, `verifyCodeOnce`.
pub const VerifyError = Allocator.Error || ConfigError || error{InvalidBase32};
```

Change signatures:

- `pub fn enroll(...) EnrollError!Enrollment`
- `pub fn generateCode(...) VerifyError!u32`
- `pub fn verifyCode(...) VerifyError!bool`
- `pub fn verifyCodeStep(...) VerifyError!?u64`
- `pub fn verifyCodeOnce(...) VerifyError!bool`

- [x] **Step 2: Run all tests + plain build** → `zig build && zig build test --summary all && zig build test-integration --summary all` all pass. Compile errors here mean a fn body can return an error outside the declared set — widen the declared set with the EXACT missing error rather than reverting to inferred.

- [x] **Step 3: Commit**

```bash
git add src/api_keys.zig src/mfa.zig
git commit -m "refactor(api)!: explicit error sets on all public fallible functions

Closes GAP-0037 (#81)"
```

---

## Task 10: Hot-path base32 stack decode (PERF-P2-002, part of GAP-0025 #70)

**Files:**

- Modify: `src/mfa.zig`

- [x] **Step 1: Implement.** In `verifyCodeStep` and `generateCode`, decode into a stack buffer when the secret fits (standard 32-char secret → 20 bytes), falling back to heap for oversized inputs. Replace the decode block in BOTH functions:

```zig
    // Hot path: decode the secret into a stack buffer (standard TOTP
    // secrets are 20 bytes / 32 chars) — zero heap traffic per call.
    var stack_buf: [64]u8 = undefined;
    var data_len = secret_base32.len;
    while (data_len > 0 and secret_base32[data_len - 1] == '=') data_len -= 1;
    const decoded_len = base32DecodedLen(data_len) catch return error.InvalidBase32;
    var heap_buf: ?[]u8 = null;
    defer if (heap_buf) |b| allocator.free(b);
    const secret_raw = if (decoded_len <= stack_buf.len) blk: {
        base32DecodeInto(stack_buf[0..decoded_len], secret_base32[0..data_len]) catch return error.InvalidBase32;
        break :blk stack_buf[0..decoded_len];
    } else blk: {
        const b = try allocator.alloc(u8, decoded_len);
        heap_buf = b;
        base32DecodeInto(b, secret_base32[0..data_len]) catch return error.InvalidBase32;
        break :blk b;
    };
    defer crypto.secureZero(u8, secret_raw);
```

(This replaces `const secret_raw = try base32Decode(allocator, secret_base32); defer { crypto.secureZero(...); allocator.free(...); }` in both functions. Note `stack_buf` is zeroized via the `secureZero(u8, secret_raw)` defer which covers the used slice.)

- [x] **Step 2: Run all tests** → pass (behavior identical; only allocation strategy changed).

- [x] **Step 3: Commit**

```bash
git add src/mfa.zig
git commit -m "perf(mfa): stack-buffer base32 decode on TOTP hot paths (zero heap per verify)

Part of GAP-0025 (#70)"
```

---

## Task 11: Observability — fix -Dwith_otel test failure + document inert seam (GAP-0010 #59, GAP-0020 #66, GAP-0035 #79 doc)

**Files:**

- Modify: `tests/observability_disabled_test.zig`, `src/observability.zig`, `src/observability_init.zig`

- [x] **Step 1: Fix the failing test.** In `tests/observability_disabled_test.zig:28` the test asserts `expectEqual(build_options.with_otel, auth.observability.enabled)` which fails under `-Dwith_otel=true` because the seam is hardcoded disabled. Replace that test with:

```zig
test "observability.enabled is hardcoded false (GAP-0020: seam inert until upstream Zig dedup fix)" {
    // 2026-05-02 workaround: observability.zig hardcodes enabled=false
    // regardless of -Dwith_otel. When the seam is restored to
    // `enabled = build_options.with_otel`, flip this assertion back to
    // expectEqual(build_options.with_otel, auth.observability.enabled).
    try std.testing.expectEqual(false, auth.observability.enabled);
}
```

(Keep the `build_options` import only if still used elsewhere in the file; remove it if now unused.)

- [x] **Step 2: Verify both build modes**

Run: `zig build test --summary all && zig build test -Dwith_otel=true --summary all` → BOTH green now.

- [x] **Step 3: Document the inert seam.** In `src/observability.zig`, extend the comment block above `pub const enabled: bool = false;` with a tracking pointer:

```zig
// TRACKING: GAP-0020 (gitlab issue #66). While this constant is false,
// consumers get ZERO auth security events even with -Dwith_otel=true —
// add application-level logging around auth calls until the seam is
// restored. The -Dwith_otel build still type-checks the otel wiring.
```

In `src/observability_init.zig`, extend the `installGlobals` doc comment with the GAP-0035 contract:

```zig
    /// SAFETY CONTRACT (GAP-0035, gitlab issue #79): `installGlobals`
    /// publishes raw pointers into process-global state with NO
    /// synchronization. The caller MUST (1) keep `self` at a stable
    /// address that outlives every span site, (2) call this ONCE,
    /// before any thread can start a span, and (3) call `deinit` only
    /// after all span activity has quiesced. Violating any of these is
    /// a use-after-free / data race. Revisit with atomic publication
    /// when the seam is re-enabled (GAP-0020).
```

- [x] **Step 4: Run all tests once more** (`zig build test --summary all`) → pass.

- [x] **Step 5: Commit**

```bash
git add tests/observability_disabled_test.zig src/observability.zig src/observability_init.zig
git commit -m "fix(test): align observability test with hardcoded-disabled seam; document inertness + installGlobals safety contract

Closes GAP-0010 (#59); documents GAP-0020 (#66), GAP-0035 (#79)"
```

---

## Task 12: Fix conditionally-no-op TOTP rejection test (QR-013, part of GAP-0036 #80)

**Files:**

- Modify: `src/mfa.zig`

- [x] **Step 1: Replace** the test `"verifyCode rejects wrong code"` (which only asserts when `real_code != 999999`) with a guaranteed-meaningful version:

```zig
test "verifyCode rejects wrong code" {
    const allocator = std.testing.allocator;
    const cfg = deterministicConfig();
    const enrollment = try enroll(allocator, "grace", cfg);
    defer enrollment.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const real_code = try generateCode(allocator, enrollment.secret_base32, ts, cfg);
    // A code derived from the real one is guaranteed different.
    const wrong_code = (real_code + 1) % 1_000_000;
    try std.testing.expect(!try verifyCode(allocator, enrollment.secret_base32, ts, wrong_code, cfg));
}
```

Caveat: with `window = 1` the wrong code could coincidentally equal a neighboring window's code (~3-in-10^6 chance, but DETERMINISTIC inputs make it fixed — run once; if it collides, change `"grace"` to another fixture name and note why).

- [x] **Step 2: Run tests** → pass.

- [x] **Step 3: Commit**

```bash
git add src/mfa.zig
git commit -m "test(mfa): make wrong-code rejection test unconditional

Part of GAP-0036 (#80)"
```

---

## Task 13: Adversarial integration tests (GAP-0036 #80, SR-012)

**Files:**

- Modify: `tests/integration.zig`

- [x] **Step 1: Append adversarial tests** to `tests/integration.zig` (after reading the file's existing import style — it imports the library as `auth`):

```zig
test "adversarial: parseApiKey malformed input classes" {
    const cases = [_][]const u8{
        "", ".", "..", "ak1.", "ak1..", ".abc.def",
        "ak1.!!!.???", "ak1.AAAA.BBBB", // wrong decoded sizes
        "ak1.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.extra",
    };
    for (cases) |c| {
        try std.testing.expectError(error.InvalidApiKeyFormat, auth.api_keys.parseApiKey(c));
    }
}

test "adversarial: MFA config edge cases surface errors not panics" {
    const allocator = std.testing.allocator;
    const secret = "MZXW6YTBMZXW6YTBMZXW6YTBMZXW6YTB";
    const ts: u64 = 1_700_000_000_000;
    try std.testing.expectError(error.InvalidMfaConfig, auth.mfa.verifyCode(allocator, secret, ts, 0, .{ .digits = 0 }));
    try std.testing.expectError(error.InvalidMfaConfig, auth.mfa.verifyCode(allocator, secret, ts, 0, .{ .step_seconds = 0 }));
    try std.testing.expectError(error.InvalidMfaConfig, auth.mfa.verifyCode(allocator, secret, ts, 0, .{ .window = -1 }));
}

test "adversarial: recovery code lifecycle end-to-end" {
    const allocator = std.testing.allocator;
    const e = try auth.mfa.enroll(allocator, "endtoend", .{});
    defer e.deinit(allocator);

    const hashes = try allocator.alloc([32]u8, e.scratch_codes.len);
    defer allocator.free(hashes);
    const consumed = try allocator.alloc(bool, e.scratch_codes.len);
    defer allocator.free(consumed);
    for (e.scratch_codes, 0..) |code, i| {
        hashes[i] = auth.mfa.hashScratchCode(code);
        consumed[i] = false;
    }
    // Each code works exactly once.
    for (e.scratch_codes) |code| {
        try std.testing.expect(auth.mfa.verifyScratchCode(hashes, consumed, code) != null);
        try std.testing.expect(auth.mfa.verifyScratchCode(hashes, consumed, code) == null);
    }
}

test "adversarial: TOTP replay rejected via verifyCodeOnce across logins" {
    const allocator = std.testing.allocator;
    const e = try auth.mfa.enroll(allocator, "replay-int", .{});
    defer e.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const code = try auth.mfa.generateCode(allocator, e.secret_base32, ts, .{});
    var last_step: u64 = 0;
    try std.testing.expect(try auth.mfa.verifyCodeOnce(allocator, e.secret_base32, ts, code, &last_step, .{}));
    try std.testing.expect(!try auth.mfa.verifyCodeOnce(allocator, e.secret_base32, ts, code, &last_step, .{}));
    // The NEXT step's code is accepted.
    const ts2 = ts + 30_000;
    const code2 = try auth.mfa.generateCode(allocator, e.secret_base32, ts2, .{});
    if (code2 != code) {
        try std.testing.expect(try auth.mfa.verifyCodeOnce(allocator, e.secret_base32, ts2, code2, &last_step, .{}));
    }
}
```

- [x] **Step 2: Run** `zig build test-integration --summary all` → all pass.

- [x] **Step 3: Commit**

```bash
git add tests/integration.zig
git commit -m "test(integration): adversarial coverage — malformed keys, MFA config edges, recovery + replay lifecycle

Closes GAP-0036 (#80)"
```

---

## Task 14: Working example wired into the build (GAP-0002 #30, QR-024)

**Files:**

- Modify: `examples/basic.zig`, `build.zig`, `Makefile`

- [x] **Step 1: Rewrite `examples/basic.zig`** with REAL library calls (Zig 0.16 — no `std.io.getStdOut`; use `std.debug.print` to avoid the removed API):

```zig
// SPDX-License-Identifier: Apache-2.0
//! Basic usage example: HMAC key derivation, API key lifecycle, MFA
//! enrollment + TOTP verification. Build and run: `zig build example`.

const std = @import("std");
const auth = @import("auth");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // ── HMAC chain integrity ────────────────────────────────────────
    const master_key: [32]u8 = @splat(0x2a); // demo only — use a real KMS secret
    const derived = auth.hmac.deriveHmacKey(&master_key, .{});
    const record = [_]auth.hmac.KeyValue{
        .{ .key = "id", .value = "rec-1" },
        .{ .key = "amount", .value = "42" },
    };
    const mac = try auth.hmac.computeRecordHmac(&derived, &record);
    std.debug.print("record hmac: {s}\n", .{&auth.hmac.hmacToHex(&mac)});

    // ── API keys ────────────────────────────────────────────────────
    var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{});
    defer mgr.deinit();

    const key_string = try mgr.createKey(1001, "demo-key", &.{ "metrics:read", "health:read" }, 3600);
    defer allocator.free(key_string);
    std.debug.print("issued key: {s}\n", .{key_string});

    if (try mgr.validateKey(key_string)) |key| {
        defer mgr.freeValidatedKey(key);
        std.debug.print("validated key for user {d}; metrics:read={}\n", .{
            key.user_id,
            auth.api_keys.ApiKeyManager.hasScope(&key, "metrics:read"),
        });
    }

    // ── MFA / TOTP ──────────────────────────────────────────────────
    const enrollment = try auth.mfa.enroll(allocator, "alice", .{});
    defer enrollment.deinit(allocator);
    std.debug.print("totp secret (give to authenticator app): {s}\n", .{enrollment.secret_base32});
    std.debug.print("recovery codes: {d}\n", .{enrollment.scratch_codes.len});

    const now_ms: u64 = @intCast(std.time.milliTimestamp());
    const code = try auth.mfa.generateCode(allocator, enrollment.secret_base32, now_ms, .{});
    var last_step: u64 = 0;
    const accepted = try auth.mfa.verifyCodeOnce(allocator, enrollment.secret_base32, now_ms, code, &last_step, .{});
    std.debug.print("totp code {d:0>6} accepted: {}\n", .{ code, accepted });
}
```

- [x] **Step 2: Wire into `build.zig`.** Read `build.zig` first; after the main module setup add (following the file's existing style for module creation — the `auth` module with `observability` import already exists as a variable; reuse it):

```zig
    // Example executable: `zig build example` builds and runs it.
    const example_exe = b.addExecutable(.{
        .name = "example-basic",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "auth", .module = auth_module }},
        }),
    });
    const example_step = b.step("example", "Build and run the basic example");
    const run_example = b.addRunArtifact(example_exe);
    example_step.dependOn(&run_example.step);
```

(Adapt `auth_module` to the actual variable name in build.zig; also add the example compile (not run) to the `check` step if one exists so CI compiles it: `check_step.dependOn(&example_exe.step);`.)

- [x] **Step 3: Add Makefile target** — in `Makefile` add near the test targets:

```makefile
.PHONY: example
example: ## Build and run the basic example
 zig build example
```

- [x] **Step 4: Run** `zig build example` → prints hmac/key/totp lines, exit 0. Run `zig build test --summary all` → still green.

- [x] **Step 5: Commit**

```bash
git add examples/basic.zig build.zig Makefile
git commit -m "feat(examples): working basic example wired into zig build example

Closes GAP-0002 (#30)"
```

---

## Task 15: User-facing documentation (AUTH-DOC-001 #12, AUTH-DOC-002 #13, AUTH-DOC-003 #14, GAP-0038 #82 doc, SR-007, QR-005)

**Files:**

- Create: `docs/USAGE.md`
- Modify: `docs/README.md` (add link)

- [x] **Step 1: Write `docs/USAGE.md`** with these sections (each with working code snippets consistent with the post-Task-7 API):

1. **API-key token format & configuration** (AUTH-DOC-001): format `<prefix>.<id_b64url>.<secret_b64url>`; `Config.key_prefix` rules (no `.`, enforced via `error.InvalidKeyPrefix`); `Config.pepper` (what it protects against, where to store it, rotation = key invalidation); `Config.max_keys`; ownership rules (`createKey` string → caller frees; `validateKey` → `freeValidatedKey`; `listUserKeys` → `freeKeyList` with the SAME allocator — GAP-0038); `parseBearerToken` returns a slice borrowing the input header (QR-005); threading guarantees (all manager methods thread-safe).
2. **HMAC chain usage** (AUTH-DOC-002): `deriveHmacKey` + `HkdfConfig` (supply your own salt/info in production — defaults are dev-only), `computeRecordHmac` (128-prop cap, duplicate-key total ordering), `computeChainHash` (anti-truncation count), `verifyHmac` (constant-time), hex helpers. Full worked example.
3. **MFA configuration** (AUTH-DOC-003): every `MfaConfig` knob with validation ranges (digits 6–9, step_seconds > 0, window 0–64); `deterministic` is test-only (returns `error.DeterministicModeIsTestOnly` outside `zig test`); recovery-code lifecycle (show once → `hashScratchCode` → store hashes + consumed flags → `verifyScratchCode`); TOTP replay protection (`verifyCodeOnce` / `verifyCodeStep`, persist `last_used_step`); **otpauth URI guidance** (SR-007): percent-encode username/issuer when building `otpauth://totp/...` URIs — never interpolate raw user input.

Use real, compiling snippets (copy patterns from `examples/basic.zig`). ~150-250 lines total.

- [x] **Step 2: Link it** — in `docs/README.md` add `- [Usage Guide](USAGE.md) — token format, HMAC chains, MFA configuration` to the doc list, and in `README.md` add a `See [docs/USAGE.md](docs/USAGE.md) for the full usage guide.` line under Quick Start.

- [x] **Step 3: Verify** `pre-commit run markdownlint --files docs/USAGE.md docs/README.md README.md` → pass.

- [x] **Step 4: Commit**

```bash
git add docs/USAGE.md docs/README.md README.md
git commit -m "docs: usage guide — token format config, HMAC chains, MFA knobs + recovery/replay lifecycle

Closes AUTH-DOC-001 (#12), AUTH-DOC-002 (#13), AUTH-DOC-003 (#14)"
```

---

## Task 16: README + version/metadata accuracy (GAP-0009 #58, GAP-0011 #60, GAP-0012 #61, GAP-0013 #62, GAP-0014 #63, GAP-0026 #28)

**Files:**

- Modify: `README.md`, `build.zig.zon`, `src/root.zig`, `CHANGELOG.md`, `CODEOWNERS`, `.pre-commit-config.yaml`

- [x] **Step 1: `build.zig.zon`**: set `.minimum_zig_version = "0.16.0",` (GAP-0013).

- [x] **Step 2: `src/root.zig`**: set `pub const version = "0.1.5";` and add doc `/// Library version — MUST match build.zig.zon .version (checked by pre-commit).` (GAP-0011).

- [x] **Step 3: Version-sync check** — add a local pre-commit hook. In `.pre-commit-config.yaml` under the existing `repo: local` hooks add:

```yaml
      - id: version-sync
        name: root.zig version matches build.zig.zon
        entry: bash -c 'z=$(grep -oP "\.version = \"\K[0-9.]+" build.zig.zon | head -1); r=$(grep -oP "pub const version = \"\K[0-9.]+" src/root.zig); if [ "$z" != "$r" ]; then echo "version mismatch: zon=$z root.zig=$r"; exit 1; fi'
        language: system
        files: ^(build\.zig\.zon|src/root\.zig)$
        pass_filenames: false
```

- [x] **Step 4: `README.md`** fixes (GAP-0009, GAP-0012, GAP-0013):
- Badge + Requirements: `0.15.1` → `0.16.0` (both occurrences, lines ~4 and ~62).
- Install snippet (line ~26-31): `ref=v0.1.0` → `ref=v0.1.5`.
- "Zero Dependencies" bullet → `**Zero dependencies by default** — pure Zig stdlib; optional OpenTelemetry instrumentation behind \`-Dwith_otel\` (currently inert, see docs)`.
- Remove or fix the test-count claim (line ~15): replace exact numbers with "Comprehensive unit + integration test suite, leak-checked, fuzzed in CI".
- Line ~147 dead link `otel/docs/integration/RECIPE.md`: replace the sentence with a reference to `https://gitlab.com/devnw/zig/otel` (the dependency's repo) or delete the line.

- [x] **Step 5: `CHANGELOG.md`** (GAP-0014): backfill from git history. Run `git tag --sort=version:refname` and `git log --oneline <tag1>..<tag2>` per pair; write one `## [0.1.X] - YYYY-MM-DD` section per released tag (dates from `git log -1 --format=%as <tag>`) with 2-4 bullets each summarizing the changes. Replace the `[0.1.0] - YYYY-MM-DD` placeholder with the real date.

- [x] **Step 6: `CODEOWNERS`** (GAP-0026): replace `@your-username` with `@benjiv`.

- [x] **Step 7: Verify** — `pre-commit run --all-files 2>&1 | grep -E "Failed|version-sync"` → version-sync passes, no new failures. `zig build test --summary all` → green.

- [x] **Step 8: Commit**

```bash
git add README.md build.zig.zon src/root.zig CHANGELOG.md CODEOWNERS .pre-commit-config.yaml
git commit -m "docs(meta): fix version claims (0.16.0 floor, v0.1.5), changelog backfill, CODEOWNERS, version-sync hook

Closes GAP-0009 (#58), GAP-0011 (#60), GAP-0012 (#61), GAP-0013 (#62), GAP-0014 (#63), GAP-0026 (#28)"
```

---

## Task 17: Lint/format chores (GAP-0027 #71, GAP-0028 #72, GAP-0029 #73)

**Files:**

- Modify: `.gitlab/issue_templates/Bug Report.md`, `CONTRIBUTING.md`, `.cz.yaml`, `scripts/detect_diamond_deps.py`, `src/api_keys.zig`, `src/hmac.zig`, `src/mfa.zig`, `src/observability.zig`, `src/observability_init.zig`

- [x] **Step 1: MD040** — add language specifiers to the bare fences: `.gitlab/issue_templates/Bug Report.md:44` (use ```text) and `CONTRIBUTING.md:48` (inspect content; likely```bash or ```text).

- [x] **Step 2: Formatting** — run `pre-commit run pretty-format-yaml --all-files` and `pre-commit run "ruff format" --all-files` (or `pre-commit run --all-files` and let them autofix), then verify clean.

- [x] **Step 3: Doc comments (GAP-0029)** — add `///` docs to the undocumented pub fns: `ApiKeyManager.init`/`deinit` (api_keys.zig), `lessThan` sort helper if pub (hmac.zig — or make it private if Zig sort API allows), `Enrollment.deinit` (mfa.zig), `Span.end`, `endClientSpan`, `endServerSpan` (observability.zig), `Otel.deinit` (observability_init.zig). One-line contracts each, e.g. `/// Free all stored keys and the map. The manager is unusable afterwards.`

- [x] **Step 4: Verify** `pre-commit run --all-files` → all pass; `zig build test --summary all` → green.

- [x] **Step 5: Commit**

```bash
git add -A
git commit -m "chore(quality): MD040 fences, yaml/ruff formatting, doc comments on remaining pub fns

Closes GAP-0027 (#71), GAP-0028 (#72), GAP-0029 (#73)"
```

---

## Task 18: CI cache + image digest pin + script BFS fix (GAP-0025 #70 parts, CI-IMG-001)

**Files:**

- Modify: `.gitlab-ci.yml`, `scripts/detect_diamond_deps.py`

- [x] **Step 1: CI cache.** In `.gitlab-ci.yml` add a global cache block (top level, after `variables:`):

```yaml
cache:
  key: zig-$ZIG_VERSION
  paths:
    - zig-$ZIG_VERSION/
    - .zig-cache/
```

(The existing `*install-zig` guard `if [ ! -f "zig-${ZIG_VERSION}/zig" ]` now actually triggers on cache hits.)

- [x] **Step 2: Digest-pin the image.** Get the current digest: `docker manifest inspect debian:bookworm-slim -v 2>/dev/null | grep -m1 digest` or `skopeo inspect docker://debian:bookworm-slim | grep digest` — if neither tool is available, SKIP this step and note it in the commit (do not guess a digest). If obtained, replace every `image: debian:bookworm-slim` with `image: debian:bookworm-slim@sha256:<digest>`.

- [x] **Step 3: BFS deque** — in `scripts/detect_diamond_deps.py` (~line 189): `from collections import deque`, change `queue: List[Path] = [root_zon]` to `queue: deque[Path] = deque([root_zon])` and `queue.pop(0)` to `queue.popleft()`.

- [x] **Step 4: Verify** — `python3 -m py_compile scripts/detect_diamond_deps.py && python3 scripts/detect_diamond_deps.py` (run mode per its `--help`; the pre-commit hook invocation is `detect-diamond-deps` — run `pre-commit run detect-diamond-deps --all-files`) → pass. YAML lint: `pre-commit run check-yaml --files .gitlab-ci.yml` → pass.

- [x] **Step 5: Commit**

```bash
git add .gitlab-ci.yml scripts/detect_diamond_deps.py
git commit -m "ci: cache Zig toolchain across jobs; perf(scripts): O(1) BFS dequeue

Part of GAP-0025 (#70)"
```

---

## Task 19: Makefile/CI alignment (GAP-0045 #89)

**Files:**

- Modify: `Makefile`

- [x] **Step 1: Implement** (read `Makefile` first; adapt to its existing structure):
- `fmt`: add `examples/` → `zig fmt src/ tests/ examples/ build.zig`
- Add `fuzz` target: `zig build test --fuzz` with `## Run the CI fuzz job locally`
- Expand `ci` target to mirror the pipeline: `ci: clean check test test-release` where `check: zig build check`, and add `test-release: zig build test -Doptimize=ReleaseSafe && zig build test -Doptimize=ReleaseFast && zig build test-integration -Doptimize=ReleaseSafe`
- Add a comment header noting `build` = full build, CI's "build" job = `zig build check` (compile-check only).

- [x] **Step 2: Verify** `make fmt && make check && make test` → pass (don't run full `make ci` release matrix locally unless fast).

- [x] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build(make): align targets with CI — fmt covers examples, add fuzz + release-mode ci

Closes GAP-0045 (#89)"
```

---

## Task 20: Issue closures, Won't-Do dispositions, otel upstream issue (GAP-0018 #64 + remaining tracker hygiene)

**Files:**

- Modify: `docs/GAP_ANALYSIS.md`, `docs/GAP_ANALYSIS_RESOLVED.md` (move closed items)
- External: GitLab issues via `glab`

- [x] **Step 1: Close GAP-0018 (#64) with the investigation evidence:**

The pin is CORRECT and deterministic: cold-cache `zig fetch "git+https://gitlab.com/devnw/zig/otel.git?ref=v0.1.10#a1afbfe672d5c0894969d0aa49efa7a66510eda3"` reproduces the pinned hash `otel-0.1.9-B0v3ltxeNgB4mGDRS7r1dapusir8f7_ISb-MvzYltW1h`, and the sibling otel repo confirms tag v0.1.10 → commit a1afbfe contains that tree (tls v0.1.11 pins). The "mismatch" was zig's ref-only (no fragment) resolution returning a stale/different tree — an upstream resolution anomaly that our fragment-pinned URL is immune to. The hash's `0.1.9` label lags because otel's internal `.version` wasn't bumped with the tag — an upstream otel bug.

```bash
glab issue close 64 -R devnw/zig/auth --comment "..."  # paste evidence above
```

- [x] **Step 2: File the upstream otel issue:**

```bash
glab issue create -R devnw/zig/otel --title "build.zig.zon .version (0.1.9) lags tag v0.1.10 — package hash labels are misleading" --description "<evidence: zig fetch of v0.1.10 emits otel-0.1.9-* hashes; also note ref-only vs fragment fetch resolved different trees on 2026-06-12 — recommend bumping .version with every tag (sync_diamond_deps already bumps siblings) and investigating the tag re-push>"
```

- [x] **Step 3: Won't-Do / accepted-with-rationale closures** (comment + close each):
- **#86 (GAP-0042** ?i64 sentinel): Won't Do — optionals are the clearer API; ~16B/key padding is irrelevant without a measured workload and no bench harness exists (#11). Reopen if profiling shows scan-bound behavior.
- **#70 (GAP-0025** umbrella): PARTIAL — close after noting: CI cache DONE (Task 18), base32 stack decode DONE (Task 10), BFS deque DONE (Task 18), max_keys DONE (Task 7); O(n) user scans / two-pass cleanup / HashMap pre-alloc ACCEPTED with rationale (admin-path frequency, no measured workload, no bench harness — blocked on #11). Keep #35/#36 closed via the cache fix (comment on both).
- **#87 (GAP-0043)**, **#88 (GAP-0044)**: closed by Task 1 — comment with commit SHA.
- **#79 (GAP-0035)**: comment "documented safety contract (Task 11); code hardening blocked on seam re-enable (GAP-0020 #66); keeping open, blocked" — leave OPEN with a `blocked` note.
- **#66 (GAP-0020)**: comment "inertness documented in code+README (Task 11); seam restore blocked on upstream Zig module-dedup issue" — leave OPEN.
- **#11 (AUTH-TEST-004)**: leave open (bench harness deferred).
- All other implemented gaps: close with the implementing commit SHA (issues #12 #13 #14 #23 #28 #30 #40 #43 #44 #55 #56 #57 #58 #59 #60 #61 #62 #63 #65 #67 #68 #69 #71 #72 #73 #74 #75 #76 #77 #78 #80 #81 #82*#83 #84 #85 #89). (*#82/GAP-0038 closes via the USAGE.md ownership documentation, Task 15.)

- [x] **Step 4: Update `docs/GAP_ANALYSIS.md`** — move every closed gap to `docs/GAP_ANALYSIS_RESOLVED.md` with one-line resolution evidence (commit SHA + file:line); leave open only: GAP-0020 (#66, blocked upstream), GAP-0035 (#79, blocked on GAP-0020), AUTH-TEST-004 (#11, deferred), and any accepted-with-rationale rows (record the rationale inline). Update the summary table.

- [x] **Step 5: Commit**

```bash
git add docs/GAP_ANALYSIS.md docs/GAP_ANALYSIS_RESOLVED.md
git commit -m "docs(gaps): round-1 closure — resolve implemented gaps, record Won't-Do rationale, GAP-0018 investigation

Closes GAP-0018 (#64)"
```

---

## Task 21: Full verification sweep

- [x] **Step 1:** `zig build && zig build test --summary all && zig build test-integration --summary all` → all green.
- [x] **Step 2:** `zig build test -Dwith_otel=true --summary all` → green (GAP-0010 fixed).
- [x] **Step 3:** `zig build test -Doptimize=ReleaseSafe --summary all && zig build test -Doptimize=ReleaseFast --summary all` → green.
- [x] **Step 4:** `zig build example` → runs, exit 0.
- [x] **Step 5:** `pre-commit run --all-files` → all pass.
- [x] **Step 6:** `zig fmt --check src/ tests/ examples/ build.zig` → exit 0.
- [x] **Step 7:** Any failure → fix before declaring the round complete (use superpowers:systematic-debugging).

---

## Self-Review Notes

- **Spec coverage:** every open GitLab issue from the audit maps to a task (Tasks 1–20) or an explicit Won't-Do/blocked disposition (Task 20). GAP-0036's "concurrency test" lands in Task 7 (thread test), "MFA edges" in Tasks 1/13, "boundary tests" in Tasks 6/8.
- **Ordering matters:** Task 1 before 5 (validate() referenced), Task 6 before 10 (base32DecodedLen referenced), Task 7 before 9 (error sets name Task-7 errors), Task 7 before 13/14 (freeValidatedKey used).
- **Type consistency:** `freeValidatedKey(self, key)` (method, manager allocator); `verifyScratchCode(hashes, consumed, presented) ?usize`; `verifyCodeStep(...) !?u64`; `MfaConfig.validate() error{InvalidMfaConfig}!void` — used consistently across tasks.
- **Breaking changes** are marked with `!` in commit messages (Tasks 1, 3, 7, 9): scratch code length 8→32, validateKey ownership, error-set tightening, config validation errors. Next release should be v0.2.0.
