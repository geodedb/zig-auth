// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Multi-Factor Authentication (MFA) — RFC 6238 TOTP implementation.
//!
//! Provides TOTP enrollment, code generation, and verification with
//! explicit configuration. No feature flags or product-specific wiring.
//!
//! **Security note:** By default, `enroll` generates cryptographically
//! random TOTP secrets using the OS CSPRNG. Set `deterministic = true`
//! in `MfaConfig` only for testing — never in production.

const std = @import("std");
const builtin = @import("builtin");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
// otel seam — credentials NEVER pass to the seam. Only the auth-method
// label ("mfa", "mfa.enroll") and the post-success subject id (the
// already-public username on enrollment) reach span attributes; the
// secret, scratch codes, and TOTP code itself stay on the local stack
// and are zeroised on return.
const observability = @import("observability");

/// MFA configuration.
pub const MfaConfig = struct {
    /// Number of TOTP digits (typically 6).
    digits: u8 = 6,
    /// Time step in seconds (typically 30).
    step_seconds: u64 = 30,
    /// Number of time steps to check in each direction for clock skew.
    window: i32 = 1,
    /// Number of scratch/recovery codes to generate on enrollment.
    scratch_code_count: usize = 2,
    /// TEST-ONLY: derive the secret deterministically from username +
    /// salt. Returns `error.DeterministicModeIsTestOnly` in non-test
    /// builds — this switch cannot be enabled in production.
    deterministic: bool = false,
    /// Salt for deterministic derivation. Ignored when `deterministic` is false.
    salt: []const u8 = "auth-mfa-salt-v1",

    /// Validate configuration invariants. Called by `enroll`,
    /// `generateCode`, and `verifyCode`.
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
};

/// Enrollment result containing the Base32-encoded secret and scratch codes.
pub const Enrollment = struct {
    secret_base32: []u8,
    scratch_codes: [][]u8,

    pub fn deinit(self: *const Enrollment, allocator: Allocator) void {
        for (self.scratch_codes) |code| {
            crypto.secureZero(u8, code);
            allocator.free(code);
        }
        allocator.free(self.scratch_codes);
        crypto.secureZero(u8, self.secret_base32);
        allocator.free(self.secret_base32);
    }
};

/// Raw entropy per scratch code: 20 bytes = 160 bits.
pub const SCRATCH_CODE_RAW_LEN: usize = 20;
/// Encoded scratch-code length: 20 raw bytes -> 32 base32 chars.
pub const SCRATCH_CODE_LEN: usize = 32;

/// Hash a scratch code for at-rest storage. Store ONLY these hashes;
/// never persist plaintext recovery codes.
/// Bare SHA-256 (no KDF/salt) is sufficient: codes are 160-bit uniform CSPRNG output, so preimage cost is ~2^160 regardless of hash speed.
pub fn hashScratchCode(code: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(code, &out, .{});
    return out;
}

/// Verify a presented recovery code against stored hashes, enforcing
/// single use. Scans ALL hashes with constant-time comparison (no early
/// exit). Rejection timing is independent of the stored hashes and
/// consumed state (full fixed-length scan, timing-safe hash comparison);
/// the matched index itself is returned to the caller and is not a secret.
/// On match of an unconsumed slot, marks it consumed and returns its
/// index; otherwise returns null. `hashes` and `consumed` must be the
/// same length.
///
/// CONCURRENCY: the consumed-flag check and set are not atomic. Calls
/// for a given user MUST be externally serialized; in persistent
/// deployments make the consumed-flag update atomic with verification
/// (e.g. a conditional UPDATE / compare-and-set), never read-verify-writeback.
/// INPUT: codes are uppercase base32 — normalize case and strip any
/// separators before calling.
pub fn verifyScratchCode(hashes: []const [32]u8, consumed: []bool, presented: []const u8) ?usize {
    std.debug.assert(hashes.len == consumed.len);
    if (hashes.len != consumed.len) return null; // fail closed in release builds
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

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 10^n for n in 0..=9 — comptime table so the TOTP modulus is a
/// single indexed load (digits are validated to 6..9).
const POW10 = [_]u32{ 1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000 };

/// Encode raw bytes to Base32 (RFC 4648, no padding).
/// Output length is always `((raw.len + 4) / 5) * 8`. For inputs whose
/// length is not a multiple of 5, trailing encoded characters represent
/// zero-padded bits.
pub fn base32Encode(allocator: Allocator, raw: []const u8) ![]u8 {
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
        out[oi + 0] = BASE32_ALPHABET[(b0 >> 3) & 0x1F];
        out[oi + 1] = BASE32_ALPHABET[((b0 << 2) | (b1 >> 6)) & 0x1F];
        out[oi + 2] = BASE32_ALPHABET[(b1 >> 1) & 0x1F];
        out[oi + 3] = BASE32_ALPHABET[((b1 << 4) | (b2 >> 4)) & 0x1F];
        out[oi + 4] = BASE32_ALPHABET[((b2 << 1) | (b3 >> 7)) & 0x1F];
        out[oi + 5] = BASE32_ALPHABET[(b3 >> 2) & 0x1F];
        out[oi + 6] = BASE32_ALPHABET[((b3 << 3) | (b4 >> 5)) & 0x1F];
        out[oi + 7] = BASE32_ALPHABET[b4 & 0x1F];
        bi += 5;
        oi += 8;
    }
    return out;
}

/// Decode Base32 (RFC 4648, no padding) to raw bytes.
pub fn base32Decode(allocator: Allocator, encoded: []const u8) ![]u8 {
    if (encoded.len % 8 != 0) return error.InvalidBase32;
    const out_len = (encoded.len / 8) * 5;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);
    base32DecodeInto(out, encoded) catch return error.InvalidBase32;
    return out;
}

/// Decode Base32 into a caller-provided buffer (no allocation).
fn base32DecodeInto(out: []u8, encoded: []const u8) !void {
    if (encoded.len % 8 != 0) return error.InvalidBase32;
    const expected_len = (encoded.len / 8) * 5;
    if (out.len < expected_len) return error.InvalidBase32;
    var ei: usize = 0;
    var oi: usize = 0;
    while (ei < encoded.len) : (ei += 8) {
        var vals: [8]u8 = undefined;
        for (0..8) |j| {
            const c = encoded[ei + j];
            if (c >= 'A' and c <= 'Z') {
                vals[j] = c - 'A';
            } else if (c >= '2' and c <= '7') {
                vals[j] = c - '2' + 26;
            } else {
                return error.InvalidBase32;
            }
        }
        out[oi + 0] = (vals[0] << 3) | (vals[1] >> 2);
        out[oi + 1] = (vals[1] << 6) | (vals[2] << 1) | (vals[3] >> 4);
        out[oi + 2] = (vals[3] << 4) | (vals[4] >> 1);
        out[oi + 3] = (vals[4] << 7) | (vals[5] << 2) | (vals[6] >> 3);
        out[oi + 4] = (vals[6] << 5) | vals[7];
        oi += 5;
    }
}

/// Generate a 20-byte TOTP secret.
/// If `config.deterministic` is true, derives from username + salt (testing only).
/// Otherwise generates a cryptographically random secret.
fn generateSecret(allocator: Allocator, username: []const u8, config: MfaConfig) ![]u8 {
    const secret = try allocator.alloc(u8, 20);
    errdefer allocator.free(secret);
    if (config.deterministic) {
        // Deterministic secrets are derivable by anyone who knows the
        // username + salt. Physically unreachable outside `zig test`
        // builds: misuse in production would destroy MFA for all users.
        if (comptime !builtin.is_test) return error.DeterministicModeIsTestOnly;
        var prk = HkdfSha256.extract(config.salt, username);
        defer crypto.secureZero(u8, &prk);
        HkdfSha256.expand(secret[0..20], "totp-secret-v1", prk);
    } else {
        // Fail closed: no silent low-entropy fallback on a credential path.
        try std.Io.Threaded.global_single_threaded.io().randomSecure(secret);
    }
    return secret;
}

/// Enroll a user for TOTP MFA.
/// Returns the Base32 secret and scratch codes.
///
/// Telemetry: emits one `auth.mfa.enroll` span per call. Subject id is
/// the `username` — at enrollment time the username IS the public
/// identifier being enrolled (not a credential — the secret is what's
/// new and it stays on the stack). On any error path the span closes
/// `.error_` with no subject id attached.
pub fn enroll(allocator: Allocator, username: []const u8, config: MfaConfig) !Enrollment {
    try config.validate();
    const span = observability.startAuthnSpan("mfa.enroll");
    var ok: bool = false;
    defer observability.endAuthnSpan(span, ok, if (ok) username else null);

    const raw_secret = try generateSecret(allocator, username, config);
    defer {
        crypto.secureZero(u8, raw_secret);
        allocator.free(raw_secret);
    }

    const secret_base32 = try base32Encode(allocator, raw_secret);
    errdefer allocator.free(secret_base32);

    const scodes = try allocator.alloc([]u8, config.scratch_code_count);
    var allocated: usize = 0;
    errdefer {
        for (scodes[0..allocated]) |code| {
            crypto.secureZero(u8, code);
            allocator.free(code);
        }
        allocator.free(scodes);
    }

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

    ok = true;
    return Enrollment{ .secret_base32 = secret_base32, .scratch_codes = scodes };
}

/// Generate a TOTP code from a Base32-encoded secret.
pub fn generateCode(allocator: Allocator, secret_base32: []const u8, timestamp_ms: u64, config: MfaConfig) !u32 {
    try config.validate();
    const secret_raw = try base32Decode(allocator, secret_base32);
    defer {
        crypto.secureZero(u8, secret_raw);
        allocator.free(secret_raw);
    }
    return generateCodeFromRaw(secret_raw, timestamp_ms, config);
}

/// Generate a TOTP code from raw secret bytes (no allocation).
fn generateCodeFromRaw(secret_raw: []const u8, timestamp_ms: u64, config: MfaConfig) u32 {
    const timestep = timestamp_ms / (config.step_seconds * 1000);
    var counter_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &counter_be, timestep, .big);

    comptime std.debug.assert(HmacSha1.mac_length == 20); // RFC 4226 dynamic truncation reads h[19]
    var h: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&h, &counter_be, secret_raw);
    defer crypto.secureZero(u8, &h);

    const offset = h[19] & 0x0F;
    const bin_code: u32 = (@as(u32, h[offset] & 0x7f) << 24) |
        (@as(u32, h[offset + 1]) << 16) |
        (@as(u32, h[offset + 2]) << 8) |
        (@as(u32, h[offset + 3]));

    const mod = POW10[config.digits];
    return bin_code % mod;
}

/// Verify a TOTP code against a Base32-encoded secret, checking within the
/// configured time window to account for clock skew.
/// Uses constant-time comparison to prevent timing side-channels.
///
/// Telemetry: emits one `auth.mfa` span per call. NO subject id is
/// attached — `verifyCode` receives only the secret blob and code; it
/// has no notion of who the verifier is. Span status: `.ok` on accept,
/// `.error_` on reject. The secret_base32 and code values NEVER appear
/// as span attributes.
pub fn verifyCode(allocator: Allocator, secret_base32: []const u8, timestamp_ms: u64, code: u32, config: MfaConfig) !bool {
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
    var match: bool = false;

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
            match = true;
        }
    }
    ok = match;
    return match;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

fn deterministicConfig() MfaConfig {
    return .{ .deterministic = true };
}

test "base32 round-trip" {
    const allocator = std.testing.allocator;
    const raw = "Hello, World!!!!"; // 16 bytes, not divisible by 5 — tests padding
    const encoded = try base32Encode(allocator, raw);
    defer allocator.free(encoded);
    const decoded = try base32Decode(allocator, encoded);
    defer allocator.free(decoded);
    // Decoded may have trailing zero-padding from block alignment.
    try std.testing.expectEqualSlices(u8, raw, decoded[0..raw.len]);
}

test "base32Decode rejects invalid characters" {
    const allocator = std.testing.allocator;
    const result = base32Decode(allocator, "0000000!");
    try std.testing.expectError(error.InvalidBase32, result);
}

test "base32Decode rejects non-block-aligned input" {
    const allocator = std.testing.allocator;
    const result = base32Decode(allocator, "ABCDE");
    try std.testing.expectError(error.InvalidBase32, result);
}

test "enroll produces Base32 secret and scratch codes" {
    const allocator = std.testing.allocator;
    const enrollment = try enroll(allocator, "alice", deterministicConfig());
    defer enrollment.deinit(allocator);

    try std.testing.expect(enrollment.secret_base32.len > 0);
    try std.testing.expectEqual(@as(usize, 2), enrollment.scratch_codes.len);

    for (enrollment.scratch_codes) |code| {
        try std.testing.expectEqual(@as(usize, 32), code.len);
        for (code) |c| {
            try std.testing.expect((c >= 'A' and c <= 'Z') or (c >= '2' and c <= '7'));
        }
    }
}

test "enroll deterministic is reproducible for same username and salt" {
    const allocator = std.testing.allocator;
    const cfg = deterministicConfig();
    const e1 = try enroll(allocator, "bob", cfg);
    defer e1.deinit(allocator);
    const e2 = try enroll(allocator, "bob", cfg);
    defer e2.deinit(allocator);

    try std.testing.expectEqualSlices(u8, e1.secret_base32, e2.secret_base32);
}

test "enroll random produces different secrets" {
    const allocator = std.testing.allocator;
    const e1 = try enroll(allocator, "carol", .{});
    defer e1.deinit(allocator);
    const e2 = try enroll(allocator, "carol", .{});
    defer e2.deinit(allocator);

    // Two random enrollments should differ (probability of collision: ~2^-160).
    try std.testing.expect(!std.mem.eql(u8, e1.secret_base32, e2.secret_base32));
}

test "enroll differs for different salts (deterministic mode)" {
    const allocator = std.testing.allocator;
    const e1 = try enroll(allocator, "carol", .{ .deterministic = true, .salt = "salt-a" });
    defer e1.deinit(allocator);
    const e2 = try enroll(allocator, "carol", .{ .deterministic = true, .salt = "salt-b" });
    defer e2.deinit(allocator);

    try std.testing.expect(!std.mem.eql(u8, e1.secret_base32, e2.secret_base32));
}

test "generateCode returns a code within digit range" {
    const allocator = std.testing.allocator;
    const enrollment = try enroll(allocator, "dave", deterministicConfig());
    defer enrollment.deinit(allocator);

    const code = try generateCode(allocator, enrollment.secret_base32, 1_700_000_000_000, deterministicConfig());
    try std.testing.expect(code < 1_000_000);
}

test "generateCode is deterministic for same timestamp" {
    const allocator = std.testing.allocator;
    const enrollment = try enroll(allocator, "eve", deterministicConfig());
    defer enrollment.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const cfg = deterministicConfig();
    const c1 = try generateCode(allocator, enrollment.secret_base32, ts, cfg);
    const c2 = try generateCode(allocator, enrollment.secret_base32, ts, cfg);
    try std.testing.expectEqual(c1, c2);
}

test "verifyCode accepts correct code" {
    const allocator = std.testing.allocator;
    const cfg = deterministicConfig();
    const enrollment = try enroll(allocator, "frank", cfg);
    defer enrollment.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const code = try generateCode(allocator, enrollment.secret_base32, ts, cfg);
    const valid = try verifyCode(allocator, enrollment.secret_base32, ts, code, cfg);
    try std.testing.expect(valid);
}

test "verifyCode rejects wrong code" {
    const allocator = std.testing.allocator;
    const cfg = deterministicConfig();
    const enrollment = try enroll(allocator, "grace", cfg);
    defer enrollment.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const valid = try verifyCode(allocator, enrollment.secret_base32, ts, 999999, cfg);
    const real_code = try generateCode(allocator, enrollment.secret_base32, ts, cfg);
    if (real_code != 999999) {
        try std.testing.expect(!valid);
    }
}

test "verifyCode accepts code within time window" {
    const allocator = std.testing.allocator;
    const config = MfaConfig{ .deterministic = true, .window = 1 };
    const enrollment = try enroll(allocator, "heidi", config);
    defer enrollment.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const future_ts = ts + config.step_seconds * 1000;
    const future_code = try generateCode(allocator, enrollment.secret_base32, future_ts, config);

    const valid = try verifyCode(allocator, enrollment.secret_base32, ts, future_code, config);
    try std.testing.expect(valid);
}

test "enroll with custom scratch code count" {
    const allocator = std.testing.allocator;
    const enrollment = try enroll(allocator, "ivan", .{ .deterministic = true, .scratch_code_count = 5 });
    defer enrollment.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 5), enrollment.scratch_codes.len);
}

test "base32 RFC 4648 test vectors (mod-5 inputs)" {
    const allocator = std.testing.allocator;

    // RFC 4648 Section 10 test vectors (only mod-5 lengths for exact round-trip).
    const vectors = [_]struct { raw: []const u8, encoded: []const u8 }{
        .{ .raw = "fooba", .encoded = "MZXW6YTB" },
        .{ .raw = "foobar", .encoded = "MZXW6YTBOI======" },
    };

    // For mod-5 lengths, our no-padding encoder produces exact round-trips.
    for (vectors) |v| {
        if (v.raw.len % 5 == 0) {
            const encoded = try base32Encode(allocator, v.raw);
            defer allocator.free(encoded);
            try std.testing.expectEqualSlices(u8, v.encoded[0..encoded.len], encoded);

            const decoded = try base32Decode(allocator, encoded);
            defer allocator.free(decoded);
            try std.testing.expectEqualSlices(u8, v.raw, decoded);
        }
    }
}

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

test "enroll with default config produces 32-char base32 secret" {
    // Exercises the non-deterministic path through randomSecure; error propagation is enforced by the type system (try in generateSecret).
    const allocator = std.testing.allocator;
    const e = try enroll(allocator, "secure-rng-user", .{});
    defer e.deinit(allocator);
    try std.testing.expect(e.secret_base32.len == 32);
}

test "scratch codes are 32 chars and independent of the TOTP secret" {
    const allocator = std.testing.allocator;
    const e1 = try enroll(allocator, "rc-user", .{});
    defer e1.deinit(allocator);
    for (e1.scratch_codes) |code| {
        try std.testing.expectEqual(@as(usize, SCRATCH_CODE_LEN), code.len);
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
