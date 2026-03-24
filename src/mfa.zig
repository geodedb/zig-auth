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
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

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
    /// If true, derive the secret deterministically from username + salt
    /// (for testing only). If false (default), generate a random secret.
    deterministic: bool = false,
    /// Salt for deterministic derivation. Ignored when `deterministic` is false.
    salt: []const u8 = "auth-mfa-salt-v1",
};

/// Enrollment result containing the Base32-encoded secret and scratch codes.
pub const Enrollment = struct {
    secret_base32: []u8,
    scratch_codes: [][]u8,

    pub fn deinit(self: *const Enrollment, allocator: Allocator) void {
        for (self.scratch_codes) |code| allocator.free(code);
        allocator.free(self.scratch_codes);
        crypto.secureZero(u8, self.secret_base32);
        allocator.free(self.secret_base32);
    }
};

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

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
    if (config.deterministic) {
        var prk = HkdfSha256.extract(config.salt, username);
        defer crypto.secureZero(u8, &prk);
        HkdfSha256.expand(secret[0..20], "totp-secret-v1", prk);
    } else {
        crypto.random.bytes(secret);
    }
    return secret;
}

/// Enroll a user for TOTP MFA.
/// Returns the Base32 secret and scratch codes.
pub fn enroll(allocator: Allocator, username: []const u8, config: MfaConfig) !Enrollment {
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
        for (scodes[0..allocated]) |code| allocator.free(code);
        allocator.free(scodes);
    }

    // Hoist HKDF extract outside the loop (salt + raw_secret are invariant).
    var prk = HkdfSha256.extract(config.salt, raw_secret);
    defer crypto.secureZero(u8, &prk);

    while (allocated < config.scratch_code_count) : (allocated += 1) {
        const code = try allocator.alloc(u8, 8);
        var scratch_bytes: [8]u8 = undefined;
        defer crypto.secureZero(u8, &scratch_bytes);
        var info_buf: [32]u8 = undefined;
        const info = std.fmt.bufPrint(&info_buf, "scratch-code-{d}", .{allocated}) catch unreachable;
        HkdfSha256.expand(&scratch_bytes, info, prk);
        for (0..8) |j| {
            code[j] = BASE32_ALPHABET[@as(usize, scratch_bytes[j] & 0x1F)];
        }
        scodes[allocated] = code;
    }

    return Enrollment{ .secret_base32 = secret_base32, .scratch_codes = scodes };
}

/// Generate a TOTP code from a Base32-encoded secret.
pub fn generateCode(allocator: Allocator, secret_base32: []const u8, timestamp_ms: u64, config: MfaConfig) !u32 {
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

    var h: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&h, &counter_be, secret_raw);
    defer crypto.secureZero(u8, &h);

    const offset = h[19] & 0x0F;
    const bin_code: u32 = (@as(u32, h[offset] & 0x7f) << 24) |
        (@as(u32, h[offset + 1]) << 16) |
        (@as(u32, h[offset + 2]) << 8) |
        (@as(u32, h[offset + 3]));

    var mod: u32 = 1;
    var i: u8 = 0;
    while (i < config.digits) : (i += 1) mod *= 10;
    return bin_code % mod;
}

/// Verify a TOTP code against a Base32-encoded secret, checking within the
/// configured time window to account for clock skew.
/// Uses constant-time comparison to prevent timing side-channels.
pub fn verifyCode(allocator: Allocator, secret_base32: []const u8, timestamp_ms: u64, code: u32, config: MfaConfig) !bool {
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
        try std.testing.expectEqual(@as(usize, 8), code.len);
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
