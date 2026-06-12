// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! HMAC chain integrity module for auth storage.
//!
//! Provides deterministic HMAC-SHA256 computation over key-value properties,
//! HKDF-based key derivation from master keys, chain hashing for tamper
//! detection, and constant-time verification primitives.
//!
//! This module is a pure crypto + serialization layer with no dependency on
//! any I/O subsystem.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const timing_safe = std.crypto.timing_safe;

/// Length of an HMAC-SHA256 output in bytes.
pub const HMAC_LEN: usize = 32;

/// Length of an HMAC key in bytes.
pub const KEY_LEN: usize = 32;

/// A key-value pair used as input to `computeRecordHmac`.
pub const KeyValue = struct {
    key: []const u8,
    value: []const u8,
};

/// Configuration for HKDF key derivation.
pub const HkdfConfig = struct {
    /// Domain-separation salt for HKDF extract step.
    salt: []const u8 = "auth-hmac-v1",
    /// Domain-separation info for HKDF expand step.
    info: []const u8 = "auth-chain-integrity",
};

/// Derive an HMAC signing key from a master key using HKDF-SHA256.
///
/// The derivation uses configurable salt and info strings so the output
/// is domain-separated from the raw master key and any other HKDF-derived keys.
pub fn deriveHmacKey(master_key: *const [32]u8, config: HkdfConfig) [32]u8 {
    var prk = HkdfSha256.extract(config.salt, master_key);
    defer std.crypto.secureZero(u8, &prk);
    var okm: [32]u8 = undefined;
    HkdfSha256.expand(&okm, config.info, prk);
    return okm;
}

/// Compute HMAC-SHA256 over a set of key-value properties.
///
/// Properties are sorted by key then value (lexicographic, ascending) before
/// hashing to guarantee deterministic output regardless of input order,
/// including duplicate keys (total order over key then value).
/// Each property is serialized as:
///
///     key_len (u32 LE) || key || value_len (u32 LE) || value
///
/// This length-prefixed format is unambiguous: no combination of different
/// key/value contents can produce the same byte stream.
pub fn computeRecordHmac(key: *const [32]u8, props: []const KeyValue) error{TooManyProperties}![32]u8 {
    const max_stack = 128;

    if (props.len <= max_stack) {
        var indices: [max_stack]usize = undefined;
        return computeRecordHmacWithBuf(key, props, indices[0..props.len]);
    } else {
        return error.TooManyProperties;
    }
}

fn computeRecordHmacWithBuf(key: *const [32]u8, props: []const KeyValue, indices: []usize) [32]u8 {
    for (indices, 0..) |*idx, i| {
        idx.* = i;
    }

    const Ctx = struct {
        kv: []const KeyValue,

        /// Sort-context comparator (key, then value) — public only for std.sort.
        pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
            const ka = ctx.kv[a].key;
            const kb = ctx.kv[b].key;
            const va = ctx.kv[a].value;
            const vb = ctx.kv[b].value;
            switch (std.mem.order(u8, ka, kb)) {
                .lt => return true,
                .gt => return false,
                .eq => return std.mem.order(u8, va, vb) == .lt,
            }
        }
    };

    std.mem.sortUnstable(usize, indices, Ctx{ .kv = props }, Ctx.lessThan);

    var hmac = HmacSha256.init(key);
    for (indices) |idx| {
        feedKv(&hmac, props[idx]);
    }
    var out: [32]u8 = undefined;
    hmac.final(&out);
    return out;
}

fn feedKv(hmac: *HmacSha256, kv: KeyValue) void {
    const klen: u32 = @intCast(kv.key.len);
    hmac.update(std.mem.asBytes(&std.mem.nativeToLittle(u32, klen)));
    hmac.update(kv.key);

    const vlen: u32 = @intCast(kv.value.len);
    hmac.update(std.mem.asBytes(&std.mem.nativeToLittle(u32, vlen)));
    hmac.update(kv.value);
}

/// Compute a chain hash over a sequence of record HMACs and a record count.
///
/// The chain hash is:
///
///     HMAC-SHA256(key, record_hmac[0] || record_hmac[1] || ... || count_le64)
///
/// Including the record count prevents truncation attacks where an attacker
/// removes trailing records while keeping the prefix valid.
pub fn computeChainHash(key: *const [32]u8, record_hmacs: []const [32]u8, record_count: u64) error{RecordCountMismatch}![32]u8 {
    if (record_hmacs.len != record_count) return error.RecordCountMismatch;
    var hmac = HmacSha256.init(key);
    for (record_hmacs) |rec| {
        hmac.update(&rec);
    }
    hmac.update(std.mem.asBytes(&std.mem.nativeToLittle(u64, record_count)));
    var out: [32]u8 = undefined;
    hmac.final(&out);
    return out;
}

/// Constant-time comparison of two 32-byte HMACs.
///
/// Returns `true` if and only if every byte matches. The comparison time
/// does not depend on the position of the first differing byte.
pub fn verifyHmac(expected: *const [32]u8, actual: *const [32]u8) bool {
    return timing_safe.eql([32]u8, expected.*, actual.*);
}

/// Encode a 32-byte HMAC as a 64-character lowercase hex string.
pub fn hmacToHex(hmac_bytes: *const [32]u8) [64]u8 {
    return std.fmt.bytesToHex(hmac_bytes.*, .lower);
}

/// Decode a 64-character hex string (any case) into a 32-byte HMAC.
///
/// Returns `error.InvalidCharacter` if any character is not a valid hex digit.
pub fn hexToHmac(hex: *const [64]u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

test "deriveHmacKey is deterministic" {
    const master = [_]u8{0xab} ** 32;
    const k1 = deriveHmacKey(&master, .{});
    const k2 = deriveHmacKey(&master, .{});
    try std.testing.expectEqualSlices(u8, &k1, &k2);
}

test "deriveHmacKey is domain-separated from raw master key" {
    const master = [_]u8{0x42} ** 32;
    const derived = deriveHmacKey(&master, .{});
    try std.testing.expect(!std.mem.eql(u8, &derived, &master));
}

test "deriveHmacKey respects custom config" {
    const master = [_]u8{0x42} ** 32;
    const default_derived = deriveHmacKey(&master, .{});
    const custom_derived = deriveHmacKey(&master, .{
        .salt = "my-app-hmac-v1",
        .info = "my-chain-integrity",
    });
    try std.testing.expect(!std.mem.eql(u8, &default_derived, &custom_derived));
}

test "computeRecordHmac is deterministic for same input" {
    const key = [_]u8{0x01} ** 32;
    const props = [_]KeyValue{
        .{ .key = "username", .value = "alice" },
        .{ .key = "role", .value = "admin" },
    };
    const h1 = try computeRecordHmac(&key, &props);
    const h2 = try computeRecordHmac(&key, &props);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "computeRecordHmac differs for different input" {
    const key = [_]u8{0x01} ** 32;
    const props_a = [_]KeyValue{
        .{ .key = "username", .value = "alice" },
    };
    const props_b = [_]KeyValue{
        .{ .key = "username", .value = "bob" },
    };
    const ha = try computeRecordHmac(&key, &props_a);
    const hb = try computeRecordHmac(&key, &props_b);
    try std.testing.expect(!std.mem.eql(u8, &ha, &hb));
}

test "computeRecordHmac sorts keys - different order produces same HMAC" {
    const key = [_]u8{0x02} ** 32;
    const order_ab = [_]KeyValue{
        .{ .key = "alpha", .value = "1" },
        .{ .key = "beta", .value = "2" },
    };
    const order_ba = [_]KeyValue{
        .{ .key = "beta", .value = "2" },
        .{ .key = "alpha", .value = "1" },
    };
    const h_ab = try computeRecordHmac(&key, &order_ab);
    const h_ba = try computeRecordHmac(&key, &order_ba);
    try std.testing.expectEqualSlices(u8, &h_ab, &h_ba);
}

test "computeChainHash is deterministic" {
    const key = [_]u8{0x03} ** 32;
    const rec1 = [_]u8{0xaa} ** 32;
    const rec2 = [_]u8{0xbb} ** 32;
    const records = [_][32]u8{ rec1, rec2 };
    const c1 = try computeChainHash(&key, &records, 2);
    const c2 = try computeChainHash(&key, &records, 2);
    try std.testing.expectEqualSlices(u8, &c1, &c2);
}

test "computeChainHash differs for different record sets" {
    const key = [_]u8{0x04} ** 32;
    const rec_a = [_]u8{0xcc} ** 32;
    const rec_b = [_]u8{0xdd} ** 32;
    const records_1 = [_][32]u8{rec_a};
    const records_2 = [_][32]u8{ rec_a, rec_b };
    const c1 = try computeChainHash(&key, &records_1, 1);
    const c2 = try computeChainHash(&key, &records_2, 2);
    try std.testing.expect(!std.mem.eql(u8, &c1, &c2));
}

test "hmacToHex and hexToHmac round-trip" {
    const original = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const hex = hmacToHex(&original);
    const recovered = try hexToHmac(&hex);
    try std.testing.expectEqualSlices(u8, &original, &recovered);
}

test "verifyHmac returns true for matching" {
    const a = [_]u8{0xde} ** 32;
    const b = [_]u8{0xde} ** 32;
    try std.testing.expect(verifyHmac(&a, &b));
}

test "computeRecordHmac returns error for too many properties" {
    const key = [_]u8{0x01} ** 32;
    var props: [129]KeyValue = undefined;
    for (&props) |*p| {
        p.* = .{ .key = "k", .value = "v" };
    }
    const result = computeRecordHmac(&key, &props);
    try std.testing.expectError(error.TooManyProperties, result);
}

test "verifyHmac returns false for non-matching" {
    const a = [_]u8{0xde} ** 32;
    var b = [_]u8{0xde} ** 32;
    b[31] = 0xff;
    try std.testing.expect(!verifyHmac(&a, &b));
}

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
