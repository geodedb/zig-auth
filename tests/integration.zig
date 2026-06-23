// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests for auth.
//!
//! These tests verify cross-module interactions and end-to-end workflows.

const std = @import("std");
const auth = @import("auth");

// ============================================================================
// HMAC Integration
// ============================================================================

test "integration: HMAC key derivation and record hashing" {
    const master = [_]u8{0x42} ** 32;
    const key = auth.hmac.deriveHmacKey(&master, .{});

    const props = [_]auth.hmac.KeyValue{
        .{ .key = "user", .value = "alice" },
        .{ .key = "role", .value = "admin" },
    };
    const h1 = try auth.hmac.computeRecordHmac(&key, &props);
    const h2 = try auth.hmac.computeRecordHmac(&key, &props);
    try std.testing.expectEqualSlices(u8, &h1, &h2);
}

test "integration: HMAC chain hash detects tampering" {
    const master = [_]u8{0x42} ** 32;
    const key = auth.hmac.deriveHmacKey(&master, .{});

    const rec1 = try auth.hmac.computeRecordHmac(&key, &[_]auth.hmac.KeyValue{
        .{ .key = "id", .value = "1" },
    });
    const rec2 = try auth.hmac.computeRecordHmac(&key, &[_]auth.hmac.KeyValue{
        .{ .key = "id", .value = "2" },
    });

    const chain = try auth.hmac.computeChainHash(&key, &[_][32]u8{ rec1, rec2 }, 2);

    const tampered = try auth.hmac.computeRecordHmac(&key, &[_]auth.hmac.KeyValue{
        .{ .key = "id", .value = "X" },
    });
    const bad_chain = try auth.hmac.computeChainHash(&key, &[_][32]u8{ rec1, tampered }, 2);
    try std.testing.expect(!auth.hmac.verifyHmac(&chain, &bad_chain));
}

test "integration: HMAC hex encoding round-trip" {
    const master = [_]u8{0xab} ** 32;
    const key = auth.hmac.deriveHmacKey(&master, .{});
    const hex = auth.hmac.hmacToHex(&key);
    const recovered = try auth.hmac.hexToHmac(&hex);
    try std.testing.expect(auth.hmac.verifyHmac(&key, &recovered));
}

test "integration: computeRecordHmac returns error for too many properties" {
    const key = [_]u8{0x01} ** 32;
    var props: [129]auth.hmac.KeyValue = undefined;
    for (&props) |*p| {
        p.* = .{ .key = "k", .value = "v" };
    }
    const result = auth.hmac.computeRecordHmac(&key, &props);
    try std.testing.expectError(error.TooManyProperties, result);
}

// ============================================================================
// API Key Integration
// ============================================================================

test "integration: API key create, validate, revoke lifecycle" {
    const allocator = std.testing.allocator;

    var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{});
    defer mgr.deinit();

    const key_string = try mgr.createKey(42, "ci-token", &[_][]const u8{ "read", "write" }, null);
    defer allocator.free(key_string);

    const key = (try mgr.validateKey(key_string)).?;
    defer mgr.freeValidatedKey(key);
    try std.testing.expectEqual(@as(u64, 42), key.user_id);
    try std.testing.expect(auth.api_keys.ApiKeyManager.hasScope(&key, "read"));
    try std.testing.expect(!auth.api_keys.ApiKeyManager.hasScope(&key, "admin"));

    const parsed = try auth.api_keys.parseApiKey(key_string);
    try std.testing.expect(mgr.revokeKey(parsed.id));

    try std.testing.expect((try mgr.validateKey(key_string)) == null);
}

test "integration: API key with custom prefix" {
    const allocator = std.testing.allocator;

    var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{ .key_prefix = "myapp2" });
    defer mgr.deinit();

    const key_string = try mgr.createKey(1, "test", &[_][]const u8{"*"}, null);
    defer allocator.free(key_string);

    try std.testing.expect(std.mem.startsWith(u8, key_string, "myapp2."));
    if (try mgr.validateKey(key_string)) |k| {
        mgr.freeValidatedKey(k);
    } else return error.TestUnexpectedResult;
}

test "integration: Bearer token parsing feeds into validation" {
    const allocator = std.testing.allocator;

    var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{});
    defer mgr.deinit();

    const key_string = try mgr.createKey(1, "bearer-test", &[_][]const u8{"read"}, null);
    defer allocator.free(key_string);

    const header = try std.fmt.allocPrint(allocator, "Bearer {s}", .{key_string});
    defer allocator.free(header);

    const token = auth.api_keys.parseBearerToken(header).?;
    if (try mgr.validateKey(token)) |k| {
        mgr.freeValidatedKey(k);
    } else return error.TestUnexpectedResult;
}

test "integration: listUserKeys returns owned copies" {
    const allocator = std.testing.allocator;

    var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{});
    defer mgr.deinit();

    const k1 = try mgr.createKey(1, "key-a", &[_][]const u8{"read"}, null);
    defer allocator.free(k1);

    const keys = try mgr.listUserKeys(allocator, 1);
    defer auth.api_keys.ApiKeyManager.freeKeyList(allocator, keys);

    try std.testing.expectEqual(@as(usize, 1), keys.len);
    try std.testing.expectEqualStrings("key-a", keys[0].name);
}

// ============================================================================
// MFA Integration
// ============================================================================

test "integration: MFA enroll and verify code" {
    const allocator = std.testing.allocator;
    const config = auth.mfa.MfaConfig{ .deterministic = true };

    const enrollment = try auth.mfa.enroll(allocator, "alice", config);
    defer enrollment.deinit(allocator);

    const ts: u64 = 1_700_000_000_000;
    const code = try auth.mfa.generateCode(allocator, enrollment.secret_base32, ts, config);
    const valid = try auth.mfa.verifyCode(allocator, enrollment.secret_base32, ts, code, config);
    try std.testing.expect(valid);
}

test "integration: MFA random enrollment produces unique secrets" {
    const allocator = std.testing.allocator;

    const e1 = try auth.mfa.enroll(allocator, "same-user", .{});
    defer e1.deinit(allocator);
    const e2 = try auth.mfa.enroll(allocator, "same-user", .{});
    defer e2.deinit(allocator);

    try std.testing.expect(!std.mem.eql(u8, e1.secret_base32, e2.secret_base32));
}

test "integration: MFA with custom salt isolates secrets (deterministic)" {
    const allocator = std.testing.allocator;

    const e1 = try auth.mfa.enroll(allocator, "same-user", .{ .deterministic = true, .salt = "app-a" });
    defer e1.deinit(allocator);
    const e2 = try auth.mfa.enroll(allocator, "same-user", .{ .deterministic = true, .salt = "app-b" });
    defer e2.deinit(allocator);

    try std.testing.expect(!std.mem.eql(u8, e1.secret_base32, e2.secret_base32));
}

test "integration: version is defined" {
    try std.testing.expectEqualStrings("0.1.9", auth.version);
}

// ============================================================================
// Adversarial Tests
// ============================================================================

test "adversarial: parseApiKey malformed input classes" {
    const cases = [_][]const u8{
        "", ".", "..", "ak1.", "ak1..", ".abc.def",
        "ak1.!!!.???",                                                                  "ak1.AAAA.BBBB", // wrong decoded sizes
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
    // The NEXT step's code is accepted unconditionally: replay tracking
    // is step-based, so even a value collision with the prior code is
    // accepted at the new step.
    const ts2 = ts + 30_000;
    const code2 = try auth.mfa.generateCode(allocator, e.secret_base32, ts2, .{});
    try std.testing.expect(try auth.mfa.verifyCodeOnce(allocator, e.secret_base32, ts2, code2, &last_step, .{}));
}
