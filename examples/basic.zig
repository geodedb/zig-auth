// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic usage example: HMAC key derivation, API key lifecycle, MFA
//! enrollment + TOTP verification. Build and run: `zig build example`.

const std = @import("std");
const auth = @import("auth");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
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
    const hex = auth.hmac.hmacToHex(&mac);
    std.debug.print("record hmac: {s}\n", .{&hex});

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

    const io = std.Io.Threaded.global_single_threaded.io();
    const now_ms: u64 = @intCast(std.Io.Timestamp.now(io, .real).toMilliseconds());
    const code = try auth.mfa.generateCode(allocator, enrollment.secret_base32, now_ms, .{});
    var last_step: u64 = 0;
    const accepted = try auth.mfa.verifyCodeOnce(allocator, enrollment.secret_base32, now_ms, code, &last_step, .{});
    std.debug.print("totp code {d:0>6} accepted: {}\n", .{ code, accepted });
}
