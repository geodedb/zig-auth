// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic usage example demonstrating HMAC, API keys, and MFA.
//!
//! This file is not built by default — it shows API usage patterns
//! for developers integrating the auth library.

const std = @import("std");

// In a real project, import from the build system:
// const auth = @import("auth");
//
// Then use:
//   auth.hmac.deriveHmacKey(...)
//   auth.api_keys.ApiKeyManager.init(...)
//   auth.mfa.enroll(...)

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print("auth library usage examples\n", .{});
    try stdout.print("==========================\n\n", .{});

    // --- HMAC chain integrity ---
    try stdout.print("1. HMAC key derivation\n", .{});
    try stdout.print("   const key = auth.hmac.deriveHmacKey(&master_key, .{{}});\n\n", .{});

    // --- API key management ---
    try stdout.print("2. API key lifecycle\n", .{});
    try stdout.print("   var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{{}});\n", .{});
    try stdout.print("   const key_string = try mgr.createKey(user_id, \"ci\", &.{{\"read\"}}, null);\n", .{});
    try stdout.print("   const validated = try mgr.validateKey(key_string);\n\n", .{});

    // --- MFA/TOTP ---
    try stdout.print("3. MFA enrollment and verification\n", .{});
    try stdout.print("   const enrollment = try auth.mfa.enroll(allocator, \"alice\", .{{}});\n", .{});
    try stdout.print("   const code = try auth.mfa.generateCode(allocator, enrollment.secret_base32, ts, .{{}});\n", .{});
    try stdout.print("   const valid = try auth.mfa.verifyCode(allocator, enrollment.secret_base32, ts, code, .{{}});\n", .{});
}
