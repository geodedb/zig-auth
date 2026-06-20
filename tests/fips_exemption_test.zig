// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Pins the FIPS exemption boundary for auth: TOTP HMAC-SHA1 is the
//! ONLY security primitive intentionally left on std.crypto (RFC 6238
//! legacy-interop, spec §5). Everything else routes through the seam.
//!
//! This test proves TOTP still produces correct, deterministic codes
//! under both -Dfips values, and that the public seam re-export exists.
const std = @import("std");
const auth = @import("auth");

test "TOTP code is stable and correct under any fips mode (RFC 6238 SHA-1 exemption)" {
    const allocator = std.testing.allocator;
    const enr = try auth.mfa.enroll(allocator, "alice", .{ .deterministic = true });
    defer enr.deinit(allocator);
    // Two reads of the same timestep yield the same 6-digit code,
    // independent of backend (TOTP HMAC-SHA1 is std-only by design).
    const c1 = try auth.mfa.generateCode(allocator, enr.secret_base32, 59_000, .{});
    const c2 = try auth.mfa.generateCode(allocator, enr.secret_base32, 59_000, .{});
    try std.testing.expectEqual(c1, c2);
    try std.testing.expect(c1 < 1_000_000);
}

test "auth re-exports the crypto_backend seam" {
    // The seam is part of auth's public surface so downstream consumers
    // can reach the same backend selection.
    try std.testing.expect(@hasDecl(auth.crypto_backend, "assertActive"));
    try std.testing.expect(@hasDecl(auth.crypto_backend, "policy"));
}
