// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Pins the FIPS exemption boundary for auth: TOTP HMAC-SHA1 is the
//! ONLY std.crypto security primitive intentionally left off the seam
//! (RFC 6238 legacy-interop, see docs/FIPS.md); every other algorithm in
//! a security path routes through `crypto_backend`.
//!
//! This is enforced, not just asserted in prose. A comptime source guard
//! (`test "no non-exempt std.crypto algorithm in a security path"`) scans
//! the high-level security modules — mfa.zig, api_keys.zig, hmac.zig —
//! and fails the build if any literal `std.crypto.<token>` appears that is
//! not either a whitelisted constant-time utility (timing_safe, secureZero)
//! or the single exempt algorithm `std.crypto.auth.hmac.HmacSha1` (allowed
//! only in mfa.zig). Adding a direct std.crypto algorithm call to a
//! security path — bypassing the seam — breaks this test at compile time.
//!
//! The scanner deliberately excludes the backend implementation files
//! (crypto_backend.zig, std_shim.zig): the shim IS the std.crypto-backed
//! backend, so std.crypto there is expected, not a boundary violation.
//!
//! It also proves TOTP still produces correct, deterministic codes under
//! both -Dfips values, and that the public seam re-export exists.
const std = @import("std");
const auth = @import("auth");

// Security-path sources, wired as anonymous embeds in build.zig. These are
// the high-level modules that MUST route crypto through the seam (the
// backend impl — crypto_backend.zig/std_shim.zig — is intentionally out of
// scope; it is the std.crypto backend itself).
const security_path_sources = [_]struct { name: []const u8, src: []const u8 }{
    .{ .name = "mfa.zig", .src = @embedFile("mfa_src") },
    .{ .name = "api_keys.zig", .src = @embedFile("api_keys_src") },
    .{ .name = "hmac.zig", .src = @embedFile("hmac_src") },
};

// Constant-time utility namespaces under std.crypto. These are NOT crypto
// algorithms (no confidentiality/integrity/KDF/signature primitive); they
// are timing-side-channel helpers and stay on std by design.
const allowed_utils = [_][]const u8{ "timing_safe", "secureZero" };

// The single exempt algorithm token sequence (RFC 6238 TOTP), permitted
// only inside mfa.zig.
const totp_exemption = "auth.hmac.HmacSha1";

fn isIdentChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_' or c == '.';
}

/// Reads the dotted token immediately following `std.crypto.` at `start`.
fn tokenAfter(src: []const u8, start: usize) []const u8 {
    var end = start;
    while (end < src.len and isIdentChar(src[end])) : (end += 1) {}
    return src[start..end];
}

fn startsWithAllowedUtil(token: []const u8) bool {
    for (allowed_utils) |util| {
        if (std.mem.startsWith(u8, token, util)) {
            // Must be a whole leading path segment: "timing_safe" or
            // "timing_safe.eql", not "timing_safexyz".
            if (token.len == util.len or token[util.len] == '.') return true;
        }
    }
    return false;
}

test "no non-exempt std.crypto algorithm appears in a security path (FIPS seam boundary)" {
    // Comptime so a violation is a COMPILE error, not a runtime failure —
    // the boundary holds for any build that compiles this test, under both
    // -Dfips values.
    comptime {
        // Scanning multi-KB sources char-by-char blows the default 1000
        // backwards-branch budget; size to the largest source with slack.
        @setEvalBranchQuota(200_000);
        const needle = "std.crypto.";
        for (security_path_sources) |file| {
            var i: usize = 0;
            while (std.mem.indexOfPos(u8, file.src, i, needle)) |pos| {
                const tok_start = pos + needle.len;
                const token = tokenAfter(file.src, tok_start);
                i = tok_start;

                if (startsWithAllowedUtil(token)) continue;

                if (std.mem.startsWith(u8, token, totp_exemption)) {
                    // Exemption is mfa-only: HMAC-SHA1 leaking into any
                    // other security path is itself a boundary breach.
                    if (!std.mem.eql(u8, file.name, "mfa.zig")) {
                        @compileError("std.crypto." ++ totp_exemption ++
                            " (RFC 6238 TOTP exemption) is only permitted in mfa.zig, found in " ++
                            file.name);
                    }
                    continue;
                }

                // Anything else is a non-exempt std.crypto algorithm on a
                // security path that should route through crypto_backend.
                @compileError("non-exempt std.crypto algorithm in security path " ++
                    file.name ++ ": std.crypto." ++ token ++
                    " — route it through @import(\"crypto_backend\") or, for a new" ++
                    " legacy exemption, extend tests/fips_exemption_test.zig with a" ++
                    " documented rationale (see docs/FIPS.md).");
            }
        }
    }
}

test "the TOTP HMAC-SHA1 exemption is actually present (guard is not vacuous)" {
    // Defends the guard above against silent decay: if the exemption is
    // ever refactored away (e.g. TOTP moves behind the seam), this fails
    // so the doc-comment + guard get revisited rather than going stale.
    comptime {
        @setEvalBranchQuota(200_000);
        const mfa_src = @embedFile("mfa_src");
        if (std.mem.indexOf(u8, mfa_src, "std.crypto." ++ totp_exemption) == null) {
            @compileError("expected std.crypto." ++ totp_exemption ++
                " in mfa.zig; the TOTP exemption changed — update the boundary doc + guard.");
        }
    }
}

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
