// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # auth
//!
//! Reusable authentication primitives for Zig applications.
//!
//! ## Modules
//!
//! - **hmac** — HMAC-SHA256 record hashing, chain integrity, and HKDF key derivation
//! - **api_keys** — API key creation, validation, revocation, and Bearer token parsing
//! - **mfa** — TOTP enrollment, code generation, and verification (RFC 6238)
//!
//! ## Quick Start
//!
//! ```zig
//! const auth = @import("auth");
//!
//! // HMAC chain integrity
//! const key = auth.hmac.deriveHmacKey(&master_key, .{});
//!
//! // API key management
//! var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{});
//! defer mgr.deinit();
//!
//! // MFA enrollment
//! const enrollment = try auth.mfa.enroll(allocator, "alice", .{});
//! defer enrollment.deinit(allocator);
//! ```
//!
//! ## License
//!
//! Apache-2.0

const std = @import("std");

/// Library version.
pub const version = "0.1.0";

/// HMAC-SHA256 record hashing, chain integrity, and HKDF key derivation.
pub const hmac = @import("hmac.zig");

/// API key creation, validation, revocation, and Bearer token parsing.
pub const api_keys = @import("api_keys.zig");

/// TOTP enrollment, code generation, and verification (RFC 6238).
pub const mfa = @import("mfa.zig");

// ============================================================================
// Unit Tests
// ============================================================================

test {
    // Ensure all submodule tests are run.
    std.testing.refAllDecls(@This());
}
