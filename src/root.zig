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

/// Library version — MUST match build.zig.zon .version (checked by pre-commit).
pub const version = "0.1.22";

/// HMAC-SHA256 record hashing, chain integrity, and HKDF key derivation.
pub const hmac = @import("hmac.zig");

/// API key creation, validation, revocation, and Bearer token parsing.
pub const api_keys = @import("api_keys.zig");

/// TOTP enrollment, code generation, and verification (RFC 6238).
pub const mfa = @import("mfa.zig");

/// FIPS-140-3 / PQC crypto seam. When `-Dfips=false` (default) every
/// security primitive routes through a std.crypto shim with zero
/// overhead; when `-Dfips=true` it routes through the linked OpenSSL
/// FIPS provider. Re-exported so downstream consumers can reach the
/// same backend (e.g. `auth.crypto_backend.assertActive()` at startup).
pub const crypto_backend = @import("crypto_backend");

/// otel instrumentation seam. When `-Dwith_otel=false` (the default) every
/// helper compiles to a comptime-known no-op; when `-Dwith_otel=true` calls
/// forward to the `otel` SDK. Domain-specific helpers
/// (`startAuthnSpan`, `endAuthnSpan`, `startAuthzSpan`, `endAuthzSpan`)
/// emit security-relevant events without ever passing credential material.
pub const observability = @import("observability");

/// otel bootstrap helper — only available when `-Dwith_otel=true`. Builds
/// TracerProvider/MeterProvider/LoggerProvider from `OTEL_*` env vars and
/// publishes globals. Gated at the importer site so the disabled build
/// never compiles otel-touching code.
pub const observability_init = if (observability.enabled) @import("observability_init") else struct {};

// ============================================================================
// Unit Tests
// ============================================================================

test {
    // Ensure all submodule tests are run.
    std.testing.refAllDecls(@This());
}
