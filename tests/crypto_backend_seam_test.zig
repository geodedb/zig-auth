// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros

//! Verifies the crypto_backend seam resolves and exposes the FIPS API
//! surface under both -Dfips values. Under -Dfips=false the std_shim is
//! selected and assertActive() is a no-op; under -Dfips=true the
//! OpenSSL FIPS backend is selected and assertActive() must not panic
//! (the provider was installed by `make deps`).
const std = @import("std");
const backend = @import("crypto_backend");
const build_options = @import("build_options");

test "seam fips_enabled tracks -Dfips" {
    try std.testing.expectEqual(build_options.fips, backend.fips_enabled);
}

test "seam exposes Hash/Mac/Kdf/Csprng and assertActive does not panic" {
    backend.assertActive();
    var dig: [32]u8 = undefined;
    const n = try backend.Hash.digest(.sha256, "abc", &dig);
    try std.testing.expectEqual(@as(usize, 32), n);
    // Known SHA2-256("abc") prefix byte — same in both backends.
    try std.testing.expectEqual(@as(u8, 0xba), dig[0]);

    var mac: [32]u8 = undefined;
    _ = try backend.Mac.hmac(.sha256, "key", "msg", &mac);

    var okm: [42]u8 = undefined;
    try backend.Kdf.hkdf(.sha256, "ikm0000000000000000000000", "salt", "info", &okm);

    var rnd: [16]u8 = undefined;
    try backend.Csprng.bytes(&rnd);
}
