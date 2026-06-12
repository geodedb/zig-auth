//! Verifies the no-op invariant when -Dwith_otel=false (the default).
//!
//! auth publishes its public surface as the "auth" module rooted at
//! src/root.zig. The seam is exposed as `auth.observability` so this test
//! can drive the disabled-mode invariants through the public root.
//!
//! SECURITY: this file MUST NOT pass any credential-shaped value (raw
//! tokens, password material, secret keys) into the seam helpers. The
//! authn/authz helpers take method names ("password", "token", "mfa"),
//! action verbs ("read", "write"), resource names, and the post-success
//! subject id only — never the secret itself.

const std = @import("std");
const auth = @import("auth");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled is hardcoded false (GAP-0020: seam inert until upstream Zig dedup fix)" {
    // 2026-05-02 workaround: observability.zig hardcodes enabled=false
    // regardless of -Dwith_otel. When the seam is restored to
    // `enabled = build_options.with_otel`, flip this assertion back to
    // expectEqual(build_options.with_otel, auth.observability.enabled).
    try std.testing.expectEqual(false, auth.observability.enabled);
}

test "client/server seams are no-ops when otel disabled" {
    if (auth.observability.enabled) return error.SkipZigTest;
    var span = auth.observability.startClientSpan(.{
        .method = "GET",
        .route = "/",
        .url = "https://example.test/",
    });
    auth.observability.endClientSpan(span, 200);
    // Belt-and-suspenders: the seam's `endClientSpan` already covers the
    // lifecycle; this line just verifies the no-op fallback's signature
    // matches the real API's `Span.end(?u64) void`.
    span.end(null);

    var sspan = auth.observability.startServerSpan(.{
        .method = "GET",
        .route = "/",
        .url = "/",
    });
    auth.observability.endServerSpan(sspan, 200);
    sspan.end(null);
}

test "authn span helper is a no-op when otel disabled" {
    if (auth.observability.enabled) return error.SkipZigTest;
    // NOTE: argument is the AUTH METHOD (e.g. "password", "token", "mfa"),
    // never the credential itself.
    var span = auth.observability.startAuthnSpan("password");
    // post-success subject id is the only attribute set; never a secret.
    auth.observability.endAuthnSpan(span, true, "user-123");
    span.end(null);

    var span2 = auth.observability.startAuthnSpan("token");
    auth.observability.endAuthnSpan(span2, false, null);
    span2.end(null);
}

test "authz span helper is a no-op when otel disabled" {
    if (auth.observability.enabled) return error.SkipZigTest;
    var span = auth.observability.startAuthzSpan("read", "metrics");
    auth.observability.endAuthzSpan(span, true);
    span.end(null);

    var span2 = auth.observability.startAuthzSpan("write", "admin");
    auth.observability.endAuthzSpan(span2, false);
    span2.end(null);
}
