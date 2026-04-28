//! Verifies one authn span lands in an in-memory recorder when
//! `-Dwith_otel=true`. Skips under the disabled build.
//!
//! NOTE: deviation from template — we exercise the seam directly via
//! the in-memory recorder rather than driving a real authentication
//! flow. Auth's hot path (`api_keys.ApiKeyManager.validateKey`,
//! `mfa.verifyCode`) requires inputs we shouldn't synthesise in a
//! tracing smoke test (raw secrets, hashed credentials), so we exercise
//! `startAuthnSpan` + `endAuthnSpan` directly. The seam's behaviour is
//! identical: enter the span, set attributes, end with status — exactly
//! what a real auth call site does.
//!
//! SECURITY: this test exercises ONLY the labels and subject id that
//! the seam would see in production. No raw passwords, tokens, hashes,
//! or secret keys appear in test inputs or assertions.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (enabled)`
//! and stub the alias to an empty struct when the flag is off — that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const auth = @import("auth");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one authn span recorded when otel enabled" {
    if (!auth.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "auth-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "auth-test" });
    auth.observability.global.tracer = &tracer;
    defer auth.observability.global.tracer = null;

    // Drive an authentication-flow span shape end-to-end.
    const span = auth.observability.startAuthnSpan("password");
    auth.observability.endAuthnSpan(span, true, "user-123");

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    // Verify span name shape: `"auth.{method}"`.
    const recorded = recorder.spans.items[0];
    try std.testing.expectEqualStrings("auth.password", recorded.name);

    // Verify the `enduser.id` attribute landed on the span (set on
    // success only). The in-memory recorder stores attributes as
    // `[]KV` (string-stringified key/value pairs) — see
    // otel/src/exporters/in_memory.zig:30.
    var found_subject: ?[]const u8 = null;
    var found_method: ?[]const u8 = null;
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "enduser.id")) found_subject = kv.value;
        if (std.mem.eql(u8, kv.key, "auth.method")) found_method = kv.value;
    }
    const subject_value = found_subject orelse return error.MissingEnduserIdAttribute;
    try std.testing.expectEqualStrings("user-123", subject_value);
    const method_value = found_method orelse return error.MissingAuthMethodAttribute;
    try std.testing.expectEqualStrings("password", method_value);
}

test "failed authn does not attach subject id" {
    if (!auth.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "auth-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "auth-test" });
    auth.observability.global.tracer = &tracer;
    defer auth.observability.global.tracer = null;

    const span = auth.observability.startAuthnSpan("token");
    // Failure path: caller passes null subject_id so failed attempts
    // cannot be correlated to a known subject through tracing alone.
    auth.observability.endAuthnSpan(span, false, null);

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    const recorded = recorder.spans.items[0];
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "enduser.id")) {
            return error.UnexpectedEnduserIdOnFailure;
        }
    }
}
