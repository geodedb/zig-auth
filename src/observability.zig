//! observability.zig — single-file otel seam for auth.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to the appropriate
//! `otel.api.trace` helper.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller — telemetry must never break authentication
//! or authorization decisions.
//!
//! SECURITY CRITICAL — credentials never enter this file:
//!   * `startAuthnSpan(method)` accepts only the auth METHOD label
//!     ("password", "token", "mfa", "api_key"), never the credential
//!     value.
//!   * `endAuthnSpan(span, ok, subject_id)` accepts the subject id ONLY
//!     on success. On failure the caller passes `null` so we cannot
//!     correlate failed attempts to a known subject through tracing
//!     alone.
//!   * `startAuthzSpan(action, resource)` accepts the action verb +
//!     resource identifier. The resource string is the policy name
//!     ("metrics", "admin/users") not the literal data being accessed.
//!   * raw tokens, password hashes, secret keys, and API key strings
//!     are NEVER attached as attributes. The redaction list in otel's
//!     pipeline (RECIPE.md: password, secret, token, api.key,
//!     authorization, credential) is a backstop — the seam's contract
//!     is to never pass them.
//!
//! NOTE: deviation from template — auth has no HTTP-shaped surface.
//! The `startClientSpan` / `startServerSpan` helpers are kept for
//! template symmetry but are not used at the auth hot path. The two
//! domain-specific helpers (`startAuthnSpan`, `startAuthzSpan`) are the
//! ones the consumer should reach for.

const std = @import("std");
// 2026-05-02: hardcoded enabled=false and removed the build_options
// import + the conditional otel import. The previous pattern surfaced
// a Zig 0.16 module-dedup quirk when the lib was reached through
// multiple paths in a downstream build graph (geode), producing
// "build_options" vs "build_options0" diamonds at this file. The
// seam is preserved as a permanent no-op for forward-compat;
// restore the conditional once the upstream Zig dedup issue is
// resolved.
// TRACKING: GAP-0020 (gitlab issue #66). While this constant is false,
// consumers get ZERO auth security events even with -Dwith_otel=true —
// add application-level logging around auth calls until the seam is
// restored. The -Dwith_otel build still type-checks the otel wiring.
pub const enabled: bool = false;

const otel = struct {};

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    /// No-op end — matches `otel.api.trace.Span.end(?u64) void` so callers compile unchanged.
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// Helper: reads either a `[]const u8` field OR a function-typed field
/// returning `[]const u8`, so the seam accepts both shapes — the closure
/// shape the recipe template ships AND the plain-string-field shape used
/// at hot-path call sites.
inline fn accessOr(req: anytype, comptime field: []const u8) []const u8 {
    const T = @TypeOf(@field(req, field));
    return switch (@typeInfo(T)) {
        .pointer => @field(req, field),
        .@"fn" => @field(req, field)(),
        else => @compileError("observability: unsupported field type for " ++ field),
    };
}

/// Start a span for a generic outbound operation. Kept for template
/// symmetry; auth hot paths use `startAuthnSpan` / `startAuthzSpan`
/// instead.
pub fn startClientSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startClientSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

/// Close an outbound HTTP span with the final HTTP status code.
pub fn endClientSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endClientSpan(span, .{ .status_code = status });
}

/// Start a span for a generic inbound operation. Kept for template
/// symmetry; auth has no HTTP-server entry point of its own.
pub fn startServerSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startServerSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .route = accessOr(req, "route"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

/// Close an inbound HTTP span with the final HTTP status code.
pub fn endServerSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endServerSpan(span, status);
}

// ============================================================================
// Domain-specific helpers — authn / authz
// ============================================================================

/// Start a span for an authentication attempt.
///
/// Span shape:
///   - name: `"auth.{method}"` (e.g. `"auth.password"`, `"auth.token"`,
///     `"auth.mfa"`, `"auth.api_key"`)
///   - kind: `.client` (the call site is consuming the auth check; the
///     span name carries the auth-specific semantic).
///   - attributes:
///       * `auth.method = method`
///   - subject id is NOT set here. It is attached at `endAuthnSpan` and
///     ONLY when the attempt succeeded — so failed attempts cannot be
///     correlated to a known subject through tracing alone.
///
/// SECURITY: `method` MUST be a fixed-vocabulary label, not the
/// credential value. Never pass the password, token, or API key string
/// here.
pub fn startAuthnSpan(method: []const u8) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    var name_buf: [64]u8 = undefined;
    const span_name = std.fmt.bufPrint(name_buf[0..], "auth.{s}", .{method}) catch "auth.authenticate";
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = .client }) catch return Span{};
    span.setStringAttribute("auth.method", method) catch {};
    return span;
}

/// Close an authentication span.
///
/// On `ok = true` the span is marked status `.ok` AND
/// `enduser.id = subject_id` is attached (subject_id may be null even on
/// success — e.g. anonymous-pass auth — in which case no attribute is
/// set). On `ok = false` the span is marked status `.error_` with no
/// subject id attached, so failed attempts are visible as security
/// events without leaking which (real) subject they targeted.
///
/// SECURITY: `subject_id` is the stable, public-facing user identifier
/// (numeric user id, opaque uuid). It is NOT the username, password,
/// token, or any other credential material.
pub fn endAuthnSpan(span: Span, ok: bool, subject_id: ?[]const u8) void {
    if (!enabled) return;
    if (ok) {
        if (subject_id) |sid| {
            span.setStringAttribute("enduser.id", sid) catch {};
        }
        span.setStatus(.ok, "");
    } else {
        // `StatusCode` uses `@"error"` (escaped keyword) for the
        // failure variant — see otel/src/api/trace.zig:35.
        span.setStatus(.@"error", "authn failed");
    }
    span.end(null);
}

/// Start a span for an authorization check.
///
/// Span shape:
///   - name: `"authz.{action}"` (e.g. `"authz.read"`, `"authz.write"`)
///   - kind: `.client`
///   - attributes:
///       * `auth.action = action`
///       * `auth.resource = resource`
///
/// SECURITY: both `action` and `resource` MUST be policy-vocabulary
/// labels (verbs and resource identifiers from the policy schema), not
/// the literal data being accessed.
pub fn startAuthzSpan(action: []const u8, resource: []const u8) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    var name_buf: [64]u8 = undefined;
    const span_name = std.fmt.bufPrint(name_buf[0..], "authz.{s}", .{action}) catch "authz.check";
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = .client }) catch return Span{};
    span.setStringAttribute("auth.action", action) catch {};
    span.setStringAttribute("auth.resource", resource) catch {};
    return span;
}

/// Close an authorization span.
///
/// `allowed = true` -> status `.ok`. `allowed = false` -> status
/// `.error_` with description `"authz denied"`. Denied checks ARE
/// recorded (with the action+resource that was denied) — operators
/// auditing forensics need both granted and denied decisions to
/// reconstruct an attack path.
pub fn endAuthzSpan(span: Span, allowed: bool) void {
    if (!enabled) return;
    if (allowed) {
        span.setStatus(.ok, "");
    } else {
        span.setStatus(.@"error", "authz denied");
    }
    span.end(null);
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer drops
/// the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};
