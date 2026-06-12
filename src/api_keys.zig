// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! API Key authentication module.
//!
//! API Key Format: <prefix>.<token_id_b64url>.<secret_b64url>
//! - prefix: Configurable version prefix (default "ak1")
//! - token_id_b64url: 16-byte token ID, base64url encoded (no padding)
//! - secret_b64url: 32-byte secret, base64url encoded (no padding)

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
// otel seam — when `-Dwith_otel=false` (default) every helper below
// compiles to a comptime-known no-op. Credentials NEVER pass to the
// seam: only the auth-method label, the post-success user id (as the
// public-facing subject), and policy vocabulary (action, resource).
const observability = @import("observability");

/// Token ID size in bytes.
pub const TOKEN_ID_SIZE: usize = 16;

/// Secret size in bytes.
pub const SECRET_SIZE: usize = 32;

/// Configuration for the API key system.
pub const Config = struct {
    /// Version prefix for formatted key strings (e.g. "ak1", "myapp1").
    /// Must not contain '.'.
    key_prefix: []const u8 = "ak1",
};

/// API Key structure (stored server-side; never contains the raw secret).
pub const ApiKey = struct {
    id: [TOKEN_ID_SIZE]u8,
    secret_hash: [32]u8,
    user_id: u64,
    name: []const u8,
    created_at: i64,
    expires_at: ?i64,
    last_used_at: ?i64,
    scopes: []const []const u8,
    is_active: bool,
};

/// Parsed API key from string format.
pub const ParsedApiKey = struct {
    prefix: []const u8,
    id: [TOKEN_ID_SIZE]u8,
    secret: [SECRET_SIZE]u8,
};

/// API Key Manager.
pub const ApiKeyManager = struct {
    const Self = @This();

    allocator: Allocator,
    config: Config,
    keys: std.AutoHashMap([TOKEN_ID_SIZE]u8, ApiKey),
    mutex: std.Io.Mutex,

    pub fn init(allocator: Allocator, config: Config) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .keys = std.AutoHashMap([TOKEN_ID_SIZE]u8, ApiKey).init(allocator),
            .mutex = std.Io.Mutex.init,
        };
    }

    pub fn deinit(self: *Self) void {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        var it = self.keys.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.name);
            for (entry.value_ptr.scopes) |scope| {
                self.allocator.free(scope);
            }
            self.allocator.free(entry.value_ptr.scopes);
        }
        self.keys.deinit();
    }

    /// Create a new API key for a user.
    /// Returns the full key string (only time secret is available).
    ///
    /// Telemetry: emits one `auth.api_key.issue` span. Subject id is
    /// the issuing `user_id` (always known on this call site). The raw
    /// key string and secret NEVER appear as span attributes.
    pub fn createKey(
        self: *Self,
        user_id: u64,
        name: []const u8,
        scopes: []const []const u8,
        expires_in_seconds: ?i64,
    ) ![]u8 {
        const span = observability.startAuthnSpan("api_key.issue");
        var ok: bool = false;
        var subject_buf: [32]u8 = undefined;
        const subject_id: []const u8 = std.fmt.bufPrint(&subject_buf, "{d}", .{user_id}) catch "";
        defer observability.endAuthnSpan(span, ok, if (ok) subject_id else null);

        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        // Generate cryptographically random token ID and secret.
        var id: [TOKEN_ID_SIZE]u8 = undefined;
        var secret: [SECRET_SIZE]u8 = undefined;
        // Fail closed: no silent low-entropy fallback on a credential path.
        try std.Io.Threaded.global_single_threaded.io().randomSecure(&id);
        try std.Io.Threaded.global_single_threaded.io().randomSecure(&secret);

        // Hash the secret for storage (never store raw secret).
        var secret_hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&secret, &secret_hash, .{});
        defer crypto.secureZero(u8, &secret);

        const now = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real).toSeconds();
        const expires_at: ?i64 = if (expires_in_seconds) |exp| now + exp else null;

        // Format key string BEFORE inserting into map.
        // This ensures that if formatting fails (OOM), we haven't stored
        // dangling references into the map that errdefers would free.
        const key_string = try formatApiKey(self.allocator, self.config.key_prefix, &id, &secret);
        errdefer self.allocator.free(key_string);

        // Duplicate name and scopes.
        const name_dup = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_dup);

        const scopes_dup = try dupeScopes(self.allocator, scopes);
        errdefer freeScopes(self.allocator, scopes_dup);

        const key = ApiKey{
            .id = id,
            .secret_hash = secret_hash,
            .user_id = user_id,
            .name = name_dup,
            .created_at = now,
            .expires_at = expires_at,
            .last_used_at = null,
            .scopes = scopes_dup,
            .is_active = true,
        };

        try self.keys.put(id, key);

        ok = true;
        return key_string;
    }

    /// Validate an API key and return a copy of the associated key info.
    /// Returns `null` if the key is invalid, expired, revoked, or has wrong prefix.
    ///
    /// Telemetry: emits one `auth.api_key` span per call. The span is
    /// closed `.ok` with `enduser.id = <user_id>` when validation
    /// succeeds and `.error_` (no subject id) on every failure path —
    /// failed attempts are visible as security events without leaking
    /// which subject they targeted. The raw key string and parsed
    /// secret NEVER leave the function as span attributes.
    pub fn validateKey(self: *Self, key_string: []const u8) !?ApiKey {
        const span = observability.startAuthnSpan("api_key");
        // Default-fail unless the success path explicitly flips `ok`.
        // `defer endAuthnSpan` runs once on every exit (including error
        // returns from `parseApiKey`) so the span is always closed.
        var ok: bool = false;
        var subject_buf: [32]u8 = undefined;
        var subject_id: ?[]const u8 = null;
        defer observability.endAuthnSpan(span, ok, subject_id);

        var parsed = try parseApiKey(key_string);
        defer crypto.secureZero(u8, &parsed.secret);

        // Check prefix matches this manager's configured prefix.
        if (!std.mem.eql(u8, parsed.prefix, self.config.key_prefix)) return null;

        // Hash the provided secret BEFORE acquiring the lock to reduce
        // mutex hold time under concurrent validation.
        var provided_hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&parsed.secret, &provided_hash, .{});
        defer crypto.secureZero(u8, &provided_hash);

        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        const key = self.keys.getPtr(parsed.id) orelse return null;

        if (!key.is_active) return null;

        if (key.expires_at) |exp| {
            if (std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real).toSeconds() >= exp) {
                key.is_active = false;
                return null;
            }
        }

        if (!std.crypto.timing_safe.eql([32]u8, provided_hash, key.secret_hash)) {
            return null;
        }

        key.last_used_at = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real).toSeconds();

        // Success: stringify the user_id for the span attribute. Render
        // into the local stack buffer so the slice the seam captures
        // outlives only the span's `setStringAttribute` call (which
        // dupes into the span's arena under enabled mode, and is a
        // comptime no-op under disabled mode).
        const sid = std.fmt.bufPrint(&subject_buf, "{d}", .{key.user_id}) catch null;
        if (sid) |s| subject_id = s;
        ok = true;
        return key.*;
    }

    /// Check if a key has a specific scope.
    ///
    /// Telemetry: emits one `authz.{scope}` span per call. Recorded
    /// regardless of result so denied checks are visible to forensics
    /// auditors. Resource attribute is the literal string `"api_key"`
    /// (the policy-vocabulary identifier for "this key's scope set"),
    /// never the secret_hash or any field of the ApiKey beyond the
    /// scope string itself.
    pub fn hasScope(key: *const ApiKey, scope: []const u8) bool {
        const span = observability.startAuthzSpan(scope, "api_key");
        var allowed: bool = false;
        defer observability.endAuthzSpan(span, allowed);

        for (key.scopes) |s| {
            if (std.mem.eql(u8, s, scope) or std.mem.eql(u8, s, "*")) {
                allowed = true;
                return true;
            }
        }
        return false;
    }

    /// Revoke an API key by ID.
    ///
    /// Telemetry: emits one `auth.api_key.revoke` span. Subject id is
    /// the revoked key's user_id when the key was found; otherwise
    /// null (revoke-of-unknown is treated as a failed revoke, surfaced
    /// as `.error_` so operators can spot probing attempts).
    pub fn revokeKey(self: *Self, id: [TOKEN_ID_SIZE]u8) bool {
        const span = observability.startAuthnSpan("api_key.revoke");
        var ok: bool = false;
        var subject_buf: [32]u8 = undefined;
        var subject_id: ?[]const u8 = null;
        defer observability.endAuthnSpan(span, ok, subject_id);

        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        if (self.keys.getPtr(id)) |key| {
            key.is_active = false;
            const sid = std.fmt.bufPrint(&subject_buf, "{d}", .{key.user_id}) catch null;
            if (sid) |s| subject_id = s;
            ok = true;
            return true;
        }
        return false;
    }

    /// Revoke all keys for a user.
    ///
    /// Telemetry: emits one `auth.api_key.revoke_all` span. Subject id
    /// is the targeted user_id (always known on this call site). Span
    /// is `.ok` even when zero keys were affected — the operator
    /// performed an authorized bulk-revoke; the count of affected keys
    /// is a side-effect, not a failure mode.
    pub fn revokeUserKeys(self: *Self, user_id: u64) usize {
        const span = observability.startAuthnSpan("api_key.revoke_all");
        var ok: bool = false;
        var subject_buf: [32]u8 = undefined;
        const subject_id: []const u8 = std.fmt.bufPrint(&subject_buf, "{d}", .{user_id}) catch "";
        defer observability.endAuthnSpan(span, ok, if (ok) subject_id else null);

        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        var count: usize = 0;
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.user_id == user_id and entry.value_ptr.is_active) {
                entry.value_ptr.is_active = false;
                count += 1;
            }
        }
        ok = true;
        return count;
    }

    /// List all keys for a user. Returns owned copies; caller must
    /// call `freeKeyList` to release the returned slice.
    pub fn listUserKeys(self: *Self, allocator: Allocator, user_id: u64) ![]ApiKey {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        var list: std.ArrayListUnmanaged(ApiKey) = .empty;
        var cloned_count: usize = 0;
        errdefer {
            for (list.items[0..cloned_count]) |*item| {
                allocator.free(item.name);
                freeScopes(allocator, item.scopes);
            }
            list.deinit(allocator);
        }

        var it = self.keys.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.user_id == user_id) {
                var copy = entry.value_ptr.*;
                copy.name = try allocator.dupe(u8, entry.value_ptr.name);
                errdefer allocator.free(copy.name);
                copy.scopes = try dupeScopes(allocator, entry.value_ptr.scopes);
                try list.append(allocator, copy);
                cloned_count += 1;
            }
        }
        return list.toOwnedSlice(allocator);
    }

    /// Free a key list returned by `listUserKeys`.
    pub fn freeKeyList(allocator: Allocator, keys: []ApiKey) void {
        for (keys) |*k| {
            allocator.free(k.name);
            freeScopes(allocator, k.scopes);
        }
        allocator.free(keys);
    }

    /// Delete expired keys (cleanup). Returns the number of keys removed.
    pub fn cleanupExpired(self: *Self) !usize {
        self.mutex.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
        defer self.mutex.unlock(std.Io.Threaded.global_single_threaded.io());

        var to_remove: std.ArrayListUnmanaged([TOKEN_ID_SIZE]u8) = .empty;
        defer to_remove.deinit(self.allocator);

        const now = std.Io.Timestamp.now(std.Io.Threaded.global_single_threaded.io(), .real).toSeconds();
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at) |exp| {
                if (now >= exp) {
                    try to_remove.append(self.allocator, entry.key_ptr.*);
                }
            }
        }

        for (to_remove.items) |id| {
            if (self.keys.fetchRemove(id)) |kv| {
                self.allocator.free(kv.value.name);
                freeScopes(self.allocator, kv.value.scopes);
            }
        }

        return to_remove.items.len;
    }
};

/// Duplicate a slice of scopes with proper cleanup on partial failure.
fn dupeScopes(allocator: Allocator, scopes: []const []const u8) ![]const []const u8 {
    const duped = try allocator.alloc([]const u8, scopes.len);
    var i: usize = 0;
    errdefer {
        for (duped[0..i]) |s| allocator.free(s);
        allocator.free(duped);
    }
    while (i < scopes.len) : (i += 1) {
        duped[i] = try allocator.dupe(u8, scopes[i]);
    }
    return duped;
}

/// Free a duplicated scopes slice.
fn freeScopes(allocator: Allocator, scopes: []const []const u8) void {
    for (scopes) |s| allocator.free(s);
    allocator.free(scopes);
}

/// Format an API key to string: <prefix>.<id_b64url>.<secret_b64url>
pub fn formatApiKey(allocator: Allocator, prefix: []const u8, id: *const [TOKEN_ID_SIZE]u8, secret: *const [SECRET_SIZE]u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;

    const id_encoded_len = encoder.calcSize(TOKEN_ID_SIZE);
    const secret_encoded_len = encoder.calcSize(SECRET_SIZE);

    const total_len = prefix.len + 1 + id_encoded_len + 1 + secret_encoded_len;
    const result = try allocator.alloc(u8, total_len);
    errdefer allocator.free(result);

    @memcpy(result[0..prefix.len], prefix);
    result[prefix.len] = '.';

    _ = encoder.encode(result[prefix.len + 1 ..][0..id_encoded_len], id);
    result[prefix.len + 1 + id_encoded_len] = '.';

    _ = encoder.encode(result[prefix.len + 1 + id_encoded_len + 1 ..], secret);

    return result;
}

/// Parse an API key string to components.
/// Accepts any version prefix (caller validates if needed).
pub fn parseApiKey(key_string: []const u8) !ParsedApiKey {
    var parts = std.mem.splitScalar(u8, key_string, '.');

    const prefix = parts.next() orelse return error.InvalidApiKeyFormat;
    if (prefix.len == 0) return error.InvalidApiKeyFormat;

    const id_encoded = parts.next() orelse return error.InvalidApiKeyFormat;
    const decoder = std.base64.url_safe_no_pad.Decoder;

    const id_size = decoder.calcSizeForSlice(id_encoded) catch return error.InvalidApiKeyFormat;
    if (id_size != TOKEN_ID_SIZE) return error.InvalidApiKeyFormat;

    var id: [TOKEN_ID_SIZE]u8 = undefined;
    decoder.decode(&id, id_encoded) catch return error.InvalidApiKeyFormat;

    const secret_encoded = parts.next() orelse return error.InvalidApiKeyFormat;
    const secret_size = decoder.calcSizeForSlice(secret_encoded) catch return error.InvalidApiKeyFormat;
    if (secret_size != SECRET_SIZE) return error.InvalidApiKeyFormat;

    var secret: [SECRET_SIZE]u8 = undefined;
    decoder.decode(&secret, secret_encoded) catch return error.InvalidApiKeyFormat;

    if (parts.next() != null) return error.InvalidApiKeyFormat;

    return ParsedApiKey{
        .prefix = prefix,
        .id = id,
        .secret = secret,
    };
}

/// Parse Bearer token from HTTP Authorization header.
pub fn parseBearerToken(auth_header: []const u8) ?[]const u8 {
    const prefix = "Bearer ";
    if (std.mem.startsWith(u8, auth_header, prefix)) {
        const token = std.mem.trim(u8, auth_header[prefix.len..], " \t\r\n");
        if (token.len > 0) return token;
    }
    return null;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "ApiKeyManager: create and validate key" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const key_string = try manager.createKey(
        1,
        "test-key",
        &[_][]const u8{ "metrics:read", "health:read" },
        null,
    );
    defer allocator.free(key_string);

    // Verify prefix
    try std.testing.expect(std.mem.startsWith(u8, key_string, "ak1."));

    const key = try manager.validateKey(key_string);
    try std.testing.expect(key != null);

    if (key) |k| {
        try std.testing.expectEqual(@as(u64, 1), k.user_id);
        try std.testing.expectEqualStrings("test-key", k.name);
        try std.testing.expect(k.is_active);
        try std.testing.expectEqual(@as(usize, 2), k.scopes.len);
    }
}

test "ApiKeyManager: custom prefix" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{ .key_prefix = "myapp1" });
    defer manager.deinit();

    const key_string = try manager.createKey(1, "test-key", &[_][]const u8{"read"}, null);
    defer allocator.free(key_string);

    try std.testing.expect(std.mem.startsWith(u8, key_string, "myapp1."));

    const key = try manager.validateKey(key_string);
    try std.testing.expect(key != null);
}

test "ApiKeyManager: validate key with wrong secret fails" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const created = try manager.createKey(1, "test-key", &[_][]const u8{"metrics:read"}, null);
    allocator.free(created);

    const fake_key = "ak1.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const result = try manager.validateKey(fake_key);
    try std.testing.expect(result == null);
}

test "ApiKeyManager: revoke key" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const key_string = try manager.createKey(1, "test-key", &[_][]const u8{"metrics:read"}, null);
    defer allocator.free(key_string);

    var key = try manager.validateKey(key_string);
    try std.testing.expect(key != null);

    const parsed = try parseApiKey(key_string);
    try std.testing.expect(manager.revokeKey(parsed.id));

    key = try manager.validateKey(key_string);
    try std.testing.expect(key == null);
}

test "ApiKeyManager: expired key fails validation" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const key_string = try manager.createKey(1, "test-key", &[_][]const u8{"metrics:read"}, -1);
    defer allocator.free(key_string);

    const key = try manager.validateKey(key_string);
    try std.testing.expect(key == null);
}

test "ApiKeyManager: hasScope checks correctly" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const key_string = try manager.createKey(
        1,
        "test-key",
        &[_][]const u8{ "metrics:read", "health:read" },
        null,
    );
    defer allocator.free(key_string);

    const key = (try manager.validateKey(key_string)).?;

    try std.testing.expect(ApiKeyManager.hasScope(&key, "metrics:read"));
    try std.testing.expect(ApiKeyManager.hasScope(&key, "health:read"));
    try std.testing.expect(!ApiKeyManager.hasScope(&key, "admin:write"));
}

test "ApiKeyManager: wildcard scope grants all" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const key_string = try manager.createKey(1, "admin-key", &[_][]const u8{"*"}, null);
    defer allocator.free(key_string);

    const key = (try manager.validateKey(key_string)).?;

    try std.testing.expect(ApiKeyManager.hasScope(&key, "metrics:read"));
    try std.testing.expect(ApiKeyManager.hasScope(&key, "admin:write"));
    try std.testing.expect(ApiKeyManager.hasScope(&key, "anything"));
}

test "ApiKeyManager: wrong prefix rejected" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{ .key_prefix = "v2" });
    defer manager.deinit();

    const key_string = try manager.createKey(1, "test", &[_][]const u8{"read"}, null);
    defer allocator.free(key_string);

    // Key was created with prefix "v2", validate with a manager using different prefix
    var other_manager = ApiKeyManager.init(allocator, .{ .key_prefix = "v3" });
    defer other_manager.deinit();

    // Parse should succeed but validation returns null due to prefix mismatch
    const result = try other_manager.validateKey(key_string);
    try std.testing.expect(result == null);
}

test "parseApiKey: valid key format" {
    const allocator = std.testing.allocator;

    var id: [TOKEN_ID_SIZE]u8 = undefined;
    var secret: [SECRET_SIZE]u8 = undefined;
    @memset(&id, 0xAB);
    @memset(&secret, 0xCD);

    const key_string = try formatApiKey(allocator, "ak1", &id, &secret);
    defer allocator.free(key_string);

    const parsed = try parseApiKey(key_string);
    try std.testing.expectEqualSlices(u8, &id, &parsed.id);
    try std.testing.expectEqualSlices(u8, &secret, &parsed.secret);
    try std.testing.expectEqualStrings("ak1", parsed.prefix);
}

test "parseApiKey: accepts any prefix" {
    const allocator = std.testing.allocator;

    var id: [TOKEN_ID_SIZE]u8 = undefined;
    var secret: [SECRET_SIZE]u8 = undefined;
    @memset(&id, 0xAB);
    @memset(&secret, 0xCD);

    const key_string = try formatApiKey(allocator, "custom99", &id, &secret);
    defer allocator.free(key_string);

    const parsed = try parseApiKey(key_string);
    try std.testing.expectEqualStrings("custom99", parsed.prefix);
}

test "parseApiKey: invalid format fails" {
    try std.testing.expectError(error.InvalidApiKeyFormat, parseApiKey("ak1.abc"));
    try std.testing.expectError(error.InvalidApiKeyFormat, parseApiKey("ak1"));
    try std.testing.expectError(error.InvalidApiKeyFormat, parseApiKey("ak1.a.b.c"));
}

test "parseBearerToken: valid Bearer token" {
    const token = parseBearerToken("Bearer ak1.abc.def");
    try std.testing.expect(token != null);
    try std.testing.expectEqualStrings("ak1.abc.def", token.?);
}

test "parseBearerToken: Bearer with whitespace" {
    const token = parseBearerToken("Bearer   ak1.abc.def  ");
    try std.testing.expect(token != null);
    try std.testing.expectEqualStrings("ak1.abc.def", token.?);
}

test "parseBearerToken: invalid prefix returns null" {
    try std.testing.expect(parseBearerToken("Basic abc123") == null);
    try std.testing.expect(parseBearerToken("bearer ak1.abc.def") == null);
    try std.testing.expect(parseBearerToken("") == null);
}

// GAP-0005: Dedicated tests for revokeUserKeys, listUserKeys, cleanupExpired.

test "ApiKeyManager: revokeUserKeys revokes all keys for a user" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const k1 = try manager.createKey(1, "key-a", &[_][]const u8{"read"}, null);
    defer allocator.free(k1);
    const k2 = try manager.createKey(1, "key-b", &[_][]const u8{"write"}, null);
    defer allocator.free(k2);
    const k3 = try manager.createKey(2, "other-user", &[_][]const u8{"read"}, null);
    defer allocator.free(k3);

    const revoked = manager.revokeUserKeys(1);
    try std.testing.expectEqual(@as(usize, 2), revoked);

    // User 1 keys should be invalid.
    try std.testing.expect((try manager.validateKey(k1)) == null);
    try std.testing.expect((try manager.validateKey(k2)) == null);

    // User 2 key should still work.
    try std.testing.expect((try manager.validateKey(k3)) != null);
}

test "ApiKeyManager: revokeUserKeys returns 0 for unknown user" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    try std.testing.expectEqual(@as(usize, 0), manager.revokeUserKeys(999));
}

test "ApiKeyManager: listUserKeys returns owned deep copies" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const k1 = try manager.createKey(1, "key-a", &[_][]const u8{ "read", "write" }, null);
    defer allocator.free(k1);
    const k2 = try manager.createKey(1, "key-b", &[_][]const u8{"admin"}, null);
    defer allocator.free(k2);
    const k3 = try manager.createKey(2, "other", &[_][]const u8{"read"}, null);
    defer allocator.free(k3);

    const keys = try manager.listUserKeys(allocator, 1);
    defer ApiKeyManager.freeKeyList(allocator, keys);

    try std.testing.expectEqual(@as(usize, 2), keys.len);
    for (keys) |k| {
        try std.testing.expectEqual(@as(u64, 1), k.user_id);
    }
}

test "ApiKeyManager: listUserKeys returns empty for unknown user" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const keys = try manager.listUserKeys(allocator, 999);
    defer ApiKeyManager.freeKeyList(allocator, keys);

    try std.testing.expectEqual(@as(usize, 0), keys.len);
}

test "ApiKeyManager: cleanupExpired removes expired keys" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    // Create a key that expires immediately.
    const k1 = try manager.createKey(1, "expired", &[_][]const u8{"read"}, -1);
    defer allocator.free(k1);
    // Create a key that doesn't expire.
    const k2 = try manager.createKey(1, "permanent", &[_][]const u8{"read"}, null);
    defer allocator.free(k2);

    const removed = try manager.cleanupExpired();
    try std.testing.expectEqual(@as(usize, 1), removed);

    // Expired key should be gone (not just inactive — fully removed).
    try std.testing.expect((try manager.validateKey(k1)) == null);
    // Permanent key still works.
    try std.testing.expect((try manager.validateKey(k2)) != null);
}

test "ApiKeyManager: cleanupExpired with no expired keys" {
    const allocator = std.testing.allocator;

    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const k1 = try manager.createKey(1, "permanent", &[_][]const u8{"read"}, null);
    defer allocator.free(k1);

    const removed = try manager.cleanupExpired();
    try std.testing.expectEqual(@as(usize, 0), removed);
}
