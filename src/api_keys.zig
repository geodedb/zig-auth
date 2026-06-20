// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! API Key authentication module.
//!
//! API Key Format: <prefix>.<token_id_b64url>.<secret_b64url>
//! - prefix: Configurable version prefix (default "ak1")
//! - token_id_b64url: 16-byte token ID, base64url encoded (no padding)
//! - secret_b64url: 32-byte secret, base64url encoded (no padding)

const std = @import("std");
const crypto = std.crypto; // secureZero + timing_safe only (constant-time utils, not algorithms).
const backend = @import("crypto_backend");
const Allocator = std.mem.Allocator;
// otel seam — when `-Dwith_otel=false` (default) every helper below
// compiles to a comptime-known no-op. Credentials NEVER pass to the
// seam: only the auth-method label, the post-success user id (as the
// public-facing subject), and policy vocabulary (action, resource).
const observability = @import("observability");

/// Single accessor for the process-global IO used for timestamps and
/// CSPRNG. Centralized so a future injectable-clock refactor touches
/// one site.
/// NOTE: despite the instance name, the mutex/futex path delegates to real OS futexes in non-single-threaded builds (verified against std/Io/Threaded.zig futexWaitUncancelable) — see the ApiKeyManager threading doc.
inline fn ioh() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Wall-clock seconds (UTC).
fn nowSeconds() i64 {
    return std.Io.Timestamp.now(ioh(), .real).toSeconds();
}

/// Hash a raw secret for at-rest storage, peppered when configured.
/// Peppered: HMAC-SHA256(pepper, secret). Unpeppered: SHA-256(secret).
/// Both via the FIPS seam; a backend failure on these fixed-size
/// 32-byte digests is unrecoverable corruption — panic.
fn hashSecret(config: Config, secret: *const [SECRET_SIZE]u8, out: *[32]u8) void {
    if (config.pepper) |p| {
        _ = backend.Mac.hmac(.sha256, p, secret, out) catch
            @panic("HMAC-SHA256 backend failure in hashSecret");
    } else {
        _ = backend.Hash.digest(.sha256, secret, out) catch
            @panic("SHA-256 backend failure in hashSecret");
    }
}

/// Token ID size in bytes.
pub const TOKEN_ID_SIZE: usize = 16;

/// Secret size in bytes.
pub const SECRET_SIZE: usize = 32;

/// Configuration for the API key system.
pub const Config = struct {
    /// Version prefix for formatted key strings (e.g. "ak1", "myapp1").
    /// Must not contain '.' — enforced by `createKey`
    /// (`error.InvalidKeyPrefix`).
    key_prefix: []const u8 = "ak1",
    /// Optional server-side pepper. When set, stored secret hashes are
    /// `HMAC-SHA256(pepper, secret)` instead of bare SHA-256, so a
    /// key-store disclosure alone is not matchable against captured
    /// key strings. The pepper must live outside the key store and
    /// outlive the manager. Changing it invalidates all stored keys.
    pepper: ?*const [32]u8 = null,
    /// Optional hard cap on stored keys. `createKey` returns
    /// `error.KeyLimitReached` at the cap (DoS guard for unbounded
    /// key-map growth).
    max_keys: ?usize = null,
};

/// Errors from `parseApiKey`.
pub const ParseError = error{InvalidApiKeyFormat};

/// Errors from `ApiKeyManager.createKey`.
pub const CreateKeyError = Allocator.Error || error{
    InvalidKeyPrefix,
    KeyLimitReached,
    TokenIdCollision,
    CsprngFailure,
};

/// Errors from `ApiKeyManager.validateKey`.
pub const ValidateKeyError = Allocator.Error || ParseError;

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
///
/// ## Threading
/// All public methods are safe to call from multiple OS threads: a
/// blocking `std.Io.Mutex` serializes every access to the key map.
/// (Zig 0.16 moved the blocking mutex from `std.Thread.Mutex` to
/// `std.Io.Mutex`; in normal multi-threaded builds its waits are real
/// OS futex waits, so cross-thread contention blocks correctly.)
///
/// ## Ownership
/// - The manager owns all stored key data (`name`/`scopes`), freed by
///   `deinit`/`cleanupExpired`/`revoke*`.
/// - `validateKey` returns an OWNED deep copy — release with
///   `freeValidatedKey`.
/// - `listUserKeys` returns owned deep copies allocated from the
///   allocator argument — release with `freeKeyList`, passing the SAME
///   allocator.
/// - `createKey` returns an owned key string allocated from the
///   manager's allocator — caller frees it.
pub const ApiKeyManager = struct {
    const Self = @This();

    allocator: Allocator,
    config: Config,
    keys: std.AutoHashMap([TOKEN_ID_SIZE]u8, ApiKey),
    mutex: std.Io.Mutex,

    /// Create a manager that allocates from `allocator`. Free with `deinit`.
    pub fn init(allocator: Allocator, config: Config) Self {
        return .{
            .allocator = allocator,
            .config = config,
            .keys = std.AutoHashMap([TOKEN_ID_SIZE]u8, ApiKey).init(allocator),
            .mutex = std.Io.Mutex.init,
        };
    }

    /// Free all stored keys and the map. The manager is unusable afterwards.
    pub fn deinit(self: *Self) void {
        self.mutex.lockUncancelable(ioh());
        defer self.mutex.unlock(ioh());

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
    ) CreateKeyError![]u8 {
        const span = observability.startAuthnSpan("api_key.issue");
        var ok: bool = false;
        var subject_buf: [32]u8 = undefined;
        const subject_id: []const u8 = if (comptime observability.enabled)
            std.fmt.bufPrint(&subject_buf, "{d}", .{user_id}) catch ""
        else
            "";
        defer observability.endAuthnSpan(span, ok, if (ok) subject_id else null);

        // Reject prefixes that would corrupt the '.'-delimited format.
        if (std.mem.indexOfScalar(u8, self.config.key_prefix, '.') != null)
            return error.InvalidKeyPrefix;

        // Everything below until the lock is pure local work — RNG,
        // hashing, formatting, and duplication happen OUTSIDE the
        // critical section so concurrent validates are not stalled.
        var id: [TOKEN_ID_SIZE]u8 = undefined;
        var secret: [SECRET_SIZE]u8 = undefined;
        // Fail closed: no silent low-entropy fallback on a credential path.
        // CSPRNG via the FIPS seam (SP 800-90A DRBG under fips; std.crypto
        // under the shim). A backend RNG failure aborts key creation.
        backend.Csprng.bytes(&id) catch return error.CsprngFailure;
        backend.Csprng.bytes(&secret) catch return error.CsprngFailure;
        defer crypto.secureZero(u8, &secret);

        var secret_hash: [32]u8 = undefined;
        hashSecret(self.config, &secret, &secret_hash);

        const now = nowSeconds();
        const expires_at: ?i64 = if (expires_in_seconds) |exp| now + exp else null;

        // Format key string BEFORE inserting into map.
        // This ensures that if formatting fails (OOM), we haven't stored
        // dangling references into the map that errdefers would free.
        const key_string = try formatApiKey(self.allocator, self.config.key_prefix, &id, &secret);
        errdefer self.allocator.free(key_string);

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

        self.mutex.lockUncancelable(ioh());
        defer self.mutex.unlock(ioh());

        if (self.config.max_keys) |limit| {
            if (self.keys.count() >= limit) return error.KeyLimitReached;
        }

        // Collision-safe insert: a duplicate random ID must never
        // silently overwrite (and leak) another user's key.
        const gop = try self.keys.getOrPut(id);
        if (gop.found_existing) return error.TokenIdCollision;
        gop.value_ptr.* = key;

        ok = true;
        return key_string;
    }

    /// Validate an API key and return an OWNED deep copy of the
    /// associated key info — `name` and `scopes` are duplicated with
    /// the manager's allocator and remain valid after concurrent
    /// revoke/cleanup. Release with `freeValidatedKey`.
    /// Returns `null` if the key is invalid, expired, revoked, or has
    /// the wrong prefix.
    ///
    /// Telemetry: emits one `auth.api_key` span per call. The span is
    /// closed `.ok` with `enduser.id = <user_id>` when validation
    /// succeeds and `.error_` (no subject id) on every failure path —
    /// failed attempts are visible as security events without leaking
    /// which subject they targeted. The raw key string and parsed
    /// secret NEVER leave the function as span attributes.
    pub fn validateKey(self: *Self, key_string: []const u8) ValidateKeyError!?ApiKey {
        const span = observability.startAuthnSpan("api_key");
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
        hashSecret(self.config, &parsed.secret, &provided_hash);
        defer crypto.secureZero(u8, &provided_hash);

        // One wall-clock read serves both the expiry check and the
        // last_used_at update.
        const now = nowSeconds();

        self.mutex.lockUncancelable(ioh());
        defer self.mutex.unlock(ioh());

        const key = self.keys.getPtr(parsed.id) orelse return null;

        if (!key.is_active) return null;

        if (key.expires_at) |exp| {
            if (now >= exp) {
                key.is_active = false;
                return null;
            }
        }

        if (!std.crypto.timing_safe.eql([32]u8, provided_hash, key.secret_hash)) {
            return null;
        }

        var copy = key.*;
        copy.name = try self.allocator.dupe(u8, key.name);
        errdefer self.allocator.free(copy.name);
        copy.scopes = try dupeScopes(self.allocator, key.scopes);

        key.last_used_at = now;
        copy.last_used_at = now;

        if (comptime observability.enabled) {
            const sid = std.fmt.bufPrint(&subject_buf, "{d}", .{key.user_id}) catch null;
            if (sid) |s| subject_id = s;
        }
        ok = true;
        return copy;
    }

    /// Free a key returned by `validateKey`.
    pub fn freeValidatedKey(self: *Self, key: ApiKey) void {
        self.allocator.free(key.name);
        freeScopes(self.allocator, key.scopes);
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

        self.mutex.lockUncancelable(ioh());
        defer self.mutex.unlock(ioh());

        if (self.keys.getPtr(id)) |key| {
            key.is_active = false;
            if (comptime observability.enabled) {
                const sid = std.fmt.bufPrint(&subject_buf, "{d}", .{key.user_id}) catch null;
                if (sid) |s| subject_id = s;
            }
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
        const subject_id: []const u8 = if (comptime observability.enabled)
            std.fmt.bufPrint(&subject_buf, "{d}", .{user_id}) catch ""
        else
            "";
        defer observability.endAuthnSpan(span, ok, if (ok) subject_id else null);

        self.mutex.lockUncancelable(ioh());
        defer self.mutex.unlock(ioh());

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
    /// The SAME allocator passed here MUST be passed to freeKeyList —
    /// mixing allocators is undefined behavior.
    pub fn listUserKeys(self: *Self, allocator: Allocator, user_id: u64) Allocator.Error![]ApiKey {
        self.mutex.lockUncancelable(ioh());
        defer self.mutex.unlock(ioh());

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
                errdefer freeScopes(allocator, copy.scopes);
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

    /// Delete expired AND revoked keys (cleanup). Revocation is permanent,
    /// so revoked entries are tombstones — removing them reclaims memory
    /// and max_keys quota. Returns the number of keys removed.
    pub fn cleanupExpired(self: *Self) Allocator.Error!usize {
        self.mutex.lockUncancelable(ioh());
        defer self.mutex.unlock(ioh());

        var to_remove: std.ArrayListUnmanaged([TOKEN_ID_SIZE]u8) = .empty;
        defer to_remove.deinit(self.allocator);

        const now = nowSeconds();
        var it = self.keys.iterator();
        while (it.next()) |entry| {
            const expired = if (entry.value_ptr.expires_at) |exp| now >= exp else false;
            if (expired or !entry.value_ptr.is_active) {
                try to_remove.append(self.allocator, entry.key_ptr.*);
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
pub fn formatApiKey(allocator: Allocator, prefix: []const u8, id: *const [TOKEN_ID_SIZE]u8, secret: *const [SECRET_SIZE]u8) Allocator.Error![]u8 {
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
pub fn parseApiKey(key_string: []const u8) ParseError!ParsedApiKey {
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
        defer manager.freeValidatedKey(k);
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

    if (try manager.validateKey(key_string)) |k| {
        manager.freeValidatedKey(k);
    } else return error.TestUnexpectedResult;
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

    if (try manager.validateKey(key_string)) |k| {
        manager.freeValidatedKey(k);
    } else return error.TestUnexpectedResult;

    const parsed = try parseApiKey(key_string);
    try std.testing.expect(manager.revokeKey(parsed.id));

    try std.testing.expect((try manager.validateKey(key_string)) == null);
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
    defer manager.freeValidatedKey(key);

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
    defer manager.freeValidatedKey(key);

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
    if (try manager.validateKey(k3)) |k| {
        manager.freeValidatedKey(k);
    } else return error.TestUnexpectedResult;
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
    if (try manager.validateKey(k2)) |k| {
        manager.freeValidatedKey(k);
    } else return error.TestUnexpectedResult;
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

test "validateKey returns owned deep copy safe after revoke" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const ks = try manager.createKey(7, "owned-key", &[_][]const u8{ "a:read", "b:write" }, null);
    defer allocator.free(ks);

    const key = (try manager.validateKey(ks)).?;
    defer manager.freeValidatedKey(key);

    // Destroy the manager's copy; the returned key must remain valid.
    const parsed = try parseApiKey(ks);
    _ = manager.revokeKey(parsed.id);
    _ = try manager.cleanupExpired();

    try std.testing.expectEqualStrings("owned-key", key.name);
    try std.testing.expect(ApiKeyManager.hasScope(&key, "a:read"));
}

test "createKey rejects key_prefix containing '.'" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{ .key_prefix = "my.app" });
    defer manager.deinit();
    try std.testing.expectError(error.InvalidKeyPrefix, manager.createKey(1, "x", &[_][]const u8{"r"}, null));
}

test "createKey enforces max_keys limit" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{ .max_keys = 2 });
    defer manager.deinit();
    const k1 = try manager.createKey(1, "a", &[_][]const u8{"r"}, null);
    defer allocator.free(k1);
    const k2 = try manager.createKey(1, "b", &[_][]const u8{"r"}, null);
    defer allocator.free(k2);
    try std.testing.expectError(error.KeyLimitReached, manager.createKey(1, "c", &[_][]const u8{"r"}, null));
}

test "pepper changes stored hash semantics" {
    const allocator = std.testing.allocator;
    const pepper: [32]u8 = @splat(0x42);
    var manager = ApiKeyManager.init(allocator, .{ .pepper = &pepper });
    defer manager.deinit();
    const ks = try manager.createKey(1, "peppered", &[_][]const u8{"r"}, null);
    defer allocator.free(ks);

    // Validates with the same pepper.
    const key = (try manager.validateKey(ks)).?;
    manager.freeValidatedKey(key);

    // A manager with a DIFFERENT pepper must reject the same key string.
    const other_pepper: [32]u8 = @splat(0x43);
    var other = ApiKeyManager.init(allocator, .{ .pepper = &other_pepper });
    defer other.deinit();
    try std.testing.expect((try other.validateKey(ks)) == null);
}

test "expiry boundary: expires_in_seconds=0 is immediately expired (inclusive >=)" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();
    const ks = try manager.createKey(1, "boundary", &[_][]const u8{"r"}, 0);
    defer allocator.free(ks);
    try std.testing.expect((try manager.validateKey(ks)) == null);
}

test "createKey accepts empty name and empty scopes" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();
    const ks = try manager.createKey(1, "", &[_][]const u8{}, null);
    defer allocator.free(ks);
    const key = (try manager.validateKey(ks)).?;
    defer manager.freeValidatedKey(key);
    try std.testing.expectEqual(@as(usize, 0), key.scopes.len);
    try std.testing.expectEqual(@as(usize, 0), key.name.len);
}

test "ApiKeyManager: concurrent create/validate/revoke under std.Thread" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{});
    defer manager.deinit();

    const Worker = struct {
        fn run(mgr: *ApiKeyManager, alloc: std.mem.Allocator, uid: u64, success: *std.atomic.Value(usize)) void {
            var i: usize = 0;
            while (i < 50) : (i += 1) {
                const ks = mgr.createKey(uid, "t", &[_][]const u8{"r"}, null) catch return;
                defer alloc.free(ks);
                const validated = mgr.validateKey(ks) catch null;
                if (validated) |key| {
                    mgr.freeValidatedKey(key);
                } else continue;
                const parsed = parseApiKey(ks) catch return;
                if (mgr.revokeKey(parsed.id)) {
                    _ = success.fetchAdd(1, .monotonic);
                }
            }
        }
    };

    var success = std.atomic.Value(usize).init(0);
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &manager, allocator, @as(u64, i), &success });
    }
    for (&threads) |*t| t.join();

    try std.testing.expectEqual(@as(usize, 200), success.load(.monotonic));
}

test "ApiKeyManager: cleanupExpired reclaims revoked keys (max_keys quota recovery)" {
    const allocator = std.testing.allocator;
    var manager = ApiKeyManager.init(allocator, .{ .max_keys = 1 });
    defer manager.deinit();
    const k1 = try manager.createKey(1, "rotate-me", &[_][]const u8{"r"}, null);
    defer allocator.free(k1);
    const parsed = try parseApiKey(k1);
    try std.testing.expect(manager.revokeKey(parsed.id));
    // Quota still consumed by the tombstone.
    try std.testing.expectError(error.KeyLimitReached, manager.createKey(1, "new", &[_][]const u8{"r"}, null));
    // Cleanup reclaims it.
    try std.testing.expectEqual(@as(usize, 1), try manager.cleanupExpired());
    const k2 = try manager.createKey(1, "new", &[_][]const u8{"r"}, null);
    defer allocator.free(k2);
}

test "hashSecret unpeppered equals seam SHA2-256 (stable across backends)" {
    const secret = [_]u8{0x5a} ** SECRET_SIZE;
    var got: [32]u8 = undefined;
    hashSecret(.{}, &secret, &got);
    var expect: [32]u8 = undefined;
    _ = try @import("crypto_backend").Hash.digest(.sha256, &secret, &expect);
    try std.testing.expectEqualSlices(u8, &expect, &got);
}
test "hashSecret peppered equals seam HMAC-SHA256 (stable across backends)" {
    const secret = [_]u8{0x5a} ** SECRET_SIZE;
    const pepper = [_]u8{0xc3} ** 32;
    var got: [32]u8 = undefined;
    hashSecret(.{ .pepper = &pepper }, &secret, &got);
    var expect: [32]u8 = undefined;
    _ = try @import("crypto_backend").Mac.hmac(.sha256, &pepper, &secret, &expect);
    try std.testing.expectEqualSlices(u8, &expect, &got);
}
