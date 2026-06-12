# Usage Guide

Practical guide to the three auth modules: API key management, HMAC chain
integrity, and MFA/TOTP. Each section covers configuration, ownership rules,
security invariants, and a working code snippet.

## Table of Contents

- [API Keys](#api-keys)
- [HMAC Chains](#hmac-chains)
- [MFA / TOTP](#mfa--totp)

---

## API Keys

### Token format

Every key string has three dot-separated fields:

```text
<prefix>.<id_b64url>.<secret_b64url>
```

- `prefix` — a human-readable version tag (e.g. `ak1`, `myapp2`).
- `id_b64url` — 16 random bytes, base64url encoded without padding (22 chars).
- `secret_b64url` — 32 random bytes, base64url encoded without padding (43 chars).

The secret is shown exactly once (returned by `createKey`) and is never stored
in plain form. Only an HMAC-SHA256 (or peppered variant) hash is retained.

### Config fields

```zig
pub const Config = struct {
    key_prefix:  []const u8   = "ak1",
    pepper:      ?*const [32]u8 = null,
    max_keys:    ?usize         = null,
};
```

**`key_prefix`** — Stamp every key your application issues with a recognizable
prefix. Use a short, dot-free string. `createKey` enforces the no-dot rule at
runtime: a prefix such as `"my.app"` returns `error.InvalidKeyPrefix`. Choose
per-application or per-key-generation values so you can rotate the prefix when
you rotate the secret scheme without ambiguity.

**`pepper`** — A 32-byte secret held outside the key store (e.g. fetched from a
KMS at startup and kept in memory). When set, stored hashes become
`HMAC-SHA256(pepper, secret)` instead of bare SHA-256. A full key-store
disclosure alone is then not matchable against captured key strings — an
attacker also needs the pepper. Changing the pepper invalidates every stored
key, so treat a rotation as a forced re-issue event.

**`max_keys`** — Hard cap on the number of live entries. `createKey` returns
`error.KeyLimitReached` once the map reaches this count. This guards against
unbounded map growth if key creation is exposed over an unauthenticated path.
Note that revoked keys remain as tombstones until you call `cleanupExpired`:
that method removes both expired AND revoked entries, reclaiming both memory
and the max_keys quota. Schedule periodic cleanup to prevent quota exhaustion
from accumulated revocations.

### Ownership rules

| Call | What is returned | How to free |
|---|---|---|
| `createKey(...)` | `[]u8` owned by the manager's allocator | `allocator.free(key_string)` with the same allocator you passed to `init` |
| `validateKey(...)` | `?ApiKey` — deep copy owned by the manager's allocator | `manager.freeValidatedKey(key)` |
| `listUserKeys(allocator, ...)` | `[]ApiKey` — deep copies owned by the allocator argument | `ApiKeyManager.freeKeyList(allocator, keys)` with the SAME allocator argument |

The `name` and `scopes` slices inside a validated `ApiKey` are independent
copies — safe to read after a concurrent revoke or cleanup.

### `parseBearerToken` — borrowed slice

```zig
pub fn parseBearerToken(auth_header: []const u8) ?[]const u8
```

Returns a sub-slice of `auth_header` with the `Bearer` prefix stripped and
whitespace trimmed. The returned slice borrows memory from the caller's buffer:
it becomes invalid the moment `auth_header` is freed or overwritten. Parse and
validate the key in the same stack frame; do not store the slice.

### Threading

All `ApiKeyManager` methods are safe to call from multiple OS threads. A
`std.Io.Mutex` serializes every access to the internal key map.

### Error handling

```zig
pub const CreateKeyError = Allocator.Error || std.Io.RandomSecureError || error{
    InvalidKeyPrefix,
    KeyLimitReached,
    TokenIdCollision,
};
```

`TokenIdCollision` is theoretically possible (two concurrent creates that
generate the same 16-byte random id) but vanishingly rare — treat it as a
transient error and retry.

```zig
const key_string = manager.createKey(user_id, "ci-key", &.{"ci:read"}, 3600) catch |err| switch (err) {
    error.InvalidKeyPrefix  => return error.BadConfig,
    error.KeyLimitReached   => return error.QuotaExceeded,
    error.TokenIdCollision  => return error.PleaseRetry,
    error.OutOfMemory       => return error.OutOfMemory,
    else                    => return err,
};
defer allocator.free(key_string);
```

### Working snippet

```zig
const std = @import("std");
const auth = @import("auth");

pub fn apiKeyDemo(allocator: std.mem.Allocator) !void {
    const pepper: [32]u8 = @splat(0xAB); // load from KMS in production

    var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{
        .key_prefix = "v1",
        .pepper     = &pepper,
        .max_keys   = 1000,
    });
    defer mgr.deinit();

    // Issue a key that expires in one hour.
    const key_string = try mgr.createKey(42, "deploy-bot", &.{ "ci:read", "deploy:write" }, 3600);
    defer allocator.free(key_string);

    // Extract the token from an HTTP Authorization header.
    const header = "Bearer " ++ key_string;
    const token = auth.api_keys.parseBearerToken(header) orelse return error.MissingToken;

    // Validate (returns a deep copy safe to hold across concurrent revokes).
    if (try mgr.validateKey(token)) |key| {
        defer mgr.freeValidatedKey(key);
        const can_deploy = auth.api_keys.ApiKeyManager.hasScope(&key, "deploy:write");
        _ = can_deploy;
    }

    // Periodic maintenance — reclaims revoked tombstones and max_keys quota.
    _ = try mgr.cleanupExpired();
}
```

---

## HMAC Chains

### Key derivation

```zig
pub fn deriveHmacKey(master_key: *const [32]u8, config: HkdfConfig) [32]u8
```

Derives a 32-byte signing key from a master key using HKDF-SHA256. Never use
the raw master key directly as an HMAC key — the derivation provides domain
separation so the same master can safely produce keys for different subsystems.

```zig
pub const HkdfConfig = struct {
    salt: []const u8 = "auth-hmac-v1",
    info: []const u8 = "auth-chain-integrity",
};
```

The default `salt` and `info` are development-only domain-separation strings.
In production, supply your own values that are unique per deployment and
purpose:

```zig
const signing_key = auth.hmac.deriveHmacKey(&master_key, .{
    .salt = "myapp-hmac-v1",
    .info = "audit-log-integrity",
});
```

Rotating `salt` or `info` produces a completely different derived key, which
will invalidate all HMACs computed with the old key — plan rotations carefully.

### Record HMAC

```zig
pub fn computeRecordHmac(key: *const [32]u8, props: []const KeyValue) error{TooManyProperties}![32]u8
```

Computes HMAC-SHA256 over a set of key-value properties. Properties are sorted
by key then value (lexicographic, ascending) before hashing, so the result is
deterministic regardless of the order you pass them in. Duplicate keys are
handled by total-ordering over both key and value.

Each property is serialized as length-prefixed bytes:

```text
key_len (u32 LE) || key || value_len (u32 LE) || value
```

This format is unambiguous — no two distinct key/value pairs can produce the
same byte stream.

The cap is 128 properties. Exceeding it returns `error.TooManyProperties`
rather than silently allocating heap memory.

```zig
pub const KeyValue = struct {
    key:   []const u8,
    value: []const u8,
};
```

### Chain hash

```zig
pub fn computeChainHash(
    key: *const [32]u8,
    record_hmacs: []const [32]u8,
    record_count: u64,
) error{RecordCountMismatch}![32]u8
```

Hashes a sequence of per-record HMACs together, mixing in the record count:

```text
HMAC-SHA256(key, hmac[0] || hmac[1] || ... || count_le64)
```

The count guards against truncation attacks where an attacker removes trailing
records while keeping the prefix intact. `record_count` must equal
`record_hmacs.len` — a mismatch returns `error.RecordCountMismatch`.

### Verification and hex helpers

`verifyHmac` performs a constant-time comparison of two 32-byte HMACs. Never
use `std.mem.eql` for MAC comparison.

```zig
pub fn verifyHmac(expected: *const [32]u8, actual: *const [32]u8) bool
pub fn hmacToHex(hmac_bytes: *const [32]u8) [64]u8
pub fn hexToHmac(hex: *const [64]u8) ![32]u8
```

### Working snippet

```zig
const std = @import("std");
const auth = @import("auth");

pub fn hmacDemo() !void {
    const master: [32]u8 = @splat(0x2A); // load from KMS in production

    const signing_key = auth.hmac.deriveHmacKey(&master, .{
        .salt = "myapp-hmac-v1",
        .info = "audit-log-integrity",
    });

    // Sign a record.
    const props = [_]auth.hmac.KeyValue{
        .{ .key = "user_id", .value = "42" },
        .{ .key = "action",  .value = "login" },
    };
    const record_mac = try auth.hmac.computeRecordHmac(&signing_key, &props);

    // Chain multiple records.
    const macs = [_][32]u8{record_mac};
    const chain = try auth.hmac.computeChainHash(&signing_key, &macs, 1);

    // Verify.
    const chain_hex = auth.hmac.hmacToHex(&chain);
    const recovered = try auth.hmac.hexToHmac(&chain_hex);
    _ = auth.hmac.verifyHmac(&chain, &recovered);
}
```

---

## MFA / TOTP

### Configuration

```zig
pub const MfaConfig = struct {
    digits:             u8       = 6,
    step_seconds:       u64      = 30,
    window:             i32      = 1,
    scratch_code_count: usize    = 2,
    deterministic:      bool     = false,
    salt:               []const u8 = "auth-mfa-salt-v1",
};
```

`MfaConfig.validate()` is called automatically by `enroll`, `generateCode`,
`verifyCode`, `verifyCodeStep`, and `verifyCodeOnce`. The enforced ranges are:

| Field | Valid range | Why |
|---|---|---|
| `digits` | 6–9 | Below 6 violates RFC 4226 minimum; above 9 overflows the u32 code space |
| `step_seconds` | > 0 | Zero causes a division by zero in the timestep calculation |
| `window` | 0–64 | Negative silently rejects every code (lockout); larger values defeat clock-skew tolerance |

Out-of-range values return `error.InvalidMfaConfig`.

**`deterministic` is TEST-ONLY.** Setting it true in a non-test build (`zig
build`, not `zig test`) returns `error.DeterministicModeIsTestOnly` — this gate
is enforced at compile time via `builtin.is_test`. Never set `deterministic =
true` in any production path.

### Enrollment

```zig
pub fn enroll(allocator: std.mem.Allocator, username: []const u8, config: MfaConfig) EnrollError!Enrollment
```

Returns an `Enrollment` containing:

- `secret_base32: []u8` — RFC 4648 Base32-encoded TOTP secret to give to the
  user's authenticator app. Store only the Base32 form; it is the input to all
  other API calls.
- `scratch_codes: [][]u8` — recovery codes (count controlled by
  `scratch_code_count`). Each code is 32 Base32 characters (160 bits of CSPRNG
  entropy), independent of the TOTP secret.

Show the secret and recovery codes to the user exactly once at enrollment time.
Do not persist them in plain form. Store only:

- The Base32 secret (needed for future TOTP verification).
- The hash of each scratch code: `hashScratchCode(code)` returns a `[32]u8`.
- A consumed flag per scratch code, initially `false`.

```zig
const enrollment = try auth.mfa.enroll(allocator, "alice", .{});
defer enrollment.deinit(allocator);

// Hash and store each recovery code.
var stored_hashes: [2][32]u8 = undefined;
var consumed:      [2]bool    = .{ false, false };
for (enrollment.scratch_codes, 0..) |code, i| {
    stored_hashes[i] = auth.mfa.hashScratchCode(code);
}
// Show enrollment.secret_base32 and enrollment.scratch_codes to the user NOW.
// After deinit, they are gone.
```

### Recovery code verification

```zig
pub fn verifyScratchCode(
    hashes:    []const [32]u8,
    consumed:  []bool,
    presented: []const u8,
) ?usize
```

Scans all hashes with constant-time comparison (no early exit). On success,
marks the matched slot consumed and returns its index; returns `null` on any
failure. Normalize the presented code to uppercase and strip separators before
calling.

**Concurrency:** `verifyScratchCode` is not atomic. Serialize calls per user at
the application layer. In persistent deployments, make the consumed-flag update
atomic with the verification — use a conditional UPDATE / compare-and-set, not
a read-verify-writeback pattern.

Scratch codes are single-use and are never reinstated. On match, immediately
persist the updated `consumed` array before responding to the caller.

### TOTP verification and replay protection

Three verification functions are available with different replay guarantees:

| Function | Replay protection | When to use |
|---|---|---|
| `verifyCode` | None | Never in production for login |
| `verifyCodeStep` | Caller-managed | When you implement your own persistence |
| `verifyCodeOnce` | Built-in high-water mark | Recommended for most applications |

**`verifyCode`** returns a boolean. It cannot reject a replayed code within the
acceptance window — two requests with the same code submitted within the same
30-second step will both pass.

**`verifyCodeStep`** returns the matched timestep as `?u64`. Persist this value
(`last_used_step`) per user. On the next verification, reject any step that is
not strictly greater than the persisted value.

**`verifyCodeOnce`** wraps `verifyCodeStep` with an in-process high-water mark.
Pass a pointer to a `u64` initialized to `0` at enrollment time. The code is
accepted only if its step is strictly greater than the stored value; on
acceptance the pointer is advanced. Persist the updated value atomically with
the login event.

```zig
const step = try auth.mfa.verifyCodeStep(allocator, secret, now_ms, code, cfg);
if (step) |s| {
    if (s <= last_persisted_step) return error.ReplayedCode;
    // atomically persist s as the new high-water mark, then accept
}
```

```zig
var last_step: u64 = load_from_db(user_id); // 0 for new enrollments
const accepted = try auth.mfa.verifyCodeOnce(allocator, secret, now_ms, code, &last_step, .{});
if (accepted) save_to_db(user_id, last_step);
```

### otpauth URI guidance

When building `otpauth://totp/...` URIs to display as QR codes, always
percent-encode the issuer and account fields. Never interpolate raw user input:
a username containing `:` or `?secret=` corrupts or overrides URI fields.

```zig
// UNSAFE — never do this:
// const uri = "otpauth://totp/" ++ issuer ++ ":" ++ username ++ "?secret=" ++ secret;

// SAFE — percent-encode issuer and account before building the URI.
// Use a URI encoding library or manually encode ':' as '%3A', '?' as '%3F',
// '&' as '%26', '=' as '%3D', and any other reserved characters.
```

### Working snippet

```zig
const std = @import("std");
const auth = @import("auth");

pub fn mfaDemo(allocator: std.mem.Allocator) !void {
    // Enroll a user.
    const enrollment = try auth.mfa.enroll(allocator, "alice", .{});
    defer enrollment.deinit(allocator);

    // Store scratch code hashes (never store plain codes).
    var hashes: [2][32]u8 = undefined;
    var consumed: [2]bool = .{ false, false };
    for (enrollment.scratch_codes, 0..) |code, i| {
        hashes[i] = auth.mfa.hashScratchCode(code);
    }

    // At login time: generate and verify a TOTP code with replay protection.
    const io = std.Io.Threaded.global_single_threaded.io();
    const now_ms: u64 = @intCast(std.Io.Timestamp.now(io, .real).toMilliseconds());
    const code = try auth.mfa.generateCode(allocator, enrollment.secret_base32, now_ms, .{});

    var last_step: u64 = 0; // load from persistent storage per user
    const accepted = try auth.mfa.verifyCodeOnce(
        allocator,
        enrollment.secret_base32,
        now_ms,
        code,
        &last_step,
        .{},
    );
    if (accepted) {
        // persist last_step atomically with the login event
        _ = last_step;
    }

    // Recovery code verification (after the user loses their authenticator).
    const presented = enrollment.scratch_codes[0]; // user submits this
    const idx = auth.mfa.verifyScratchCode(&hashes, &consumed, presented);
    if (idx != null) {
        // persist updated consumed array atomically
    }
}
```
