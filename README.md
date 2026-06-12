# auth

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.15.1+-orange.svg)](https://ziglang.org/)

Reusable authentication primitives for Zig applications.

## Features

- **HMAC Chain Integrity** -- HMAC-SHA256 record hashing, HKDF key derivation, chain tamper detection
- **API Key Management** -- Create, validate, revoke API keys with configurable prefixes and scoped access
- **MFA/TOTP** -- RFC 6238 TOTP enrollment, code generation, and verification
- **Zero Dependencies**: Pure Zig standard library only
- **Memory Safe**: Leak-free allocation patterns with `secureZero` on secrets
- **Well Tested**: 59 tests (47 unit + 12 integration), zero leaks

## Installation

### Using Zig Package Manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .auth = .{
        .url = "https://gitlab.com/devnw/zig/auth/-/archive/v0.1.0/auth-v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const auth = b.dependency("auth", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("auth", auth.module("auth"));
```

## Quick Start

```zig
const auth = @import("auth");

// HMAC chain integrity
const key = auth.hmac.deriveHmacKey(&master_key, .{});

// API key management
var mgr = auth.api_keys.ApiKeyManager.init(allocator, .{});
defer mgr.deinit();
const key_string = try mgr.createKey(user_id, "my-key", &.{"read"}, null);

// MFA enrollment
const enrollment = try auth.mfa.enroll(allocator, "alice", .{});
defer enrollment.deinit(allocator);
```

See [docs/USAGE.md](docs/USAGE.md) for the full usage guide.

## Requirements

- Zig 0.15.1 or later

## Building

```bash
# Build the library
make build

# Run tests
make test

# Quick development iteration
make dev

# Full CI pipeline
make ci
```

## Observability

`auth` ships an opt-in OpenTelemetry seam. Every public authn/authz
entry point is wrapped in a span:

- `auth.api_key` — emitted by `ApiKeyManager.validateKey`. On success
  the span is closed `.ok` with `enduser.id = <user_id>`. On failure
  (unknown key, wrong secret, expired, revoked, prefix mismatch) the
  span closes `.error_` with NO subject id attached, so failed
  attempts cannot be correlated to a known subject through tracing
  alone.
- `auth.api_key.issue` — emitted by `ApiKeyManager.createKey`.
- `auth.api_key.revoke` / `auth.api_key.revoke_all` — emitted by the
  revocation entry points. Revoke-of-unknown-id surfaces as `.error_`
  to highlight probing.
- `auth.mfa.enroll` — emitted by `mfa.enroll`. Subject id on success
  is the enrolling username (the public identifier).
- `auth.mfa` — emitted by `mfa.verifyCode`. Span status only
  (`.ok`/`.error_`); no subject id is attached because `verifyCode`
  receives the secret blob and code with no caller identity in scope.
- `authz.{scope}` — emitted by `ApiKeyManager.hasScope`. Both granted
  and denied checks are recorded for forensic auditing.

Span attributes carry only the post-success subject id, the auth
method label (`"password"`, `"token"`, `"mfa"`, `"api_key"`), and
policy vocabulary (action, resource). Raw passwords, tokens, API key
strings, password hashes, and TOTP secrets/codes are NEVER attached
as attributes — the seam's API contract refuses to accept them.
otel's redaction list is a backstop, not the primary defense.

The instrumentation is gated behind `-Dwith_otel`:

```bash
# Default — otel dependency is never resolved, the seam compiles to
# a comptime-known no-op, and the produced artifacts contain zero
# otel symbols (verified by otel/scripts/verify-consumer-noop.sh).
zig build

# Enabled — every entry point emits a span via the otel SDK.
zig build -Dwith_otel=true
```

When `-Dwith_otel=true`, configure the exporter via `OTEL_*`
environment variables (default: OTLP/HTTP to `http://localhost:4318`,
parent-based ratio sampler at 5%). Bootstrap from `main()`:

```zig
const auth = @import("auth");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Hold the Otel value at a stable address; the seam stores
    // pointers into its tracer/meter fields.
    if (auth.observability.enabled) {
        var otel = try auth.observability_init.Otel.init(alloc, "my-service");
        defer otel.deinit();
        otel.installGlobals();
    }

    // ... auth calls now emit spans automatically.
}
```

For full integration details, see the rollout recipe at
`otel/docs/integration/RECIPE.md`.

## Documentation

See the [docs](docs/) directory for detailed documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
