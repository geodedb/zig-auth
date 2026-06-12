# auth

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/Zig-0.16.0+-orange.svg)](https://ziglang.org/)

Reusable authentication primitives for Zig applications.

## Features

- **HMAC Chain Integrity** -- HMAC-SHA256 record hashing, HKDF key derivation, chain tamper detection
- **API Key Management** -- Create, validate, revoke API keys with configurable prefixes and scoped access
- **MFA/TOTP** -- RFC 6238 TOTP enrollment, code generation, and verification
- **Zero dependencies by default** — pure Zig stdlib; optional OpenTelemetry instrumentation behind `-Dwith_otel` (currently inert — see [Observability](#observability))
- **Memory Safe**: Leak-free allocation patterns with `secureZero` on secrets
- **Tested** — comprehensive unit + integration suite, leak-checked allocations, fuzzed in CI

## Installation

### Using Zig Package Manager

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .auth = .{
        .url = "https://gitlab.com/devnw/zig/auth/-/archive/v0.1.7/auth-v0.1.7.tar.gz",
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

- Zig 0.16.0 or later

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

`auth` ships an opt-in OpenTelemetry seam. The seam is wired at every
public authn/authz entry point (`ApiKeyManager.validateKey`,
`ApiKeyManager.createKey`, `ApiKeyManager.revoke*`, `mfa.enroll`,
`mfa.verifyCode`, `ApiKeyManager.hasScope`), but is **currently inert**
regardless of the `-Dwith_otel` flag.

**Status: INERT (tracked as GAP-0020 / [issue #66](https://gitlab.com/devnw/zig/auth/-/issues/66)).**
`src/observability.zig` hardcodes `enabled = false` as of 2026-05-02
due to a Zig 0.16 module-dedup quirk that surfaces when `auth` is
reached through multiple paths in a downstream build graph (a
`build_options` vs `build_options0` diamond). The seam is preserved as
a permanent no-op for forward-compatibility and will be restored once
the upstream Zig dedup issue is resolved.

**Until the seam is restored:**

- `zig build -Dwith_otel=true` still type-checks the otel wiring (no
  build errors), but zero auth security events are emitted at runtime.
- Add application-level logging around auth calls in your own code to
  capture security-relevant events in the interim.

### Design principles (preserved for when the seam is restored)

Span attributes will carry only the post-success subject id, the auth
method label (`"password"`, `"token"`, `"mfa"`, `"api_key"`), and
policy vocabulary (action, resource). Raw passwords, tokens, API key
strings, password hashes, and TOTP secrets/codes are NEVER attached
as attributes — the seam's API contract refuses to accept them.
otel's redaction list is a backstop, not the primary defense.

The instrumentation will be gated behind `-Dwith_otel`:

```bash
# Default — otel dependency is never resolved, the seam compiles to
# a comptime-known no-op, and the produced artifacts contain zero
# otel symbols.
zig build

# Type-checks otel wiring; currently still produces no spans at runtime
# (see GAP-0020 / issue #66).
zig build -Dwith_otel=true
```

For full integration details, see [gitlab.com/devnw/zig/otel](https://gitlab.com/devnw/zig/otel).

## Documentation

See the [docs](docs/) directory for detailed documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
