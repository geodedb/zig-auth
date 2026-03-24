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

## Documentation

See the [docs](docs/) directory for detailed documentation.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and vulnerability reporting.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
