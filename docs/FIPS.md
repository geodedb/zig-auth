# auth — FIPS-140-3 / PQC Mode

`auth` routes its security cryptography through a build-flag-gated seam
(`src/crypto_backend.zig`). The flag mirrors `-Dwith_otel`: off by
default, zero overhead when off, lazily-fetched `fips` dependency.

## Flag

- `-Dfips=false` (default): the seam selects `std_shim` (std.crypto).
  No OpenSSL link; zero comptime overhead.
- `-Dfips=true`: the seam selects the `fips` package (OpenSSL 3.x FIPS
  provider). Requires `make deps` (builds + verifies the provider) and
  `-Dopenssl_path=/usr/local/ssl`. `crypto_backend.assertActive()`
  hard-fails at startup if the validated provider is not loaded.

## Approved-algorithm map (what auth uses)

| auth use | Primitive | Routes through | FIPS status |
|----------|-----------|----------------|-------------|
| `hmac.deriveHmacKey` | HKDF-SHA256 | `Kdf.hkdf(.sha256, ...)` | Approved (SP 800-56C) |
| `hmac.computeRecordHmac` / `computeChainHash` | HMAC-SHA256 | `Mac.hmac(.sha256, ...)` | Approved (FIPS 198-1) |
| `api_keys.hashSecret` (peppered) | HMAC-SHA256 | `Mac.hmac(.sha256, ...)` | Approved |
| `api_keys.hashSecret` (unpeppered) | SHA-256 | `Hash.digest(.sha256, ...)` | Approved (FIPS 180-4) |
| `mfa.hashScratchCode` / `verifyScratchCode` | SHA-256 | `Hash.digest(.sha256, ...)` | Approved |
| `mfa.generateSecret` (deterministic, test-only) | HKDF-SHA256 | `Kdf.hkdf(.sha256, ...)` | Approved |
| API-key id/secret, TOTP secret, scratch entropy | CSPRNG | `Csprng.bytes(...)` | Approved (SP 800-90A under fips) |

## Exemptions

| auth use | Primitive | Reason |
|----------|-----------|--------|
| `mfa.generateCodeFromRaw` (TOTP) | HMAC-SHA1 | `// fips-exempt: legacy-interop` — RFC 6238 TOTP mandates HMAC-SHA1; it is a one-time-code derivation, not a confidentiality/integrity primitive, and has no SHA-2 equivalent in the protocol. Stays on `std.crypto` under both `-Dfips` values. |

## Constant-time utilities (not algorithms; kept on std.crypto)

`std.crypto.timing_safe.eql` (HMAC/hash comparison) and
`std.crypto.secureZero` (zeroization) are not FIPS algorithms and are
intentionally retained on the standard library in both modes.

## Behavior changes under `-Dfips=true`

None. Every routed primitive (HMAC-SHA256, HKDF-SHA256, SHA-256,
CSPRNG) is FIPS-approved and produces byte-identical output to the std
shim, verified by the KAT-equivalence tests in `src/hmac.zig`,
`src/api_keys.zig`, and `src/mfa.zig`. TOTP codes are unchanged
(HMAC-SHA1 exemption).
