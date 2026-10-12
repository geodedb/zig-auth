// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // ========================================================================
    // Build Options
    // ========================================================================

    // -Dwith_otel: compile in otel instrumentation. OFF by default;
    // when off the otel dependency is never resolved and the seam
    // collapses to a comptime-known no-op (verified by
    // otel/scripts/verify-consumer-noop.sh).
    const with_otel = b.option(
        bool,
        "with_otel",
        "Compile in otel instrumentation (off by default; zero overhead when off)",
    ) orelse false;

    // -Dfips: route security crypto through the linked FIPS-140-3 provider.
    // OFF by default; zero overhead when off (the fips dependency is never
    // resolved and the seam selects the std.crypto shim).
    const fips = b.option(
        bool,
        "fips",
        "Route security crypto through the linked FIPS-140-3 provider (off by default; zero overhead when off)",
    ) orelse false;
    const openssl_path = b.option(
        []const u8,
        "openssl_path",
        "OpenSSL install prefix for non-standard installs (e.g. /usr/local/ssl)",
    );
    const link = @import("src/link.zig");

    const build_options = b.addOptions();
    build_options.addOption(bool, "with_otel", with_otel);
    build_options.addOption(bool, "fips", fips);
    // Materialize ONE shared `build_options` module. Each consumer module
    // imports the SAME module instance via `addImport` so we don't end up
    // with two divergent `build_options` modules referencing the same
    // file path (Zig 0.16 errors out with "file exists in modules X and
    // X0" when that happens).
    build_options.addOption([]const u8, "package_name", "auth");
    const build_options_mod = build_options.createModule();

    // Observability seam (otel). Declared as a SHARED NAMED MODULE so
    // every consumer (the lib root, plus the seam tests) resolves to the
    // same source file via `@import("observability")`. Using a relative
    // `@import("observability.zig")` from each module would trip Zig's
    // "file exists in modules X and Y" error because the file would be
    // pulled into multiple module trees. The seam's `enabled` flag
    // tracks `build_options.with_otel`; when off, every helper compiles
    // to a comptime-known no-op and the otel dependency is never
    // resolved. The optional `otel` import is wired below inside the
    // `if (with_otel)` block.
    const observability_mod = b.addModule("observability", .{
        .root_source_file = b.path("src/observability.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // ========================================================================
    // Crypto seam (fips). Mirrors the otel seam above: ONE shared named
    // module so every consumer resolves the same crypto_backend.zig via one
    // module identity (prevents the Zig 0.16 "file exists in modules X and
    // Y" dedup error, GAP-0020). Threads the SAME build_options_mod.
    // ========================================================================
    const crypto_backend_mod = b.addModule("crypto_backend", .{
        .root_source_file = b.path("src/crypto_backend.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });
    // std_shim backend: always available, std.crypto-backed, no OpenSSL link.
    const std_shim_mod = b.addModule("std_shim", .{
        .root_source_file = b.path("src/std_shim.zig"),
        .target = target,
        .optimize = optimize,
    });
    crypto_backend_mod.addImport("std_shim", std_shim_mod);
    // fips backend: resolved LAZILY only under -Dfips=true so the disabled
    // build never fetches OpenSSL-linked code. build.zig.zon pins the
    // published fips release as a lazy git+https dependency, so it must be
    // requested with `b.lazyDependency` (`b.dependency` panics on a lazy dep).
    if (fips) {
        if (b.lazyDependency("fips", .{
            .target = target,
            .optimize = optimize,
            .openssl_path = openssl_path orelse "/usr/local/ssl",
        })) |fips_dep| {
            const fips_mod = fips_dep.module("fips");
            crypto_backend_mod.addImport("fips", fips_mod);
            link.linkOpenssl(b, fips_mod, openssl_path);
        }
    }

    // ========================================================================
    // Observability seam (otel) — gated otel dependency + init helper
    // ========================================================================
    //
    // The `lazy = true` entry in build.zig.zon means Zig only fetches
    // the package when this branch executes; with the flag off the
    // dependency is never resolved and the produced artifacts contain
    // zero otel symbols (verified by otel/scripts/verify-consumer-noop.sh).
    //
    // Wired BEFORE the consumer modules + test roots are declared so
    // every root that imports `src/root.zig` (which gates
    // `@import("observability_init")` on `observability.enabled`) can
    // resolve the import in the enabled build.
    var otel_module_opt: ?*std.Build.Module = null;
    var observability_init_mod_opt: ?*std.Build.Module = null;
    if (with_otel) {
        const otel_dep = b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        }) orelse return;
        const otel_module = otel_dep.module("otel");
        otel_module_opt = otel_module;
        // The seam itself imports `otel` when enabled. Wire it onto the
        // shared observability module so every consumer sees the same
        // otel namespace.
        observability_mod.addImport("otel", otel_module);

        // Bootstrap helper. Only registered when `-Dwith_otel=true` so
        // the disabled build never compiles otel-touching code. Gated
        // from root.zig via
        // `if (observability.enabled) @import("observability_init")`.
        observability_init_mod_opt = b.addModule("observability_init", .{
            .root_source_file = b.path("src/observability_init.zig"),
            .target = target,
            .imports = &.{
                .{ .name = "otel", .module = otel_module },
                .{ .name = "observability", .module = observability_mod },
            },
        });
    }

    // ========================================================================
    // Public API Module
    // ========================================================================

    const module = b.addModule("auth", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "observability", .module = observability_mod },
            .{ .name = "build_options", .module = build_options_mod },
            .{ .name = "crypto_backend", .module = crypto_backend_mod },
        },
    });
    if (otel_module_opt) |om| module.addImport("otel", om);
    if (observability_init_mod_opt) |im| module.addImport("observability_init", im);

    // Unit tests (run tests defined in the module itself).
    // Built against `module` directly so every import the public root
    // resolves (observability, observability_init, otel) is in scope.
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{ .root_module = module });
    // Under -Dfips=true the lib root pulls crypto_backend -> fips
    // (OpenSSL-linked), so link OpenSSL onto the shared `module` once.
    // This covers unit_tests AND check (both use `module` as their root).
    if (fips) link.linkOpenssl(b, module, openssl_path);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Integration tests (separate test file with module import)
    const integration_step = b.step("test-integration", "Run integration tests");
    const integration_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/integration.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "auth", .module = module },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, integration_tests.root_module, openssl_path);
    const run_integration_tests = b.addRunArtifact(integration_tests);
    integration_step.dependOn(&run_integration_tests.step);

    // Check step for IDE integration (fast syntax validation).
    // Built against `module` so the observability gate resolves under
    // both flag values.
    const check_step = b.step("check", "Check for compilation errors");
    const check = b.addTest(.{ .root_module = module });
    check_step.dependOn(&check.step);

    // ========================================================================
    // Observability seam tests
    // ========================================================================

    // Disabled-mode no-op tests. Verifies `build_options.with_otel == false`
    // is the default and that the seam's public surface returns a
    // comptime-known no-op when otel is off. The test is skip-guarded for
    // the enabled build so it passes under both flag values.
    const observability_disabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_disabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "auth", .module = module },
                .{ .name = "build_options", .module = build_options_mod },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, observability_disabled_tests.root_module, openssl_path);
    const run_observability_disabled_tests = b.addRunArtifact(observability_disabled_tests);
    test_step.dependOn(&run_observability_disabled_tests.step);

    // Enabled-mode smoke test. Skips under -Dwith_otel=false; under
    // -Dwith_otel=true it installs an in-memory recorder, drives one
    // authn span through the seam, and asserts the recorder captured it.
    // Compiles cleanly under both flag values because the otel-namespace
    // identifiers sit behind `comptime if (enabled)` short-circuits.
    const observability_enabled_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/observability_enabled_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "auth", .module = module },
                .{ .name = "build_options", .module = build_options_mod },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, observability_enabled_tests.root_module, openssl_path);
    if (with_otel) {
        // Re-resolve the otel module under the same `with_otel` guard
        // so the smoke test reaches `@import("otel")`. The earlier
        // `lazyDependency` call handles `module`; the test root needs
        // its own import wire.
        const otel_dep = b.lazyDependency("otel", .{
            .target = target,
            .optimize = optimize,
        }) orelse return;
        observability_enabled_tests.root_module.addImport("otel", otel_dep.module("otel"));
    }
    const run_observability_enabled_tests = b.addRunArtifact(observability_enabled_tests);
    test_step.dependOn(&run_observability_enabled_tests.step);

    // ========================================================================
    // Crypto-backend seam test: resolves the seam under both -Dfips values.
    // ========================================================================
    const crypto_seam_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/crypto_backend_seam_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
                .{ .name = "build_options", .module = build_options_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, crypto_seam_tests.root_module, openssl_path);
    const run_crypto_seam_tests = b.addRunArtifact(crypto_seam_tests);
    test_step.dependOn(&run_crypto_seam_tests.step);
    check_step.dependOn(&crypto_seam_tests.step);

    // ========================================================================
    // FIPS exemption-boundary test: pins TOTP HMAC-SHA1 as the single
    // std.crypto exemption and verifies the auth.crypto_backend re-export.
    // ========================================================================
    const fips_exemption_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fips_exemption_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "auth", .module = module },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    // Embed the high-level security-path sources so the test's comptime
    // boundary guard can scan them for direct std.crypto algorithm use
    // (the seam impl — crypto_backend.zig/std_shim.zig — is intentionally
    // NOT embedded; the shim is the std.crypto backend itself). @embedFile
    // can't escape the package path with `../`, so each source is wired as
    // a named anonymous import resolved from the build root.
    fips_exemption_tests.root_module.addAnonymousImport("mfa_src", .{
        .root_source_file = b.path("src/mfa.zig"),
    });
    fips_exemption_tests.root_module.addAnonymousImport("api_keys_src", .{
        .root_source_file = b.path("src/api_keys.zig"),
    });
    fips_exemption_tests.root_module.addAnonymousImport("hmac_src", .{
        .root_source_file = b.path("src/hmac.zig"),
    });
    if (fips) link.linkOpenssl(b, fips_exemption_tests.root_module, openssl_path);
    const run_fips_exemption_tests = b.addRunArtifact(fips_exemption_tests);
    test_step.dependOn(&run_fips_exemption_tests.step);
    check_step.dependOn(&fips_exemption_tests.step);

    // ========================================================================
    // Example executable: `zig build example` builds and runs it.
    // ========================================================================

    const example_exe = b.addExecutable(.{
        .name = "example-basic",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/basic.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "auth", .module = module },
                .{ .name = "crypto_backend", .module = crypto_backend_mod },
            },
        }),
    });
    if (fips) link.linkOpenssl(b, example_exe.root_module, openssl_path);
    const example_step = b.step("example", "Build and run the basic example");
    const run_example = b.addRunArtifact(example_exe);
    example_step.dependOn(&run_example.step);
    check_step.dependOn(&example_exe.step);
}
