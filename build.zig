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

    const build_options = b.addOptions();
    build_options.addOption(bool, "with_otel", with_otel);
    // Materialize ONE shared `build_options` module. Each consumer module
    // imports the SAME module instance via `addImport` so we don't end up
    // with two divergent `build_options` modules referencing the same
    // file path (Zig 0.16 errors out with "file exists in modules X and
    // X0" when that happens).
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
        },
    });
    if (otel_module_opt) |om| module.addImport("otel", om);
    if (observability_init_mod_opt) |im| module.addImport("observability_init", im);

    // Unit tests (run tests defined in the module itself).
    // Built against `module` directly so every import the public root
    // resolves (observability, observability_init, otel) is in scope.
    const test_step = b.step("test", "Run unit tests");
    const unit_tests = b.addTest(.{ .root_module = module });
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
            },
        }),
    });
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
            },
        }),
    });
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
            },
        }),
    });
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
}
