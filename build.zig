const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // === DNS 库 ===
    const dns_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // 库测试
    const lib_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);

    // === 性能基准测试 ===
    const bench_module = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_module.addImport("dns", dns_module);

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_module,
    });

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run DNS benchmarks");
    bench_step.dependOn(&run_bench.step);

    // === 示例程序 ===
    const example_names = [_][]const u8{
        "packet",
        "name",
        "response",
        "records",
    };

    const examples_step = b.step("examples", "Build all examples");

    inline for (example_names) |name| {
        const example = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/" ++ name ++ ".zig"),
                .target = target,
                .optimize = optimize,
            }),
        });

        // 将 dns 模块添加到示例的导入中
        example.root_module.addImport("dns", dns_module);

        b.installArtifact(example);

        const run_example = b.addRunArtifact(example);
        const run_step = b.step("example-" ++ name, "Run the " ++ name ++ " example");
        run_step.dependOn(&run_example.step);

        examples_step.dependOn(&b.addInstallArtifact(example, .{}).step);
    }
}
