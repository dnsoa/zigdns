const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // === DNS 库 ===
    // addModule（非 createModule）：公开导出 "dns" 模块，使消费方（nexus-nsd 等）
    // 可经 dns_dep.module("dns") 解析。createModule 只建私有模块，跨包不可见。
    const dns_module = b.addModule("dns", .{
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

    // === 模糊测试 ===
    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    // 随 `zig build test` 编译并冒烟运行一次
    test_step.dependOn(&run_fuzz_tests.step);
    // 真正模糊：`zig build fuzz --fuzz`
    const fuzz_step = b.step("fuzz", "Run fuzz tests (append --fuzz to actually fuzz)");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // === 性能基准测试 ===
    // 必须为基准单独创建 ReleaseFast 的 dns 模块：公开导出的 dns_module 跟随用户 -Doptimize（默认 Debug），
    // 直接复用会导致 `zig build bench` 把被测库编译为 -Odebug。
    const bench_dns_module = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    const bench_module = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = true, // clock_gettime for timing
    });
    bench_module.addImport("dns", bench_dns_module);

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

        const run_example = b.addRunArtifact(example);
        const run_step = b.step("example-" ++ name, "Run the " ++ name ++ " example");
        run_step.dependOn(&run_example.step);

        const install_example = b.addInstallArtifact(example, .{});
        examples_step.dependOn(&install_example.step);
    }
}
