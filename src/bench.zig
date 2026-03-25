const std = @import("std");
const dns = @import("dns");

/// DNS 查询报文示例
const QUERY_PACKET = "\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ // Header
    "\x07example\x03com\x00" ++ // Name
    "\x00\x01\x00\x01"; // Type A, Class IN

pub fn main() !void {
    std.debug.print("=== DNS Library Benchmark ===\n\n", .{});

    // 解析性能测试
    try benchmarkParse();

    // 编码性能测试
    try benchmarkEncode();

    // 域名解析测试
    try benchmarkNameParsing();

    std.debug.print("\nAll benchmarks completed!\n", .{});
}

fn benchmarkParse() !void {
    const iterations = 1_000_000;

    std.debug.print("=== Parse Performance ===\n", .{});
    std.debug.print("Iterations: {d}\n", .{iterations});

    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        _ = try dns.Message.parse(QUERY_PACKET);
    }

    const end = std.time.nanoTimestamp();
    const elapsed = end - start;

    std.debug.print("Time: {d:.2} ms\n", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
    std.debug.print("Per packet: {d:.2} ns\n", .{@as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations))});
    std.debug.print("Packets/sec: {d:.0}\n\n", .{@as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0)});
}

fn benchmarkEncode() !void {
    const iterations = 1_000_000;

    std.debug.print("=== Encode Performance ===\n", .{});
    std.debug.print("Iterations: {d}\n", .{iterations});

    var buffer: [512]u8 = undefined;
    const header = dns.Header{
        .id = 1234,
        .rd = 1,
        .tc = 0,
        .aa = 0,
        .opcode = 0,
        .qr = 0,
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    // 预热
    {
        var b = dns.Message.Builder.init(&buffer);
        try b.addQuestion("example.com", .A, 1);
        _ = b.finish(header);
    }

    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var b = dns.Message.Builder.init(&buffer);
        try b.addQuestion("example.com", .A, 1);
        _ = b.finish(header);
    }

    const end = std.time.nanoTimestamp();
    const elapsed = end - start;

    std.debug.print("Time: {d:.2} ms\n", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
    std.debug.print("Per packet: {d:.2} ns\n", .{@as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations))});
    std.debug.print("Packets/sec: {d:.0}\n\n", .{@as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0)});
}

fn benchmarkNameParsing() !void {
    const iterations = 10_000_000;

    std.debug.print("=== Name Parsing Performance ===\n", .{});
    std.debug.print("Iterations: {d}\n", .{iterations});

    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        var iter = dns.NameIterator{ .buffer = QUERY_PACKET, .pos = 12 };
        while (try iter.next()) |_| {}
    }

    const end = std.time.nanoTimestamp();
    const elapsed = end - start;

    std.debug.print("Time: {d:.2} ms\n", .{@as(f64, @floatFromInt(elapsed)) / 1_000_000.0});
    std.debug.print("Per parse: {d:.2} ns\n", .{@as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations))});
    std.debug.print("Parses/sec: {d:.0}\n", .{@as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed)) / 1_000_000_000.0)});
}
