const std = @import("std");
const dns = @import("dns");
const mem = std.mem;

/// DNS 查询报文示例
const QUERY_PACKET = "\x04\xd2\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" ++ // Header
    "\x07example\x03com\x00" ++ // Name
    "\x00\x01\x00\x01"; // Type A, Class IN

/// 含压缩回答和 EDNS ECS 的响应报文
const RESPONSE_PACKET =
    "\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01" ++ // Header
    "\x07example\x03com\x00\x00\x01\x00\x01" ++ // Question
    "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22" ++ // A answer
    "\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x0b" ++ // OPT header
    "\x00\x08\x00\x07\x00\x01\x18\x00\xc0\x00\x02"; // ECS option

fn BenchmarkResult(comptime T: type) type {
    return struct {
        elapsed_ns: i128,
        sink: T,
    };
}

fn runBenchmark(comptime Context: type, comptime T: type, context: *Context, iterations: usize, comptime func: fn (*Context, usize) anyerror!T) !BenchmarkResult(T) {
    var sink: T = undefined;

    var warmup: usize = 0;
    while (warmup < 1_000) : (warmup += 1) {
        sink = try func(context, warmup);
        mem.doNotOptimizeAway(&sink);
    }

    const start = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < iterations) : (i += 1) {
        sink = try func(context, i);
        mem.doNotOptimizeAway(&sink);
    }

    const elapsed_ns = std.time.nanoTimestamp() - start;
    mem.doNotOptimizeAway(&sink);
    return .{ .elapsed_ns = elapsed_ns, .sink = sink };
}

fn reportBenchmark(name: []const u8, iterations: usize, elapsed_ns: i128) void {
    const elapsed_ms = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000.0;
    const per_op_ns = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iterations));
    const throughput = @as(f64, @floatFromInt(iterations)) / (@as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0);

    std.debug.print("{s}\n", .{name});
    std.debug.print("  iterations: {d}\n", .{iterations});
    std.debug.print("  elapsed: {d:.2} ms\n", .{elapsed_ms});
    std.debug.print("  per op: {d:.2} ns\n", .{per_op_ns});
    std.debug.print("  throughput: {d:.0} ops/sec\n\n", .{throughput});
}

fn reportSlowdown(label: []const u8, base_ns: i128, candidate_ns: i128) void {
    const ratio = @as(f64, @floatFromInt(candidate_ns)) / @as(f64, @floatFromInt(base_ns));
    std.debug.print("{s}: {d:.2}x slower\n\n", .{ label, ratio });
}

fn reportVsBaseline(label: []const u8, baseline_ns: i128, baseline_iterations: usize, candidate_ns: i128, candidate_iterations: usize) void {
    const baseline_per_op = @as(f64, @floatFromInt(baseline_ns)) / @as(f64, @floatFromInt(baseline_iterations));
    const candidate_per_op = @as(f64, @floatFromInt(candidate_ns)) / @as(f64, @floatFromInt(candidate_iterations));
    std.debug.print("{s}: +{d:.2} ns over loop floor\n", .{ label, candidate_per_op - baseline_per_op });
}

pub fn main() !void {
    std.debug.print("=== DNS Library Benchmark ===\n\n", .{});

    try benchmarkBaseline();
    try benchmarkMessageParse();
    try benchmarkSectionParsing();
    try benchmarkNameParsing();
    try benchmarkEdnsScanning();
    try benchmarkEncode();

    std.debug.print("\nAll benchmarks completed!\n", .{});
}

fn benchmarkBaseline() !void {
    const iterations = 20_000_000;

    std.debug.print("=== Loop Baseline ===\n", .{});

    var state: usize = 0;
    const baseline = try runBenchmark(usize, usize, &state, iterations, struct {
        fn run(counter: *usize, iteration: usize) !usize {
            counter.* +%= iteration ^ 0x9e3779b97f4a7c15;
            return counter.*;
        }
    }.run);
    reportBenchmark("baseline loop", iterations, baseline.elapsed_ns);
}

fn benchmarkMessageParse() !void {
    const iterations = 5_000_000;

    std.debug.print("=== Message Parse ===\n", .{});

    var baseline_state: usize = 0;
    const baseline = try runBenchmark(usize, usize, &baseline_state, iterations, struct {
        fn run(counter: *usize, iteration: usize) !usize {
            counter.* +%= iteration;
            return counter.*;
        }
    }.run);

    var query_packet: [QUERY_PACKET.len]u8 = undefined;
    @memcpy(query_packet[0..], QUERY_PACKET);

    const header_only = try runBenchmark([QUERY_PACKET.len]u8, u16, &query_packet, iterations, struct {
        fn run(packet: *[QUERY_PACKET.len]u8, iteration: usize) !u16 {
            packet[1] = @truncate(iteration);
            const message = try dns.Message.parse(packet[0..]);
            return message.header.id;
        }
    }.run);
    reportBenchmark("header parse", iterations, header_only.elapsed_ns);
    reportVsBaseline("header parse", baseline.elapsed_ns, iterations, header_only.elapsed_ns, iterations);

    var response_packet: [RESPONSE_PACKET.len]u8 = undefined;
    @memcpy(response_packet[0..], RESPONSE_PACKET);

    const response_header = try runBenchmark([RESPONSE_PACKET.len]u8, u16, &response_packet, iterations, struct {
        fn run(packet: *[RESPONSE_PACKET.len]u8, iteration: usize) !u16 {
            packet[1] = @truncate(iteration);
            const message = try dns.Message.parse(packet[0..]);
            return message.header.ancount + message.header.arcount;
        }
    }.run);
    reportBenchmark("header parse with larger packet", iterations, response_header.elapsed_ns);
    reportVsBaseline("larger packet header parse", baseline.elapsed_ns, iterations, response_header.elapsed_ns, iterations);

    reportSlowdown("larger packet vs query header parse", header_only.elapsed_ns, response_header.elapsed_ns);
}

fn benchmarkEncode() !void {
    const iterations = 1_000_000;

    std.debug.print("=== Encode ===\n", .{});

    var baseline_state: usize = 0;
    const baseline = try runBenchmark(usize, usize, &baseline_state, iterations, struct {
        fn run(counter: *usize, iteration: usize) !usize {
            counter.* +%= iteration;
            return counter.*;
        }
    }.run);

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

    const EncodeQueryContext = struct {
        buffer: [512]u8 = undefined,
        header: dns.Header,
    };
    var query_context = EncodeQueryContext{ .header = header };

    const query_encode = try runBenchmark(EncodeQueryContext, usize, &query_context, iterations, struct {
        fn run(context: *EncodeQueryContext, iteration: usize) !usize {
            context.header.id = @truncate(iteration);
            var builder = dns.Message.Builder.init(&context.buffer);
            try builder.addQuestion("example.com", .A, 1);
            const packet = builder.finish(context.header);
            mem.doNotOptimizeAway(packet.ptr);
            return packet.len + packet[1];
        }
    }.run);
    reportBenchmark("encode single question", iterations, query_encode.elapsed_ns);
    reportVsBaseline("encode single question", baseline.elapsed_ns, iterations, query_encode.elapsed_ns, iterations);

    const EncodeRepeatedContext = struct {
        buffer: [512]u8 = undefined,
    };
    var repeated_context = EncodeRepeatedContext{};

    const repeated_names = try runBenchmark(EncodeRepeatedContext, usize, &repeated_context, iterations, struct {
        fn run(context: *EncodeRepeatedContext, iteration: usize) !usize {
            var builder = dns.Message.Builder.init(&context.buffer);
            try builder.addQuestion("example.com", .A, 1);
            try builder.addARecord("example.com", 60, [_]u8{ 93, 184, 216, 34 });
            try builder.addARecord("example.com", 60, [_]u8{ 93, 184, 216, @truncate(35 + (iteration & 0x0f)) });
            const packet = builder.finish(.{
                .id = @truncate(iteration),
                .rd = 1,
                .tc = 0,
                .aa = 1,
                .opcode = 0,
                .qr = 1,
                .rcode = 0,
                .z = 0,
                .ra = 0,
                .qdcount = 1,
                .ancount = 2,
                .nscount = 0,
                .arcount = 0,
            });
            mem.doNotOptimizeAway(packet.ptr);
            return packet.len + packet[packet.len - 1];
        }
    }.run);
    reportBenchmark("encode repeated owner names", iterations, repeated_names.elapsed_ns);
    reportVsBaseline("encode repeated owner names", baseline.elapsed_ns, iterations, repeated_names.elapsed_ns, iterations);

    reportSlowdown("repeated names encode vs single question", query_encode.elapsed_ns, repeated_names.elapsed_ns);
}

fn benchmarkSectionParsing() !void {
    const iterations = 2_000_000;

    std.debug.print("=== Section Parsing ===\n", .{});

    var baseline_state: usize = 0;
    const baseline = try runBenchmark(usize, usize, &baseline_state, iterations, struct {
        fn run(counter: *usize, iteration: usize) !usize {
            counter.* +%= iteration;
            return counter.*;
        }
    }.run);

    var query_packet: [QUERY_PACKET.len]u8 = undefined;
    @memcpy(query_packet[0..], QUERY_PACKET);

    const question_parse = try runBenchmark([QUERY_PACKET.len]u8, u16, &query_packet, iterations, struct {
        fn run(packet: *[QUERY_PACKET.len]u8, iteration: usize) !u16 {
            packet[1] = @truncate(iteration);
            var parser = dns.MessageParser.init(packet[0..]);
            var questions = parser.questions(1);
            const q = (try questions.next()).?;
            return q.qclass + packet[1];
        }
    }.run);
    reportBenchmark("parse one question", iterations, question_parse.elapsed_ns);
    reportVsBaseline("parse one question", baseline.elapsed_ns, iterations, question_parse.elapsed_ns, iterations);

    var response_packet: [RESPONSE_PACKET.len]u8 = undefined;
    @memcpy(response_packet[0..], RESPONSE_PACKET);

    const answer_parse = try runBenchmark([RESPONSE_PACKET.len]u8, u32, &response_packet, iterations, struct {
        fn run(packet: *[RESPONSE_PACKET.len]u8, iteration: usize) !u32 {
            packet[1] = @truncate(iteration);
            var parser = dns.MessageParser.init(packet[0..]);
            try parser.skipQuestions(1);
            var answers = parser.resourceRecords(1);
            const rr = (try answers.next()).?;
            return rr.ttl + packet[1];
        }
    }.run);
    reportBenchmark("skip question + parse one answer", iterations, answer_parse.elapsed_ns);
    reportVsBaseline("skip question + parse one answer", baseline.elapsed_ns, iterations, answer_parse.elapsed_ns, iterations);

    reportSlowdown("answer parse vs question parse", question_parse.elapsed_ns, answer_parse.elapsed_ns);
}

fn benchmarkNameParsing() !void {
    const iterations = 5_000_000;

    std.debug.print("=== Name Parsing ===\n", .{});

    var baseline_state: usize = 0;
    const baseline = try runBenchmark(usize, usize, &baseline_state, iterations, struct {
        fn run(counter: *usize, iteration: usize) !usize {
            counter.* +%= iteration;
            return counter.*;
        }
    }.run);

    var query_packet: [QUERY_PACKET.len]u8 = undefined;
    @memcpy(query_packet[0..], QUERY_PACKET);

    const iterator_parse = try runBenchmark([QUERY_PACKET.len]u8, usize, &query_packet, iterations, struct {
        fn run(packet: *[QUERY_PACKET.len]u8, iteration: usize) !usize {
            packet[19] = if ((iteration & 1) == 0) 'e' else 'f';
            var iter = dns.NameIterator{ .buffer = packet[0..], .pos = 12 };
            var label_bytes: usize = 0;
            while (try iter.next()) |label| {
                label_bytes += label.len + label[0];
            }
            return label_bytes;
        }
    }.run);
    reportBenchmark("iterate simple qname", iterations, iterator_parse.elapsed_ns);
    reportVsBaseline("iterate simple qname", baseline.elapsed_ns, iterations, iterator_parse.elapsed_ns, iterations);

    var response_packet: [RESPONSE_PACKET.len]u8 = undefined;
    @memcpy(response_packet[0..], RESPONSE_PACKET);

    const compressed_format = try runBenchmark([RESPONSE_PACKET.len]u8, usize, &response_packet, iterations, struct {
        fn run(packet: *[RESPONSE_PACKET.len]u8, iteration: usize) !usize {
            packet[19] = if ((iteration & 1) == 0) 'e' else 'f';
            var parser = dns.MessageParser.init(packet[0..]);
            try parser.skipQuestions(1);
            var answers = parser.resourceRecords(1);
            const rr = (try answers.next()).?;
            var name_buf: [256]u8 = undefined;
            const name = try parser.formatNameAt(rr.name_end_pos - 2, &name_buf);
            return name.len + name[0];
        }
    }.run);
    reportBenchmark("format compressed owner name", iterations, compressed_format.elapsed_ns);
    reportVsBaseline("format compressed owner name", baseline.elapsed_ns, iterations, compressed_format.elapsed_ns, iterations);

    const compressed_equals = try runBenchmark([RESPONSE_PACKET.len]u8, usize, &response_packet, iterations, struct {
        fn run(packet: *[RESPONSE_PACKET.len]u8, iteration: usize) !usize {
            packet[19] = if ((iteration & 1) == 0) 'e' else 'f';
            var parser = dns.MessageParser.init(packet[0..]);
            try parser.skipQuestions(1);
            var answers = parser.resourceRecords(1);
            const rr = (try answers.next()).?;
            const equals = try parser.nameEqualsAt(rr.name_end_pos - 2, if ((iteration & 1) == 0) "example.com" else "fxample.com");
            return @intFromBool(equals);
        }
    }.run);
    reportBenchmark("compare compressed owner name", iterations, compressed_equals.elapsed_ns);
    reportVsBaseline("compare compressed owner name", baseline.elapsed_ns, iterations, compressed_equals.elapsed_ns, iterations);

    reportSlowdown("compressed format vs iterator parse", iterator_parse.elapsed_ns, compressed_format.elapsed_ns);
    reportSlowdown("compressed format vs direct compare", compressed_equals.elapsed_ns, compressed_format.elapsed_ns);
}

fn benchmarkEdnsScanning() !void {
    const iterations = 2_000_000;

    std.debug.print("=== EDNS Scanning ===\n", .{});

    var baseline_state: usize = 0;
    const baseline = try runBenchmark(usize, usize, &baseline_state, iterations, struct {
        fn run(counter: *usize, iteration: usize) !usize {
            counter.* +%= iteration;
            return counter.*;
        }
    }.run);

    var response_packet: [RESPONSE_PACKET.len]u8 = undefined;
    @memcpy(response_packet[0..], RESPONSE_PACKET);

    const opt_lookup = try runBenchmark([RESPONSE_PACKET.len]u8, u16, &response_packet, iterations, struct {
        fn run(packet: *[RESPONSE_PACKET.len]u8, iteration: usize) !u16 {
            packet[RESPONSE_PACKET.len - 5] = @truncate(16 + (iteration & 0x0f));
            var parser = dns.MessageParser.init(packet[0..]);
            try parser.skipQuestions(1);
            try parser.skipResourceRecords(1);
            const opt = (try parser.findOptRecord(1)).?;
            return opt.class + packet[RESPONSE_PACKET.len - 5];
        }
    }.run);
    reportBenchmark("find OPT in additional section", iterations, opt_lookup.elapsed_ns);
    reportVsBaseline("find OPT in additional section", baseline.elapsed_ns, iterations, opt_lookup.elapsed_ns, iterations);

    const ecs_lookup = try runBenchmark([RESPONSE_PACKET.len]u8, u8, &response_packet, iterations, struct {
        fn run(packet: *[RESPONSE_PACKET.len]u8, iteration: usize) !u8 {
            packet[RESPONSE_PACKET.len - 5] = @truncate(16 + (iteration & 0x0f));
            var parser = dns.MessageParser.init(packet[0..]);
            try parser.skipQuestions(1);
            try parser.skipResourceRecords(1);
            const ecs = (try parser.findECS(1)).?;
            return ecs.source_prefix;
        }
    }.run);
    reportBenchmark("find ECS in OPT", iterations, ecs_lookup.elapsed_ns);
    reportVsBaseline("find ECS in OPT", baseline.elapsed_ns, iterations, ecs_lookup.elapsed_ns, iterations);

    reportSlowdown("ECS parse vs OPT lookup", opt_lookup.elapsed_ns, ecs_lookup.elapsed_ns);
}
