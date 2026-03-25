const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    std.debug.print("=== DNS Response Construction ===\n\n", .{});

    // 创建 DNS 响应报文
    var buffer: [512]u8 = undefined;
    var builder = dns.Message.Builder.init(&buffer);

    // 添加问题 (模拟查询)
    try builder.addQuestion("example.com", .A, 1);
    std.debug.print("Added question: example.com IN A\n", .{});

    // 添加 A 记录回答
    try builder.addARecord("example.com", 3600, [_]u8{ 93, 184, 216, 34 });
    std.debug.print("Added A record answer: 93.184.216.34\n", .{});

    // 添加 AAAA 记录回答
    try builder.addAAAARecord("example.com", 3600, [_]u8{
        0x20, 0x01, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });
    std.debug.print("Added AAAA record answer: 2001:408::\n", .{});

    // 添加 TXT 记录
    try builder.addTXTRecord("example.com", 3600, "v=spf1 -all");
    std.debug.print("Added TXT record: SPF record\n", .{});

    // 构造响应头部
    const header = dns.Header{
        .id = 1234,
        .rd = 1, // 递归期望 (从查询复制)
        .tc = 0,
        .aa = 1, // 权威回答
        .opcode = 0,
        .qr = 1, // 响应
        .rcode = 0,
        .z = 0,
        .ra = 1, // 递归可用
        .qdcount = 1, // 1 个问题
        .ancount = 3, // 3 个回答
        .nscount = 0,
        .arcount = 0,
    };

    const packet = builder.finish(header);

    // 打印报文内容
    std.debug.print("\n=== Constructed DNS Response ===\n", .{});
    std.debug.print("  ID: {d}\n", .{header.id});
    std.debug.print("  QR: {d} (1=Response)\n", .{header.qr});
    std.debug.print("  Opcode: {d}\n", .{header.opcode});
    std.debug.print("  AA: {d} (Authoritative)\n", .{header.aa});
    std.debug.print("  RD: {d} (Recursion Desired)\n", .{header.rd});
    std.debug.print("  RA: {d} (Recursion Available)\n", .{header.ra});
    std.debug.print("  RCODE: {d}\n", .{header.rcode});
    std.debug.print("  QDCOUNT: {d}\n", .{header.qdcount});
    std.debug.print("  ANCOUNT: {d}\n", .{header.ancount});

    // 输出十六进制转储
    std.debug.print("\nHex dump:\n", .{});
    for (packet, 0..) |byte, i| {
        if (i % 16 == 0) std.debug.print("\n{X:0>4}: ", .{i});
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n\n", .{});

    // 解析验证
    std.debug.print("=== Parsing Response ===\n", .{});

    _ = try dns.Message.parse(packet);
    std.debug.print("Parsed header successfully\n", .{});

    var parser = dns.MessageParser.init(packet);

    // 读取问题
    if (try parser.nextQuestion()) |q| {
        std.debug.print("  Question: Type={d}, Class={d}\n", .{
            @intFromEnum(q.qtype),
            q.qclass,
        });
    }

    // 读取回答
    var i: u32 = 1;
    while (try parser.nextRR()) |rr| {
        std.debug.print("  Answer {d}: ", .{i});

        // 使用 RData.parse 解析 RDATA 字节
        const rdata = dns.ResourceData.parse(rr.rtype, rr.rdata) catch |err| {
            std.debug.print("(parse error: {}) Type={d}\n", .{ err, @intFromEnum(rr.rtype) });
            i += 1;
            continue;
        };

        switch (rdata) {
            .A => |ip| {
                std.debug.print("A {d}.{d}.{d}.{d} TTL={d}\n", .{
                    ip[0], ip[1], ip[2], ip[3], rr.ttl,
                });
            },
            .AAAA => |ip| {
                std.debug.print("AAAA ", .{});
                for (ip, 0..) |b, j| {
                    if (j > 0 and j % 2 == 0) std.debug.print(":", .{});
                    std.debug.print("{X:0>2}", .{b});
                }
                std.debug.print(" TTL={d}\n", .{rr.ttl});
            },
            .TXT => |txt| {
                std.debug.print("TXT \"{s}\" TTL={d}\n", .{ txt, rr.ttl });
            },
            else => {
                std.debug.print("Type={d}\n", .{@intFromEnum(rr.rtype)});
            },
        }
        i += 1;
    }

    std.debug.print("\nTotal encoded packet size: {d} bytes\n", .{packet.len});
}
