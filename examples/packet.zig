const std = @import("std");
const mem = std.mem;
const dns = @import("dns");
const Message = dns.Message;
const Builder = Message.Builder;
const Type = dns.Type;

pub fn main() !void {
    // 创建 DNS 查询报文
    var buffer: [512]u8 = undefined;
    var builder = Builder.init(&buffer);

    // 添加问题: example.com A 记录
    try builder.addQuestion("example.com", .A, 1);

    // 构造头部
    const header = dns.Header{
        .id = 1234,
        .rd = 1, // 期望递归
        .tc = 0,
        .aa = 0,
        .opcode = 0,
        .qr = 0, // 查询
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    const packet = builder.finish(header);

    // 输出编码后的报文 (hexdump)
    std.debug.print("Encoded packet ({d} bytes):\n", .{packet.len});
    for (packet, 0..) |byte, i| {
        if (i % 16 == 0) std.debug.print("\n{X:0>4}: ", .{i});
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n\n", .{});

    // 解析报文
    const parsed = try Message.parse(packet);

    // 打印解析后的信息
    std.debug.print("Decoded Packet:\n", .{});
    std.debug.print("  ID: {d}\n", .{parsed.header.id});
    std.debug.print("  QR: {d} (0=Query, 1=Response)\n", .{parsed.header.qr});
    std.debug.print("  Opcode: {d}\n", .{parsed.header.opcode});
    std.debug.print("  RD: {d} (Recursion Desired)\n", .{parsed.header.rd});
    std.debug.print("  QDCOUNT: {d}\n", .{parsed.header.qdcount});
    std.debug.print("  ANCOUNT: {d}\n", .{parsed.header.ancount});

    // 使用解析器读取问题
    var parser = dns.MessageParser.init(packet);
    if (try parser.nextQuestion()) |q| {
        std.debug.print("\n  Question:\n", .{});
        std.debug.print("    Name end position: {d}\n", .{q.qname_end_pos});
        std.debug.print("    Type: {d}\n", .{@intFromEnum(q.qtype)});
        std.debug.print("    Class: {d}\n", .{q.qclass});
    }
}
