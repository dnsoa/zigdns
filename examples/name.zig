const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    std.debug.print("=== DNS Name Handling ===\n\n", .{});

    const domains = [_][]const u8{
        "example.com",
        "mail.example.com",
        "sub.domain.example.com",
        "localhost",
    };

    for (domains) |domain| {
        std.debug.print("Domain: '{s}'\n", .{domain});

        // 使用 Message.Builder 编码域名
        var buffer: [256]u8 = undefined;
        var builder = dns.Message.Builder.init(&buffer);
        try builder.addQuestion(domain, .A, 1);
        const packet = builder.finish(dns.Header{
            .id = 0,
            .rd = 0,
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
        });

        // 跳过头部 (12 字节) 获取域名部分
        const name_data = packet[12..];

        // 显示线缆格式
        std.debug.print("  Wire format ({d} bytes): ", .{name_data.len});
        for (name_data) |byte| {
            if (byte >= 32 and byte <= 126) {
                std.debug.print("{c}", .{byte});
            } else {
                std.debug.print("\\x{X:0>2}", .{byte});
            }
        }
        std.debug.print("\n", .{});

        // 使用 NameIterator 解析域名
        var iter = dns.NameIterator{ .buffer = packet, .pos = 12 };
        var label_count: usize = 0;
        std.debug.print("  Labels: ", .{});

        while (try iter.next()) |label| {
            if (label_count > 0) std.debug.print(".", .{});
            std.debug.print("{s}", .{label});
            label_count += 1;
        }
        std.debug.print("\n  Total labels: {d}\n", .{label_count});
        std.debug.print("---\n\n", .{});
    }

    // 测试压缩指针
    std.debug.print("=== Testing Compression Pointer ===\n\n", .{});

    var buffer: [512]u8 = undefined;
    var builder = dns.Message.Builder.init(&buffer);

    // 添加多个相同域名的记录，第二次应使用压缩指针
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });
    const pos1 = builder.pos;
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 2 });
    const pos2 = builder.pos;

    const saved_bytes = pos2 - pos1;
    std.debug.print("First record size: {d} bytes\n", .{pos1 - 12});
    std.debug.print("Second record size: {d} bytes\n", .{saved_bytes});
    std.debug.print("Saved by compression: {d} bytes\n", .{13 - 2 + 10});
}
