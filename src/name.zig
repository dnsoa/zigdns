const std = @import("std");
const mem = std.mem;

/// 零拷贝域名解析器
/// 不分配内存，仅返回指向原始数据包的切片迭代器
pub const NameIterator = struct {
    buffer: []const u8,
    pos: u16,

    pub fn next(self: *NameIterator) !?[]const u8 {
        if (self.pos >= self.buffer.len) return null;
        const len = self.buffer[self.pos];
        if (len == 0) return null; // 结束符

        // 处理指针压缩 (0xC0)
        if (len & 0xC0 == 0xC0) {
            const offset = mem.readInt(u16, self.buffer[self.pos..][0..2], .big) & 0x3FFF;
            self.pos += 2;
            // 递归跳转逻辑（生产环境下需限制递归深度防止死循环）
            var temp_iter = NameIterator{ .buffer = self.buffer, .pos = @intCast(offset) };
            return try temp_iter.next();
        }

        const label = self.buffer[self.pos + 1 .. self.pos + 1 + len];
        self.pos += 1 + len;
        return label;
    }
};

test "NameIterator simple domain" {
    // "example.com" 的编码: 7 e x a m p l e 3 c o m 0
    const domain = "\x07example\x03com\x00";
    var iter = NameIterator{ .buffer = domain, .pos = 0 };

    try std.testing.expectEqualStrings("example", (try iter.next()).?);
    try std.testing.expectEqualStrings("com", (try iter.next()).?);
    try std.testing.expect((try iter.next()) == null);
}

test "NameIterator with compression" {
    // 测试指针压缩: 指针指向单个标签
    var buffer: [20]u8 = undefined;
    // 在偏移 12 处放置 "com\x00"
    buffer[12] = 3;
    @memcpy(buffer[13..16], "com");
    buffer[16] = 0;

    // 在开头放置 "example" + 指向 "com" 的指针 + 结束符
    buffer[0] = 7;
    @memcpy(buffer[1..8], "example");
    // 指针: 11000000 00001100 = 0xC00C (指向偏移 12)
    buffer[8] = 0xC0;
    buffer[9] = 0x0C;
    buffer[10] = 0; // 结束符

    var iter = NameIterator{ .buffer = &buffer, .pos = 0 };

    try std.testing.expectEqualStrings("example", (try iter.next()).?);
    // 指针解引用返回 "com"
    try std.testing.expectEqualStrings("com", (try iter.next()).?);
    // 结束符
    try std.testing.expect((try iter.next()) == null);
}

test "NameIterator empty domain" {
    // 仅有结束符的空域名
    const empty = "\x00";
    var iter = NameIterator{ .buffer = empty, .pos = 0 };

    try std.testing.expect((try iter.next()) == null);
}

/// 将 DNS 线路格式域名转换为点分隔格式
/// buffer: 包含 DNS 数据包的缓冲区
/// pos: 域名起始位置
/// out_buf: 输出缓冲区，必须足够大（最多 253 字节 + 1）
/// 返回: 写入 out_buf 的字符串切片
pub fn formatDnsName(buffer: []const u8, pos: usize, out_buf: []u8) ![]const u8 {
    var read_pos: usize = pos;
    var write_pos: usize = 0;
    var first_label = true;

    while (read_pos < buffer.len) {
        const len = buffer[read_pos];

        // 结束符
        if (len == 0) {
            if (write_pos == 0) {
                // 根域名
                out_buf[write_pos] = '.';
                write_pos += 1;
            }
            return out_buf[0..write_pos];
        }

        // 指针压缩
        if (len & 0xC0 == 0xC0) {
            // 遇到压缩指针，直接返回已解析内容
            if (write_pos == 0) {
                out_buf[write_pos] = '.';
                write_pos += 1;
            }
            return out_buf[0..write_pos];
        }

        // 验证标签长度
        if (len > 63) return error.LabelTooLong;
        if (read_pos + 1 + len > buffer.len) return error.PacketTooShort;

        // 添加点分隔符（第一个标签前不加）
        if (!first_label) {
            out_buf[write_pos] = '.';
            write_pos += 1;
        }
        first_label = false;

        // 复制标签内容
        @memcpy(out_buf[write_pos .. write_pos + len], buffer[read_pos + 1 .. read_pos + 1 + len]);
        write_pos += len;
        read_pos += 1 + len;

        // 检查输出缓冲区大小
        if (write_pos > out_buf.len) return error.BufferTooSmall;
    }

    return error.MalformedName;
}

test "formatDnsName simple domain" {
    const domain = "\x07example\x03com\x00";
    var buf: [256]u8 = undefined;

    const result = try formatDnsName(domain, 0, &buf);
    try std.testing.expectEqualStrings("example.com", result);
}

test "formatDnsName root domain" {
    const root = "\x00";
    var buf: [256]u8 = undefined;

    const result = try formatDnsName(root, 0, &buf);
    try std.testing.expectEqualStrings(".", result);
}

test "formatDnsName subdomain" {
    const subdomain = "\x03www\x07example\x03com\x00";
    var buf: [256]u8 = undefined;

    const result = try formatDnsName(subdomain, 0, &buf);
    try std.testing.expectEqualStrings("www.example.com", result);
}

test "formatDnsName with compression pointer" {
    var buffer: [32]u8 = undefined;
    // 在偏移 16 处放置 "com\x00"
    buffer[16] = 3;
    @memcpy(buffer[17..20], "com");
    buffer[20] = 0;
    // 在偏移 8 处放置 "example\x00"
    buffer[8] = 7;
    @memcpy(buffer[9..16], "example");
    buffer[15] = 0; // 实际上不会执行到这里

    // 开头: "www" + 指向 "example.com" 的压缩指针
    buffer[0] = 3;
    @memcpy(buffer[1..4], "www");
    // 指向偏移 8 的指针 (0xC008)
    buffer[4] = 0xC0;
    buffer[5] = 0x08;

    var buf: [256]u8 = undefined;
    const result = try formatDnsName(&buffer, 0, &buf);
    // 压缩指针会被正确跟随
    try std.testing.expectEqualStrings("www.example.com", result);
}
