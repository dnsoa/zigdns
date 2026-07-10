const std = @import("std");
const mem = std.mem;

// RFC 1035 2.3.4: 单标签 ≤63 字节，完整域名 ≤255 字节。
const MAX_LABEL = 63;
const MAX_NAME = 255;
// 单个域名跟随压缩指针的次数上限。合法域名远用不到这么多，纯粹用于防止
// 指针环导致死循环（纯指针跳转不增长 total，故必须独立限次）。
const MAX_POINTER_JUMPS = 128;

/// 域名遍历游标：所有「跟随压缩指针」的读取逻辑的唯一实现。
/// 逐标签推进，跟随 0xC0 压缩指针，统一强制 RFC 上限（label≤63 / name≤255）、
/// 边界检查与指针跳转限次（防环）。零拷贝——返回指向原缓冲区的标签切片。
///
/// 语义：一个游标实例遍历「一个」完整域名——`total`（累计长度，用于 255 上限）
/// 与 `jumps`（指针跳转计数，用于防环）跨多次 `next()` 累积。
pub const NameCursor = struct {
    buffer: []const u8,
    pos: usize,
    total: usize = 0,
    jumps: usize = 0,

    pub fn init(buffer: []const u8, offset: usize) NameCursor {
        return .{ .buffer = buffer, .pos = offset };
    }

    /// 推进到下一个标签，返回其字节切片；遇结束符返回 null。
    /// 跟随压缩指针；对非法/越界/超长/成环输入返回相应错误（绝不 panic）。
    pub fn next(self: *NameCursor) !?[]const u8 {
        while (true) {
            if (self.pos >= self.buffer.len) return error.PacketTooShort;

            const len = self.buffer[self.pos];
            if (len == 0) {
                self.pos += 1;
                return null; // 结束符
            }

            // 压缩指针 (0xC0)：跟随目标，限次防环。
            if (len & 0xC0 == 0xC0) {
                if (self.pos + 1 >= self.buffer.len) return error.PacketTooShort;
                const offset = (@as(usize, len & 0x3F) << 8) | self.buffer[self.pos + 1];
                if (offset >= self.buffer.len) return error.InvalidOffset;
                if (self.jumps >= MAX_POINTER_JUMPS) return error.MalformedName;
                self.jumps += 1;
                self.pos = offset;
                continue;
            }

            if (len > MAX_LABEL) return error.LabelTooLong;
            const start = self.pos + 1;
            if (start + len > self.buffer.len) return error.PacketTooShort;

            self.total += 1 + len;
            if (self.total > MAX_NAME) return error.NameTooLong;

            self.pos = start + len;
            return self.buffer[start .. start + len];
        }
    }
};

/// 将点分域名切成标签数组（根 "." 或 "" -> 0 个标签）。返回标签数。
/// out 长度上限即为可容纳的标签数；超出则截断到上限（域名 ≤255 -> ≤127 标签）。
fn splitLabels(name: []const u8, out: [][]const u8) usize {
    var n: usize = 0;
    var it = mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue; // 跳过根/尾点产生的空标签
        if (n >= out.len) break;
        out[n] = label;
        n += 1;
    }
    return n;
}

fn compareLabelCI(x: []const u8, y: []const u8) std.math.Order {
    const n = @min(x.len, y.len);
    var k: usize = 0;
    while (k < n) : (k += 1) {
        const cx = std.ascii.toLower(x[k]);
        const cy = std.ascii.toLower(y[k]);
        if (cx != cy) return std.math.order(cx, cy);
    }
    return std.math.order(x.len, y.len);
}

/// DNSSEC canonical 名序（RFC 4034 §6.1）：从最右（TLD）标签起逐个比较，
/// 每个标签按 US-ASCII 大小写折叠后的八位组序比较；共有后缀相同时标签更少者在前。
/// 输入为点分域名（大小写不敏感），根用 "." 或 ""。
pub fn canonicalCompare(a: []const u8, b: []const u8) std.math.Order {
    var la: [128][]const u8 = undefined;
    var lb: [128][]const u8 = undefined;
    const na = splitLabels(a, &la);
    const nb = splitLabels(b, &lb);

    var i: usize = 0;
    while (i < na and i < nb) : (i += 1) {
        const ord = compareLabelCI(la[na - 1 - i], lb[nb - 1 - i]);
        if (ord != .eq) return ord;
    }
    return std.math.order(na, nb); // 共有后缀相同 -> 标签更少者在前
}

/// 零拷贝域名解析器
/// 不分配内存，仅返回指向原始数据包的切片迭代器。
/// 内部持有一个贯穿整次遍历的 `NameCursor`，使 jumps/total 跨 next() 累积——
/// 这是防指针环与 255 上限的前提（每次新建游标会重置计数，导致死循环 DoS）。
pub const NameIterator = struct {
    buffer: []const u8,
    pos: usize,
    cursor: ?NameCursor = null,

    pub fn next(self: *NameIterator) !?[]const u8 {
        if (self.cursor == null) self.cursor = NameCursor.init(self.buffer, self.pos);
        const label = try self.cursor.?.next();
        self.pos = self.cursor.?.pos;
        return label;
    }
};

test "canonicalCompare orders names per RFC 4034 6.1" {
    const O = std.math.Order;
    // 后缀名（标签更少）排在前：example.com < a.example.com
    try std.testing.expectEqual(O.lt, canonicalCompare("example.com", "a.example.com"));
    try std.testing.expectEqual(O.gt, canonicalCompare("a.example.com", "example.com"));
    // 同层按标签比较：a.example.com < b.example.com
    try std.testing.expectEqual(O.lt, canonicalCompare("a.example.com", "b.example.com"));
    // 大小写不敏感
    try std.testing.expectEqual(O.eq, canonicalCompare("A.Example.COM", "a.example.com"));
    // 从最右标签开始比较占主导：z.a.com < a.z.com（com==com，再比 a<z）
    try std.testing.expectEqual(O.lt, canonicalCompare("z.a.com", "a.z.com"));
    // 根最小
    try std.testing.expectEqual(O.lt, canonicalCompare(".", "com"));
}

test "NameIterator terminates on pointer-cycle with intervening label" {
    // {label 'a', pointer->0}: 每次 next() 必须共享同一游标状态（jumps/total 累积），
    // 否则指针环无法被检测，形成死循环 DoS。
    const buf = [_]u8{ 0x01, 'a', 0xC0, 0x00 };
    var it = NameIterator{ .buffer = &buf, .pos = 0 };
    var count: usize = 0;
    while (true) {
        const label = it.next() catch break; // 必须最终报错（MalformedName）而非死循环
        if (label == null) break;
        count += 1;
        try std.testing.expect(count < 500); // 若到 500 说明死循环
    }
}

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
    var cur = NameCursor.init(buffer, pos);
    var write_pos: usize = 0;
    var first_label = true;

    while (try cur.next()) |label| {
        // 添加点分隔符（第一个标签前不加）
        if (!first_label) {
            if (write_pos >= out_buf.len) return error.BufferTooSmall;
            out_buf[write_pos] = '.';
            write_pos += 1;
        }
        first_label = false;

        if (write_pos + label.len > out_buf.len) return error.BufferTooSmall;
        @memcpy(out_buf[write_pos .. write_pos + label.len], label);
        write_pos += label.len;
    }

    // 根域名（无标签）返回 "."
    if (write_pos == 0) {
        if (out_buf.len == 0) return error.BufferTooSmall;
        out_buf[0] = '.';
        return out_buf[0..1];
    }
    return out_buf[0..write_pos];
}

/// 自包含的域名引用：{完整报文缓冲区, 域名起始偏移}。
/// 携带完整报文，因此可独立跟随压缩指针解析，无需指针算术或调用方隐式不变量。
/// RData 中的域名字段即为此类型。
pub const Name = struct {
    /// 完整 DNS 报文缓冲区（压缩指针可指向其中任意更早位置）
    buffer: []const u8,
    /// 域名在报文中的起始偏移
    offset: usize,

    /// 解析为点分格式写入 out_buf（跟随压缩指针，带循环检测）。
    /// 返回指向 out_buf 的切片。
    pub fn str(self: Name, out_buf: []u8) ![]const u8 {
        return formatDnsName(self.buffer, self.offset, out_buf);
    }
};

test "Name.str resolves uncompressed name" {
    const domain = "\x03www\x07example\x03com\x00";
    const name = Name{ .buffer = domain, .offset = 0 };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com", try name.str(&buf));
}

test "Name.str follows compression pointer" {
    var msg: [64]u8 = undefined;
    @memset(&msg, 0);
    // "example.com\0" 位于偏移 4
    msg[4] = 7;
    @memcpy(msg[5..12], "example");
    msg[12] = 3;
    @memcpy(msg[13..16], "com");
    msg[16] = 0;
    // 偏移 20: "www" + 指向偏移 4 的压缩指针
    msg[20] = 3;
    @memcpy(msg[21..24], "www");
    msg[24] = 0xC0;
    msg[25] = 0x04;

    const name = Name{ .buffer = &msg, .offset = 20 };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com", try name.str(&buf));
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
    buffer[16] = 3;
    @memcpy(buffer[17..20], "com");
    buffer[20] = 0;

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

test "NameIterator detects invalid pointer offset" {
    const buffer = [_]u8{ 0xC0, 0x10 };
    var iter = NameIterator{ .buffer = &buffer, .pos = 0 };

    try std.testing.expectError(error.InvalidOffset, iter.next());
}

test "formatDnsName rejects name exceeding 255 bytes" {
    // 5 个 63 字节标签 = 320 字节 name，远超 RFC 1035 的 255 上限。
    // out_buf 给足 512，确保「不是因缓冲区太小而失败，而是因超长而失败」。
    var buf: [512]u8 = undefined;
    @memset(&buf, 0);
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        buf[pos] = 63;
        @memset(buf[pos + 1 ..][0..63], 'a');
        pos += 64;
    }
    buf[pos] = 0;

    var out: [512]u8 = undefined;
    try std.testing.expectError(error.NameTooLong, formatDnsName(&buf, 0, &out));
}

test "NameCursor terminates on pointer loop" {
    // 两个互指的压缩指针形成环：offset0 -> 2, offset2 -> 0。
    // 跳转限次必须让它报错而非死循环。
    const buf = [_]u8{ 0xC0, 0x02, 0xC0, 0x00 };
    var out: [256]u8 = undefined;
    try std.testing.expectError(error.MalformedName, formatDnsName(&buf, 0, &out));
}
