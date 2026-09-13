const std = @import("std");
const mem = std.mem;

// RFC 1035 2.3.4: 单标签 ≤63 字节，完整域名 ≤255 字节。
const MAX_LABEL = 63;
const MAX_NAME = 255;
// 单个域名跟随压缩指针的次数上限。合法域名远用不到这么多，纯粹用于防止
// 指针环导致死循环（纯指针跳转不增长 total，故必须独立限次）。
const MAX_POINTER_JUMPS = 128;

/// 完整 DNS 报文中压缩指针目标的最小合法偏移：域名不可能起始于 12 字节 header 内，
/// 指向 header 的指针是畸形输入。裸缓冲区（不是整个报文）用 0 表示不约束。
pub const MESSAGE_POINTER_FLOOR = 12;

/// 域名遍历游标：所有「读出标签」的压缩指针逻辑的唯一实现。
/// 逐标签推进，跟随 0xC0 压缩指针，统一强制 RFC 上限（label≤63 / name≤255 含根）、
/// 边界检查与指针跳转限次（防环）。零拷贝——返回指向原缓冲区的标签切片。
/// 只需跳过名字（不要标签）时用同规则但不返回切片的 `skipName`。
///
/// 语义：一个游标实例遍历「一个」完整域名——`total`（累计长度，用于 255 上限）
/// 与 `jumps`（指针跳转计数，用于防环）跨多次 `next()` 累积。
pub const NameCursor = struct {
    buffer: []const u8,
    pos: usize,
    total: usize = 0,
    jumps: usize = 0,
    /// 压缩指针目标的最小合法偏移，见 `MESSAGE_POINTER_FLOOR`。
    pointer_floor: usize = 0,

    /// 裸缓冲区：不约束指针目标（缓冲区不是一整个 DNS 报文时用）。
    pub fn init(buffer: []const u8, offset: usize) NameCursor {
        return .{ .buffer = buffer, .pos = offset };
    }

    /// 完整 DNS 报文：指针不得指向 12 字节 header。
    pub fn initInMessage(msg: []const u8, offset: usize) NameCursor {
        return .{ .buffer = msg, .pos = offset, .pointer_floor = MESSAGE_POINTER_FLOOR };
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
                if (offset < self.pointer_floor or offset >= self.buffer.len) return error.InvalidOffset;
                if (self.jumps >= MAX_POINTER_JUMPS) return error.MalformedName;
                self.jumps += 1;
                self.pos = offset;
                continue;
            }

            if (len > MAX_LABEL) return error.LabelTooLong;
            const start = self.pos + 1;
            if (start + len > self.buffer.len) return error.PacketTooShort;

            self.total += 1 + len;
            // RFC 1035 §2.3.4 的 255 上限「含根结束符」：已累计的标签字节再加 1 字节
            // 根终止符即为线格式总长，故边界是 total+1（否则 256 字节的名字会被放行，
            // 而 Builder.validateName 以同一规则拒绝，形成解析/构造不一致）。
            if (self.total + 1 > MAX_NAME) return error.NameTooLong;

            self.pos = start + len;
            return self.buffer[start .. start + len];
        }
    }
};

/// 跳过 `buffer` 中起始于 `start` 的域名，返回其**线格式**结束偏移：
/// 未压缩名为根结束符之后；压缩名为首个压缩指针的 2 字节之后（**不是**指针目标之后）——
/// 也就是下一个字段（type/class 等）的起点。
///
/// 全程按 `NameCursor` 的规则校验展开结果：标签 ≤63、整名 ≤255（含根）、
/// 指针越界与成环。跳过名字的快路径（`MessageParser.skipName` / RDATA 内推进）
/// 必须走这里，否则「只跳过不展开」的服务端会放行 NameCursor 本会拒绝的名字。
///
/// `pointer_floor`：压缩指针目标的最小合法偏移，完整报文传 `MESSAGE_POINTER_FLOOR`，
/// 裸缓冲区传 0；与 `NameCursor.pointer_floor` 同义。
///
/// 这是 `NameCursor.next` 的同规则副本（含 pointer_floor），区别仅在于不返回标签
/// 切片——跳过名字是服务端最热的路径，省掉 `!?[]const u8` 的错误联合+可选切片返回值
/// 是值得的。两者的判定必须保持一致（见 "skipName agrees with NameCursor" 测试，
/// floor=0 与 floor=12 两种语义都覆盖）。
pub fn skipName(buffer: []const u8, start: usize, pointer_floor: usize) !usize {
    var pos = start;
    var total: usize = 1; // 根结束符计入 255（RFC 1035 §2.3.4）
    var jumps: usize = 0;
    var wire_end: ?usize = null; // 线格式止于首个指针；在此之前即整名末尾
    while (true) {
        if (pos >= buffer.len) return error.PacketTooShort;
        const len = buffer[pos];
        if (len == 0) return wire_end orelse pos + 1;

        if (len & 0xC0 == 0xC0) { // 压缩指针：跟随以校验展开结果
            if (pos + 2 > buffer.len) return error.PacketTooShort;
            const target = (@as(usize, len & 0x3F) << 8) | buffer[pos + 1];
            if (target < pointer_floor or target >= buffer.len) return error.InvalidOffset;
            if (jumps >= MAX_POINTER_JUMPS) return error.MalformedName; // 防指针环
            jumps += 1;
            if (wire_end == null) wire_end = pos + 2;
            pos = target;
            continue;
        }

        if (len > MAX_LABEL) return error.LabelTooLong;
        if (pos + 1 + len > buffer.len) return error.PacketTooShort;
        total += 1 + len;
        if (total > MAX_NAME) return error.NameTooLong;
        pos += 1 + len;
    }
}

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

/// 零拷贝域名解析器：只负责「逐标签遍历一个域名」，不是报文游标。
/// 不分配内存，仅返回指向原始数据包的切片迭代器。
/// 内部持有一个贯穿整次遍历的 `NameCursor`，使 jumps/total 跨 next() 累积——
/// 这是防指针环与 255 上限的前提（每次新建游标会重置计数，导致死循环 DoS）。
///
/// 走整个报文（跳到 type/class、下一条记录）请用 `MessageParser`；
/// 本迭代器只保证 `pos` 停在**线格式**结束处（见下）。
pub const NameIterator = struct {
    buffer: []const u8,
    /// 入参为域名起始偏移；迭代中被更新为目前已知的**线格式**结束偏移。
    /// 跟随压缩指针后，它是首个指针之后 2 字节的位置（而非指针目标之后），
    /// 与 `skipName` 一致，因此可安全用于续读其后的 type/class。
    pos: usize,
    /// 压缩指针目标的最小合法偏移。`buffer` 是完整报文时置为
    /// `MESSAGE_POINTER_FLOOR`，可一并拒绝指向 header 的指针；默认 0（不约束）。
    pointer_floor: usize = 0,
    cursor: ?NameCursor = null,
    /// 线格式已在首个压缩指针处结束，`pos` 不再随游标推进。
    wire_done: bool = false,

    pub fn next(self: *NameIterator) !?[]const u8 {
        if (self.cursor == null) self.cursor = .{
            .buffer = self.buffer,
            .pos = self.pos,
            .pointer_floor = self.pointer_floor,
        };
        const cur = &self.cursor.?;
        const before = cur.pos;
        const jumps_before = cur.jumps;
        const label = try cur.next();
        if (!self.wire_done) {
            if (cur.jumps > jumps_before) {
                // 首次跳转发生在进入本次 next 时的游标位置：该处是 2 字节指针。
                self.pos = before + 2;
                self.wire_done = true;
            } else {
                self.pos = cur.pos;
            }
        }
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

/// 将 DNS 线路格式域名转换为点分隔格式（裸缓冲区语义：不约束压缩指针目标）。
/// buffer: 包含 DNS 数据包的缓冲区
/// pos: 域名起始位置
/// out_buf: 输出缓冲区，必须足够大（最多 253 字节 + 1）
/// 返回: 写入 out_buf 的字符串切片
///
/// buffer 是一整个 DNS 报文时请用 `formatDnsNameInMessage`，它会一并拒绝指向
/// header 的压缩指针。
pub fn formatDnsName(buffer: []const u8, pos: usize, out_buf: []u8) ![]const u8 {
    return formatName(NameCursor.init(buffer, pos), out_buf);
}

/// 同 `formatDnsName`，但按完整报文语义校验（指针不得指向 12 字节 header）。
pub fn formatDnsNameInMessage(msg: []const u8, pos: usize, out_buf: []u8) ![]const u8 {
    return formatName(NameCursor.initInMessage(msg, pos), out_buf);
}

fn formatName(cursor: NameCursor, out_buf: []u8) ![]const u8 {
    var cur = cursor;
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
    /// `buffer` 按定义是完整报文，故指向 header 的压缩指针会被拒绝。
    pub fn str(self: Name, out_buf: []u8) ![]const u8 {
        return formatDnsNameInMessage(self.buffer, self.offset, out_buf);
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
    // "example.com\0" 位于偏移 12（header 之后——真实报文里名字不会更靠前）
    msg[12] = 7;
    @memcpy(msg[13..20], "example");
    msg[20] = 3;
    @memcpy(msg[21..24], "com");
    msg[24] = 0;
    // 偏移 28: "www" + 指向偏移 12 的压缩指针
    msg[28] = 3;
    @memcpy(msg[29..32], "www");
    msg[32] = 0xC0;
    msg[33] = 12;

    const name = Name{ .buffer = &msg, .offset = 28 };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com", try name.str(&buf));
}

test "Name.str rejects a pointer into the header" {
    // Name.buffer 按定义是完整报文，指向 header 的指针是畸形 RDATA，
    // 不得因为「只是解析 RDATA 内的名字」就绕过 owner name 那条路径的判定。
    var msg: [32]u8 = undefined;
    @memset(&msg, 0);
    msg[12] = 0xC0;
    msg[13] = 0x02;

    const name = Name{ .buffer = &msg, .offset = 12 };
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidOffset, name.str(&buf));
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

test "NameIterator.pos is the wire end after a compression pointer" {
    // "example" + 指向偏移 12 的指针；线格式在指针后结束（偏移 10），
    // 而非指针目标 "com" 之后（偏移 17）。调用方按 pos 续读才能拿到正确字节。
    var buffer: [20]u8 = undefined;
    @memset(&buffer, 0);
    buffer[12] = 3;
    @memcpy(buffer[13..16], "com");
    buffer[16] = 0;
    buffer[0] = 7;
    @memcpy(buffer[1..8], "example");
    buffer[8] = 0xC0;
    buffer[9] = 0x0C;

    var iter = NameIterator{ .buffer = &buffer, .pos = 0 };
    try std.testing.expectEqualStrings("example", (try iter.next()).?);
    try std.testing.expectEqualStrings("com", (try iter.next()).?);
    try std.testing.expect((try iter.next()) == null);
    try std.testing.expectEqual(@as(usize, 10), iter.pos);
    // 与 skipName 给出的线格式结束点一致。
    try std.testing.expectEqual(@as(usize, 10), try skipName(&buffer, 0, 0));
}

test "NameIterator.pos ends after terminator for uncompressed name" {
    const domain = "\x07example\x03com\x00";
    var iter = NameIterator{ .buffer = domain, .pos = 0 };
    while (try iter.next()) |_| {}
    try std.testing.expectEqual(@as(usize, 13), iter.pos);
}

test "skipName enforces 255 including the root octet (RFC 1035 2.3.4)" {
    // 3×63 + 1×61 标签：线格式 = 64*3 + 62 + 1 = 255 -> 合法。
    // 同构造改成 62 字节末标签：= 256 -> NameTooLong。
    const S = struct {
        fn build(buf: []u8, last: u8) []const u8 {
            var pos: usize = 0;
            for (0..3) |_| {
                buf[pos] = 63;
                @memset(buf[pos + 1 ..][0..63], 'a');
                pos += 64;
            }
            buf[pos] = last;
            @memset(buf[pos + 1 ..][0..last], 'b');
            pos += 1 + last;
            buf[pos] = 0;
            return buf[0 .. pos + 1];
        }
    };
    var buf: [512]u8 = undefined;

    const ok = S.build(&buf, 61);
    try std.testing.expectEqual(@as(usize, 255), ok.len);
    try std.testing.expectEqual(@as(usize, 255), try skipName(ok, 0, 0));

    var buf2: [512]u8 = undefined;
    const too_long = S.build(&buf2, 62);
    try std.testing.expectEqual(@as(usize, 256), too_long.len);
    try std.testing.expectError(error.NameTooLong, skipName(too_long, 0, 0));
}

test "skipName agrees with NameCursor" {
    // skipName 是 NameCursor.next 的无切片副本；两者对「接受/拒绝」的判定必须一致，
    // 否则「只跳过」与「展开」两条路径又会重新分叉（issue #2 的根因）。
    // floor=0（裸缓冲区）与 floor=12（完整报文）两种语义都要对齐——parser 用的是后者。
    const cases = [_][]const u8{
        "\x00", // 根
        "\x07example\x03com\x00", // 普通名
        "\x03www\xC0\x01", // 指针（目标在缓冲区内，但 <12）
        "\x40aaaa\x00", // 标签 >63
        "\x03www", // 缺结束符
        "\xC0", // 悬挂指针
        "\xC0\x00", // 自指成环
        "\xC0\x02\xC0\x00", // 互指成环
        "\x01a\xC0\x00", // 带标签的环
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03com\x00\xC0\x0c", // 指针 -> 12（合法）
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03com\x00\xC0\x0b", // 指针 -> 11（<floor）
    };
    for (cases) |buf| {
        for ([_]usize{ 0, MESSAGE_POINTER_FLOOR }) |floor| {
            // 两种语义下名字的起点不同：报文语义从 header 之后开始。
            const start = if (floor == 0) 0 else @min(MESSAGE_POINTER_FLOOR + 4, buf.len -| 1);
            const skip_err: ?anyerror = if (skipName(buf, start, floor)) |_| null else |e| e;
            var cur = NameCursor{ .buffer = buf, .pos = start, .pointer_floor = floor };
            const cursor_err: ?anyerror = while (true) {
                if (cur.next()) |label| {
                    if (label == null) break null;
                } else |e| break e;
            };
            try std.testing.expectEqual(cursor_err, skip_err);
        }
    }
}

test "NameCursor.initInMessage rejects pointers into the header" {
    // formatNameAt / nameEqualsAt / Name.str 都走 Cursor；它们必须和 skipName
    // 一样拒绝指向 header 的指针，否则同一个报文在两条路径上判定不同。
    var msg: [32]u8 = undefined;
    @memset(&msg, 0);
    msg[12] = 0xC0;
    msg[13] = 0x02; // 指向偏移 2（header 内）

    var cur = NameCursor.initInMessage(&msg, 12);
    try std.testing.expectError(error.InvalidOffset, cur.next());
    try std.testing.expectEqual(@as(usize, MESSAGE_POINTER_FLOOR), cur.pointer_floor);

    var out: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidOffset, formatDnsNameInMessage(&msg, 12, &out));
    // 裸缓冲区语义下同一输入只按普通名字校验（此处目标是 0 字节 -> 根）。
    try std.testing.expectEqualStrings(".", try formatDnsName(&msg, 12, &out));
}

test "skipName rejects pointer below the floor" {
    // 报文上下文中，域名不可能起始于 12 字节 header 内；指向 header 的指针是畸形输入。
    var msg: [32]u8 = undefined;
    @memset(&msg, 0);
    msg[12] = 0xC0;
    msg[13] = 0x02; // 指向偏移 2（header 内）
    try std.testing.expectError(error.InvalidOffset, skipName(&msg, 12, 12));
    // 裸缓冲区语义（floor=0）下同一输入仅按普通名字校验。
    _ = try skipName(&msg, 12, 0);
}

test "skipName validates the expansion behind a pointer" {
    // 指针目标处是超长标签：只跳过不展开的实现会放行，skipName 必须报错。
    var msg: [64]u8 = undefined;
    @memset(&msg, 0);
    msg[12] = 0xC0;
    msg[13] = 20;
    msg[20] = 64; // 非法标签长度
    try std.testing.expectError(error.LabelTooLong, skipName(&msg, 12, 12));

    // 指针成环同样必须在跳过阶段被拒。
    var loop: [32]u8 = undefined;
    @memset(&loop, 0);
    loop[12] = 0xC0;
    loop[13] = 14;
    loop[14] = 0xC0;
    loop[15] = 12;
    try std.testing.expectError(error.MalformedName, skipName(&loop, 12, 12));
}

test "NameCursor terminates on pointer loop" {
    // 两个互指的压缩指针形成环：offset0 -> 2, offset2 -> 0。
    // 跳转限次必须让它报错而非死循环。
    const buf = [_]u8{ 0xC0, 0x02, 0xC0, 0x00 };
    var out: [256]u8 = undefined;
    try std.testing.expectError(error.MalformedName, formatDnsName(&buf, 0, &out));
}
