const std = @import("std");
const mem = std.mem;
const ECSData = @import("types.zig").ECSData;
const CookieData = @import("types.zig").CookieData;
const Type = @import("types.zig").Type;
const parseECS = @import("rdata.zig").parseECS;
const parseCookie = @import("rdata.zig").parseCookie;
const parseOptOptions = @import("rdata.zig").parseOptOptions;
const RData = @import("rdata.zig").RData;
const NameCursor = @import("name.zig").NameCursor;
const skipNameAt = @import("name.zig").skipName;
const formatDnsNameInMessage = @import("name.zig").formatDnsNameInMessage;
const POINTER_FLOOR = @import("name.zig").MESSAGE_POINTER_FLOOR;
const Error = @import("errors.zig").Error;

pub const Question = struct {
    name_pos: usize, // Where the owner name starts in the buffer (for zero-copy echo / name resolution)
    qname_end_pos: usize, // Where the name ends in the buffer
    qtype: Type,
    qclass: u16,
};

pub const ResourceRecord = struct {
    name_pos: usize, // Where the owner name starts in the buffer (for name resolution / OPT root check)
    name_end_pos: usize,
    rtype: Type,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: []const u8, // Slice pointing into the original packet
    rdata_offset: usize, // Absolute offset of rdata within the packet (for name resolution)

    /// RFC 2181 §8: 收到的 TTL 是 31 位无符号；最高位置位时应视为 0。
    /// 保留原始 `ttl` 不变，缓存/回显请使用此规范化值。
    ///
    /// OPT（类型 41）除外：RFC 6891 §6.1.3 把 TTL 字段挪作扩展 RCODE(8) + 版本(8) +
    /// flags(16)，扩展 RCODE ≥128 时最高位本就置位。对其套用 RFC 2181 会把 DO/版本/
    /// 扩展 RCODE 一起清零，故原样返回；OPT 本来也没有可缓存的 TTL 语义。
    pub fn effectiveTtl(self: ResourceRecord) u32 {
        if (self.rtype == .OPT) return self.ttl;
        return if (self.ttl > 0x7FFFFFFF) 0 else self.ttl;
    }
};

pub fn CountedIterator(comptime T: type) type {
    return struct {
        parser: *MessageParser,
        remaining: u16,
        nextFn: *const fn (*MessageParser) Error!?T,

        pub fn next(self: *@This()) Error!?T {
            if (self.remaining == 0) return null;

            const item = try self.nextFn(self.parser);
            if (item == null) return error.PacketTooShort;

            self.remaining -= 1;
            return item;
        }
    };
}

pub const MessageParser = struct {
    buffer: []const u8,
    pos: usize,

    pub const QuestionIterator = CountedIterator(Question);
    pub const RRIterator = CountedIterator(ResourceRecord);

    pub fn init(raw: []const u8) MessageParser {
        return .{ .buffer = raw, .pos = 12 }; // Start after Header
    }

    /// Skips a DNS name (including compression pointers) without copying it.
    /// Crucial for jumping to the Type/Class fields.
    ///
    /// 委托给 `name.skipName`：压缩指针会被**跟随并完整校验**（RFC 1035 §2.3.4 的
    /// 标签 ≤63 / 整名 ≤255 含根、目标越界、指向 header、指针成环），而 `pos` 仍落在
    /// 线格式结束处（指针后 2 字节）。只 skip 不展开的快路径服务端因此与
    /// `formatNameAt` / `nameEqualsAt` 走同一套校验，不会放行畸形名字。
    fn skipName(self: *MessageParser) !void {
        self.pos = try skipNameAt(self.buffer, self.pos, POINTER_FLOOR);
    }

    /// Parses the next Question in the packet
    pub fn nextQuestion(self: *MessageParser) !?Question {
        if (self.pos >= self.buffer.len) return null;

        const name_pos = self.pos;
        try self.skipName();
        const end_name = self.pos;

        if (self.pos + 4 > self.buffer.len) return error.PacketTooShort;

        const qtype = @as(Type, @enumFromInt(mem.readInt(u16, self.buffer[self.pos..][0..2], .big)));
        const qclass = mem.readInt(u16, self.buffer[self.pos + 2 ..][0..2], .big);
        self.pos += 4;

        return Question{
            .name_pos = name_pos,
            .qname_end_pos = end_name,
            .qtype = qtype,
            .qclass = qclass,
        };
    }

    /// Parses the next Resource Record (Answer/Authority/Additional)
    pub fn nextRR(self: *MessageParser) !?ResourceRecord {
        if (self.pos >= self.buffer.len) return null;

        const name_pos = self.pos;
        try self.skipName();
        const end_name = self.pos;

        if (self.pos + 10 > self.buffer.len) return error.PacketTooShort;

        const rtype = @as(Type, @enumFromInt(mem.readInt(u16, self.buffer[self.pos..][0..2], .big)));
        const class = mem.readInt(u16, self.buffer[self.pos + 2 ..][0..2], .big);
        const ttl = mem.readInt(u32, self.buffer[self.pos + 4 ..][0..4], .big);
        const rdlen = mem.readInt(u16, self.buffer[self.pos + 8 ..][0..2], .big);

        // Check rdlength before advancing position
        if (self.pos + 10 + rdlen > self.buffer.len) return error.PacketTooShort;

        self.pos += 10;
        const rdata_offset = self.pos;
        const rdata = self.buffer[self.pos .. self.pos + rdlen];
        self.pos += rdlen;

        return ResourceRecord{
            .name_pos = name_pos,
            .name_end_pos = end_name,
            .rtype = rtype,
            .class = class,
            .ttl = ttl,
            .rdlength = rdlen,
            .rdata = rdata,
            .rdata_offset = rdata_offset,
        };
    }

    pub fn questions(self: *MessageParser, count: u16) QuestionIterator {
        return .{
            .parser = self,
            .remaining = count,
            .nextFn = nextQuestion,
        };
    }

    pub fn resourceRecords(self: *MessageParser, count: u16) RRIterator {
        return .{
            .parser = self,
            .remaining = count,
            .nextFn = nextRR,
        };
    }

    pub fn skipQuestions(self: *MessageParser, count: u16) !void {
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            if ((try self.nextQuestion()) == null) return error.PacketTooShort;
        }
    }

    pub fn skipResourceRecords(self: *MessageParser, count: u16) !void {
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            if ((try self.nextRR()) == null) return error.PacketTooShort;
        }
    }

    /// **快路径**：返回附加区第一个 OPT 记录，遇到即停。
    /// 不检测第二个 OPT，也不校验 owner name 为根——即不做 RFC 6891 §6.1.1 的
    /// FORMERR 判定。只在你已用别的手段确认过报文合法时使用；
    /// 面向不可信输入的严格入口是 `findEdns`。
    pub fn findOptRecord(self: *const MessageParser, count: u16) !?ResourceRecord {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return rr;
        }
        return null;
    }

    /// **快路径**：返回第一个 OPT 中的 ECS（RFC 7871）。
    /// 与 `findOptRecord` 同样跳过 RFC 6891 §6.1.1 检查（多 OPT / 非根 owner）。
    /// 严格校验且同时要 OPT+ECS+Cookie 时用 `findEdns`（单趟扫描）。
    pub fn findECS(self: *const MessageParser, count: u16) !?ECSData {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return parseECS(rr.rdata);
        }
        return null;
    }

    /// **快路径**：返回第一个 OPT 中的 DNS Cookie（RFC 7873）。
    /// 与 `findOptRecord` 同样跳过 RFC 6891 §6.1.1 检查（多 OPT / 非根 owner）。
    /// 严格校验用 `findEdns`。
    pub fn findCookie(self: *const MessageParser, count: u16) !?CookieData {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return parseCookie(rr.rdata);
        }
        return null;
    }

    /// `findEdns` 的结果：OPT 记录本身 + 其 RDATA 中已识别的选项。
    /// EDNS 头部字段（UDP 载荷大小 / 版本 / 扩展 RCODE / DO）在 `opt` 的
    /// CLASS 与 TTL 里，用 `dns.Edns.fromOpt(result.opt)` 可一次解出，
    /// 与 Builder 侧的 `dns.Edns` 是同一个类型。
    pub const Edns = struct { opt: ResourceRecord, ecs: ?ECSData, cookie: ?CookieData };

    /// **严格入口**（RFC 6891 §6.1.1）：单趟扫描附加区，一次返回 OPT 记录及其
    /// RDATA 中的 ECS 与 Cookie，避免 findOptRecord + findECS + findCookie 的三次扫描。
    /// - 多于一个 OPT -> error.MultipleOptRecords（必须回 FORMERR）
    /// - OPT 的 owner name 非根 -> error.MalformedName
    /// - OPT RDATA 的 TLV 未恰好平铺 -> error.InvalidRData
    pub fn findEdns(self: *const MessageParser, count: u16) !?Edns {
        var scan = self.*;
        var remaining = count;
        var found: ?Edns = null;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) {
                if (found != null) return error.MultipleOptRecords;
                // RFC 6891 §6.1.1: OPT 的 owner name 必须为根（单个 0 字节）。
                if (rr.name_pos >= self.buffer.len or self.buffer[rr.name_pos] != 0) return error.MalformedName;
                // 选项只遍历一趟，ECS 与 Cookie 同时取出。
                const options = try parseOptOptions(rr.rdata);
                found = .{ .opt = rr, .ecs = options.ecs, .cookie = options.cookie };
            }
        }
        return found;
    }

    pub fn nameEqualsAt(self: *const MessageParser, offset: usize, expected: []const u8) !bool {
        if (offset >= self.buffer.len) return error.InvalidOffset;

        // 根域名以 "." 或 "" 表示（与 formatDnsName 输出 "." 一致）。
        // 非根名字剥掉单个尾点，与 Builder.canonicalizeName 及区域文件 FQDN 约定一致；
        // 否则带尾点的 "example.com." 会对实际为 example.com 的名字误报不匹配。
        const want: []const u8 = blk: {
            if (mem.eql(u8, expected, ".")) break :blk expected[0..0];
            if (expected.len > 1 and expected[expected.len - 1] == '.') break :blk expected[0 .. expected.len - 1];
            break :blk expected;
        };

        var cur = NameCursor.initInMessage(self.buffer, offset);
        var expected_pos: usize = 0;
        var first_label = true;

        while (try cur.next()) |label| {
            if (!first_label) {
                if (expected_pos >= want.len or want[expected_pos] != '.') return false;
                expected_pos += 1;
            }
            first_label = false;

            if (expected_pos + label.len > want.len) return false;
            // RFC 1035 §2.3.3 / RFC 4343: 域名比较对 ASCII 大小写不敏感。
            if (!std.ascii.eqlIgnoreCase(label, want[expected_pos .. expected_pos + label.len])) return false;
            expected_pos += label.len;
        }

        return expected_pos == want.len;
    }

    /// Format a DNS name at a specific offset in the packet.
    /// Follows compression pointers and returns dotted format.
    /// 委托给 name.zig 的 `formatDnsNameInMessage`（基于统一的 `NameCursor`，
    /// 按完整报文语义拒绝指向 header 的压缩指针），保留入口 InvalidOffset 语义。
    pub fn formatNameAt(self: *const MessageParser, offset: usize, out_buf: []u8) ![]const u8 {
        if (offset >= self.buffer.len) return error.InvalidOffset;
        return formatDnsNameInMessage(self.buffer, offset, out_buf);
    }

    /// Parse a resource record's RDATA. Domain names inside RDATA are returned as
    /// self-contained `Name` values bound to this parser's buffer, so they resolve
    /// compression pointers without any pointer arithmetic or aliasing assumptions.
    ///
    /// OPT（类型 41）不是普通 RR：其 RDATA 是 EDNS 选项 TLV 序列，CLASS/TTL 也另作他用。
    /// 对 OPT 调用本方法返回 `error.UseEdns`——泛化的「遍历附加区每条 RR」循环据此
    /// 明确分流到 `findEdns` / `dns.Edns.fromOpt`，而不是撞上含混的 InvalidRData。
    pub fn parseRData(self: *const MessageParser, rr: ResourceRecord) !RData {
        return RData.parse(rr.rtype, self.buffer, rr.rdata_offset, rr.rdlength);
    }
};

test "Question and RR expose owner name start offset" {
    var packet: [128]u8 = undefined;
    @memset(packet[0..12], 0);

    // Question "example.com" 起始于偏移 12
    var pos: usize = 12;
    const qname = "\x07example\x03com\x00";
    @memcpy(packet[pos..][0..qname.len], qname);
    pos += qname.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big);
    pos += 4;

    // RR owner name 起始于此偏移
    const rr_name_pos = pos;
    const rr_name = "\x03www\x07example\x03com\x00";
    @memcpy(packet[pos..][0..rr_name.len], rr_name);
    pos += rr_name.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 60, .big);
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 4, .big);
    pos += 10;
    @memcpy(packet[pos..][0..4], &[_]u8{ 127, 0, 0, 1 });
    pos += 4;

    var parser = MessageParser.init(packet[0..pos]);
    const q = (try parser.nextQuestion()).?;
    try std.testing.expectEqual(@as(usize, 12), q.name_pos);
    // 起点可直接喂给 name 解析/比较 API
    try std.testing.expect(try parser.nameEqualsAt(q.name_pos, "example.com"));

    const rr = (try parser.nextRR()).?;
    try std.testing.expectEqual(rr_name_pos, rr.name_pos);
    try std.testing.expect(try parser.nameEqualsAt(rr.name_pos, "www.example.com"));
}

test "MessageParser parse question" {
    // 构造 DNS 查询报文
    // Header(12字节) + Question(name + type + class)
    var packet: [100]u8 = undefined;

    // Header: id=1, flags=0x0100 (RD=1), qdcount=1
    mem.writeInt(u16, packet[0..2], 1, .big);
    mem.writeInt(u16, packet[2..4], 0x0100, .big);
    mem.writeInt(u16, packet[4..6], 1, .big); // qdcount
    @memset(packet[6..12], 0);

    // Question: "example.com" + TYPE=A + CLASS=IN
    var pos: usize = 12;
    const name = "\x07example\x03com\x00";
    @memcpy(packet[pos..][0..name.len], name);
    pos += name.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big); // A
    pos += 2;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big); // IN
    pos += 2;

    var parser = MessageParser.init(packet[0..pos]);
    const question = (try parser.nextQuestion()).?;

    try std.testing.expectEqual(@as(usize, 25), question.qname_end_pos); // 12 + 13 (name length)
    try std.testing.expectEqual(Type.A, question.qtype);
    try std.testing.expectEqual(@as(u16, 1), question.qclass);
}

test "MessageParser parse resource record" {
    var packet: [100]u8 = undefined;

    // Header
    @memset(packet[0..12], 0);

    // ResourceRecord: "com" + A + IN + ttl=3600 + rdlength=4 + rdata
    var pos: usize = 12;
    const name = "\x03com\x00";
    @memcpy(packet[pos..][0..name.len], name);
    pos += name.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big); // A
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big); // IN
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 3600, .big); // TTL
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 4, .big); // RDLENGTH
    pos += 10;
    // RDATA: 127.0.0.1
    packet[pos] = 127;
    packet[pos + 1] = 0;
    packet[pos + 2] = 0;
    packet[pos + 3] = 1;
    pos += 4;

    var parser = MessageParser.init(packet[0..pos]);
    const rr = (try parser.nextRR()).?;

    try std.testing.expectEqual(Type.A, rr.rtype);
    try std.testing.expectEqual(@as(u16, 1), rr.class);
    try std.testing.expectEqual(@as(u32, 3600), rr.ttl);
    try std.testing.expectEqual(@as(u16, 4), rr.rdlength);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, rr.rdata);
}

test "MessageParser label too long error" {
    var packet: [200]u8 = undefined;
    @memset(packet[0..12], 0);

    // Label 长度 64 (超过 RFC 限制 63)
    var pos: usize = 12;
    packet[pos] = 64; // 标签长度
    @memset(packet[pos + 1 ..][0..64], 'a');
    pos += 65;
    packet[pos] = 0; // 结束符

    var parser = MessageParser.init(packet[0..pos]);
    try std.testing.expectError(error.LabelTooLong, parser.nextQuestion());
}

test "MessageParser name too long error" {
    var packet: [300]u8 = undefined;
    @memset(packet[0..12], 0);

    // 创建超过 255 字节的域名
    var pos: usize = 12;
    var total: usize = 0;
    while (total < 250) : (total += 64) {
        packet[pos] = 63;
        @memset(packet[pos + 1 ..][0..63], 'a');
        pos += 64;
    }
    // 再加一个标签使总长度超过 255
    packet[pos] = 10;
    @memset(packet[pos + 1 ..][0..10], 'b');
    pos += 11;
    packet[pos] = 0;

    var parser = MessageParser.init(packet[0..pos]);
    try std.testing.expectError(error.NameTooLong, parser.nextQuestion());
}

test "MessageParser packet too short" {
    var packet: [20]u8 = undefined;
    @memset(packet[0..12], 0);

    // 不完整的域名（标签长度超出数据包）
    packet[12] = 10; // 声称 10 字节
    @memset(packet[13..20], 'a'); // 只有 7 字节

    var parser = MessageParser.init(&packet);
    try std.testing.expectError(error.PacketTooShort, parser.nextQuestion());
}

test "MessageParser rrdata too long" {
    var packet: [100]u8 = undefined;
    @memset(packet[0..12], 0);

    var pos: usize = 12;
    const name = "\x03com\x00";
    @memcpy(packet[pos..][0..name.len], name);
    pos += name.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big); // A
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big); // IN
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 3600, .big); // TTL
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 100, .big); // RDLENGTH=100 (超过剩余空间)

    var parser = MessageParser.init(packet[0 .. pos + 10]);
    try std.testing.expectError(error.PacketTooShort, parser.nextRR());
}

test "MessageParser nextQuestion returns null at end" {
    var packet: [20]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[12] = 0; // 空域名
    mem.writeInt(u16, packet[13..][0..2], 1, .big); // A
    mem.writeInt(u16, packet[15..][0..2], 1, .big); // IN

    var parser = MessageParser.init(packet[0..17]);
    _ = try parser.nextQuestion();
    try std.testing.expect((try parser.nextQuestion()) == null);
}

test "MessageParser nextRR returns null at end" {
    var packet: [30]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[12] = 0; // 空域名
    mem.writeInt(u16, packet[13..][0..2], 1, .big); // A
    mem.writeInt(u16, packet[15..][0..2], 1, .big); // IN
    mem.writeInt(u32, packet[17..][0..4], 3600, .big); // TTL
    mem.writeInt(u16, packet[21..][0..2], 0, .big); // RDLENGTH=0

    var parser = MessageParser.init(packet[0..23]);
    _ = try parser.nextRR();
    try std.testing.expect((try parser.nextRR()) == null);
}

test "MessageParser with compression pointer" {
    var packet: [100]u8 = undefined;
    @memset(&packet, 0);

    // 在偏移 30 处放置 "com\x00"
    packet[30] = 3;
    @memcpy(packet[31..34], "com");
    packet[34] = 0;

    // 在开头放置 "example" + 指向 "com" 的压缩指针
    var pos: usize = 12;
    packet[pos] = 7;
    @memcpy(packet[pos + 1 ..][0..7], "example");
    pos += 8;
    // 压缩指针: 0xC0 | (30 >> 8), 30 & 0xFF
    packet[pos] = 0xC0 | (30 >> 8);
    packet[pos + 1] = 30 & 0xFF;
    pos += 2;

    mem.writeInt(u16, packet[pos..][0..2], 1, .big); // A
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big); // IN

    // 报文须覆盖指针目标（35）：skipName 会跟随并校验展开结果，
    // 目标落在切片之外即为越界指针。
    var parser = MessageParser.init(packet[0..35]);
    const question = (try parser.nextQuestion()).?;

    try std.testing.expectEqual(Type.A, question.qtype);
    try std.testing.expectEqual(@as(u16, 1), question.qclass);
    // 名字止于指针之后（22），而非指针目标之后。
    try std.testing.expectEqual(@as(usize, 22), question.qname_end_pos);
}

test "MessageParser rejects compression pointer into the header" {
    // 域名不可能起始于 12 字节 header 内；指向 header 的 QNAME 是畸形输入，
    // 必须在 skip 阶段就被拒（快路径服务端只 skip 不展开）。
    var packet: [32]u8 = undefined;
    @memset(&packet, 0);
    packet[12] = 0xC0;
    packet[13] = 0x02; // 指向偏移 2（header 内）
    var parser = MessageParser.init(&packet);
    try std.testing.expectError(error.InvalidOffset, parser.nextQuestion());
}

test "MessageParser skipName validates the name behind a pointer" {
    // 指针目标处是超长标签：只跳过不展开会放行，导致 skipQuestions 后
    // 按类型直接应答的服务端接受 formatNameAt 会拒绝的 QNAME。
    var packet: [64]u8 = undefined;
    @memset(&packet, 0);
    packet[12] = 0xC0;
    packet[13] = 20;
    packet[20] = 64; // 非法标签长度（>63）
    var parser = MessageParser.init(&packet);
    try std.testing.expectError(error.LabelTooLong, parser.nextQuestion());

    // 指针成环同样必须在 skip 阶段被拒，而不是靠下游兜底。
    var loop: [32]u8 = undefined;
    @memset(&loop, 0);
    loop[12] = 0xC0;
    loop[13] = 14;
    loop[14] = 0xC0;
    loop[15] = 12;
    var loop_parser = MessageParser.init(&loop);
    try std.testing.expectError(error.MalformedName, loop_parser.nextQuestion());
}

test "MessageParser enforces 255 including root on parse (RFC 1035 2.3.4)" {
    // 3×63 + 1×61 标签的线格式恰为 255 -> 合法；末标签改成 62 则为 256 -> 拒绝。
    // 与 Builder.validateName 同一边界，保证「能解析的名字一定能重新构造」。
    const S = struct {
        fn build(packet: []u8, last: u8) []const u8 {
            @memset(packet[0..12], 0);
            var pos: usize = 12;
            for (0..3) |_| {
                packet[pos] = 63;
                @memset(packet[pos + 1 ..][0..63], 'a');
                pos += 64;
            }
            packet[pos] = last;
            @memset(packet[pos + 1 ..][0..last], 'b');
            pos += 1 + last;
            packet[pos] = 0;
            pos += 1;
            mem.writeInt(u16, packet[pos..][0..2], 1, .big); // A
            mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big); // IN
            return packet[0 .. pos + 4];
        }
    };

    var ok_buf: [512]u8 = undefined;
    const ok = S.build(&ok_buf, 61);
    var ok_parser = MessageParser.init(ok);
    const q = (try ok_parser.nextQuestion()).?;
    try std.testing.expectEqual(@as(usize, 12 + 255), q.qname_end_pos);

    var bad_buf: [512]u8 = undefined;
    var bad_parser = MessageParser.init(S.build(&bad_buf, 62));
    try std.testing.expectError(error.NameTooLong, bad_parser.nextQuestion());
}

test "ResourceRecord.effectiveTtl keeps OPT TTL intact (RFC 6891 6.1.3)" {
    // OPT 的 TTL 是 扩展RCODE(8)+版本(8)+flags(16)：扩展 RCODE=128 时最高位置位，
    // 套用 RFC 2181 会把 DO/版本/扩展 RCODE 一起清零。
    const ttl: u32 = (@as(u32, 128) << 24) | (@as(u32, 0) << 16) | 0x8000; // DO=1
    const opt = ResourceRecord{
        .name_pos = 12,
        .name_end_pos = 13,
        .rtype = .OPT,
        .class = 1232,
        .ttl = ttl,
        .rdlength = 0,
        .rdata = &[_]u8{},
        .rdata_offset = 0,
    };
    try std.testing.expectEqual(ttl, opt.effectiveTtl());
    try std.testing.expect(opt.effectiveTtl() & 0x8000 != 0); // DO 仍在
    try std.testing.expectEqual(@as(u8, 128), @as(u8, @truncate(opt.effectiveTtl() >> 24)));
}

test "MessageParser counted question iterator" {
    var packet: [64]u8 = undefined;

    mem.writeInt(u16, packet[0..2], 1, .big);
    mem.writeInt(u16, packet[2..4], 0x0100, .big);
    mem.writeInt(u16, packet[4..6], 1, .big);
    @memset(packet[6..12], 0);

    var pos: usize = 12;
    const name = "\x07example\x03com\x00";
    @memcpy(packet[pos..][0..name.len], name);
    pos += name.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;

    var parser = MessageParser.init(packet[0..pos]);
    var questions = parser.questions(1);

    const q = (try questions.next()).?;
    try std.testing.expectEqual(Type.A, q.qtype);
    try std.testing.expect((try questions.next()) == null);
}

test "MessageParser counted iterator detects truncated packet" {
    var parser = MessageParser.init(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 });
    var questions = parser.questions(1);

    try std.testing.expectError(error.PacketTooShort, questions.next());
}

test "MessageParser skipQuestions advances to answer section" {
    var packet: [128]u8 = undefined;
    @memset(packet[0..12], 0);

    mem.writeInt(u16, packet[4..6], 1, .big);
    mem.writeInt(u16, packet[6..8], 1, .big);

    var pos: usize = 12;
    const qname = "\x07example\x03com\x00";
    @memcpy(packet[pos..][0..qname.len], qname);
    pos += qname.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    pos += 2;

    const rr_name = "\x03www\x07example\x03com\x00";
    @memcpy(packet[pos..][0..rr_name.len], rr_name);
    pos += rr_name.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 60, .big);
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 4, .big);
    pos += 10;
    @memcpy(packet[pos..][0..4], &[_]u8{ 127, 0, 0, 1 });
    pos += 4;

    var parser = MessageParser.init(packet[0..pos]);
    try parser.skipQuestions(1);

    const rr = (try parser.nextRR()).?;
    try std.testing.expectEqual(Type.A, rr.rtype);
    try std.testing.expectEqual(@as(u32, 60), rr.ttl);
}

test "MessageParser skipResourceRecords consumes exact count" {
    var packet: [128]u8 = undefined;
    @memset(packet[0..12], 0);

    var pos: usize = 12;
    const rr_name = "\x03com\x00";

    inline for (0..2) |_| {
        @memcpy(packet[pos..][0..rr_name.len], rr_name);
        pos += rr_name.len;
        mem.writeInt(u16, packet[pos..][0..2], 1, .big);
        mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big);
        mem.writeInt(u32, packet[pos + 4 ..][0..4], 1, .big);
        mem.writeInt(u16, packet[pos + 8 ..][0..2], 4, .big);
        pos += 10;
        @memcpy(packet[pos..][0..4], &[_]u8{ 1, 1, 1, 1 });
        pos += 4;
    }

    var parser = MessageParser.init(packet[0..pos]);
    try parser.skipResourceRecords(2);
    try std.testing.expect((try parser.nextRR()) == null);
}

test "MessageParser skipQuestions reports truncated packet" {
    var parser = MessageParser.init(&[_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 });
    try std.testing.expectError(error.PacketTooShort, parser.skipQuestions(1));
}

test "MessageParser findOptRecord scans without consuming parser state" {
    var packet: [128]u8 = undefined;
    @memset(packet[0..12], 0);

    var pos: usize = 12;
    const a_name = "\x03com\x00";
    @memcpy(packet[pos..][0..a_name.len], a_name);
    pos += a_name.len;
    mem.writeInt(u16, packet[pos..][0..2], 1, .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 1, .big);
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 4, .big);
    pos += 10;
    @memcpy(packet[pos..][0..4], &[_]u8{ 127, 0, 0, 1 });
    pos += 4;

    packet[pos] = 0;
    pos += 1;
    mem.writeInt(u16, packet[pos..][0..2], @intFromEnum(Type.OPT), .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1232, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 0, .big);
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 11, .big);
    pos += 10;
    mem.writeInt(u16, packet[pos..][0..2], 8, .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 7, .big);
    mem.writeInt(u16, packet[pos + 4 ..][0..2], 1, .big);
    packet[pos + 6] = 24;
    packet[pos + 7] = 0;
    @memcpy(packet[pos + 8 ..][0..3], &[_]u8{ 192, 0, 2 });
    pos += 11;

    var parser = MessageParser.init(packet[0..pos]);
    const initial_pos = parser.pos;

    const opt = (try parser.findOptRecord(2)).?;

    try std.testing.expectEqual(@as(usize, initial_pos), parser.pos);
    try std.testing.expectEqual(Type.OPT, opt.rtype);
    try std.testing.expectEqual(@as(u16, 1232), opt.class);
}

test "MessageParser findEdns returns OPT and ECS in one scan" {
    var packet: [64]u8 = undefined;
    @memset(packet[0..12], 0);

    var pos: usize = 12;
    packet[pos] = 0;
    pos += 1;
    mem.writeInt(u16, packet[pos..][0..2], @intFromEnum(Type.OPT), .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1232, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 0, .big);
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 11, .big);
    pos += 10;
    mem.writeInt(u16, packet[pos..][0..2], 8, .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 7, .big);
    mem.writeInt(u16, packet[pos + 4 ..][0..2], 1, .big);
    packet[pos + 6] = 24;
    packet[pos + 7] = 0;
    @memcpy(packet[pos + 8 ..][0..3], &[_]u8{ 192, 0, 2 });
    pos += 11;

    const parser = MessageParser.init(packet[0..pos]);
    const edns = (try parser.findEdns(1)).?;

    try std.testing.expectEqual(Type.OPT, edns.opt.rtype);
    try std.testing.expectEqual(@as(u16, 1232), edns.opt.class);
    try std.testing.expectEqual(@as(u16, 1), edns.ecs.?.family);
    try std.testing.expectEqual(@as(u8, 24), edns.ecs.?.source_prefix);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2 }, edns.ecs.?.address);
}

test "MessageParser findEdns returns OPT, ECS and Cookie in one scan" {
    // 单趟扫描即可满足「OPT + ECS + Cookie」的常见服务端需求，
    // 不必再叠加 findCookie 的第二次扫描。
    var packet: [96]u8 = undefined;
    @memset(&packet, 0);

    const rdata = "\x00\x08\x00\x07\x00\x01\x18\x00\xc0\x00\x02" ++ // ECS 192.0.2/24
        "\x00\x0a\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08"; // COOKIE（仅客户端）

    var pos: usize = 12;
    packet[pos] = 0; // 根 owner
    pos += 1;
    mem.writeInt(u16, packet[pos..][0..2], @intFromEnum(Type.OPT), .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1232, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 0x00008000, .big); // DO=1
    mem.writeInt(u16, packet[pos + 8 ..][0..2], @intCast(rdata.len), .big);
    pos += 10;
    @memcpy(packet[pos..][0..rdata.len], rdata);
    pos += rdata.len;

    const parser = MessageParser.init(packet[0..pos]);
    const edns = (try parser.findEdns(1)).?;
    try std.testing.expectEqual(@as(u16, 1232), edns.opt.class);
    try std.testing.expectEqual(@as(u8, 24), edns.ecs.?.source_prefix);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &edns.cookie.?.client);

    // OPT 走通用 RDATA 解析必须给出明确的分流信号。
    try std.testing.expectError(error.UseEdns, parser.parseRData(edns.opt));
}

test "MessageParser findECS extracts ECS from OPT record" {
    var packet: [64]u8 = undefined;
    @memset(packet[0..12], 0);

    var pos: usize = 12;
    packet[pos] = 0;
    pos += 1;
    mem.writeInt(u16, packet[pos..][0..2], @intFromEnum(Type.OPT), .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1232, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 0, .big);
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 11, .big);
    pos += 10;
    mem.writeInt(u16, packet[pos..][0..2], 8, .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 7, .big);
    mem.writeInt(u16, packet[pos + 4 ..][0..2], 1, .big);
    packet[pos + 6] = 24;
    packet[pos + 7] = 0;
    @memcpy(packet[pos + 8 ..][0..3], &[_]u8{ 192, 0, 2 });
    pos += 11;

    const parser = MessageParser.init(packet[0..pos]);
    const ecs = (try parser.findECS(1)).?;

    try std.testing.expectEqual(@as(u16, 1), ecs.family);
    try std.testing.expectEqual(@as(u8, 24), ecs.source_prefix);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2 }, ecs.address);
}

test "MessageParser findEdns rejects OPT with non-root owner name (RFC 6891)" {
    // OPT 记录的 owner name 必须为根（单个 0 字节）；非根须 FORMERR。
    var packet: [64]u8 = undefined;
    @memset(packet[0..12], 0);
    mem.writeInt(u16, packet[10..12], 1, .big); // arcount=1

    var pos: usize = 12;
    // 非根 owner: label 'a' + 结束符
    packet[pos] = 1;
    packet[pos + 1] = 'a';
    packet[pos + 2] = 0;
    pos += 3;
    mem.writeInt(u16, packet[pos..][0..2], @intFromEnum(Type.OPT), .big);
    mem.writeInt(u16, packet[pos + 2 ..][0..2], 1232, .big);
    mem.writeInt(u32, packet[pos + 4 ..][0..4], 0, .big);
    mem.writeInt(u16, packet[pos + 8 ..][0..2], 0, .big);
    pos += 10;

    var parser = MessageParser.init(packet[0..pos]);
    try std.testing.expectError(error.MalformedName, parser.findEdns(1));
}

test "MessageParser nameEqualsAt matches compressed name" {
    var packet: [64]u8 = undefined;
    @memset(packet[0..12], 0);

    packet[12] = 0xC0;
    packet[13] = 0x20;
    packet[32] = 7;
    @memcpy(packet[33..40], "example");
    packet[40] = 3;
    @memcpy(packet[41..44], "com");
    packet[44] = 0;

    const parser = MessageParser.init(packet[0..45]);
    try std.testing.expect(try parser.nameEqualsAt(12, "example.com"));
    try std.testing.expect(!(try parser.nameEqualsAt(12, "example.net")));
}

test "MessageParser nameEqualsAt matches root against both \".\" and \"\"" {
    // 根域名（单个 0 字节）应同时匹配 "." 与 ""，与 formatDnsName 输出 "." 保持一致。
    var packet: [16]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[12] = 0; // 根

    const parser = MessageParser.init(packet[0..13]);
    try std.testing.expect(try parser.nameEqualsAt(12, "."));
    try std.testing.expect(try parser.nameEqualsAt(12, ""));
    try std.testing.expect(!(try parser.nameEqualsAt(12, "example.com")));
}

test "ResourceRecord.effectiveTtl clamps high-bit TTL to zero (RFC 2181)" {
    // RFC 2181 §8: 收到的 TTL 最高位置位时应视为 0。
    const rr_hi = ResourceRecord{
        .name_pos = 12,
        .name_end_pos = 13,
        .rtype = .A,
        .class = 1,
        .ttl = 0x80000000,
        .rdlength = 0,
        .rdata = &[_]u8{},
        .rdata_offset = 0,
    };
    try std.testing.expectEqual(@as(u32, 0), rr_hi.effectiveTtl());
    try std.testing.expectEqual(@as(u32, 0x80000000), rr_hi.ttl); // 原始值保留

    const rr_ok = ResourceRecord{
        .name_pos = 12,
        .name_end_pos = 13,
        .rtype = .A,
        .class = 1,
        .ttl = 3600,
        .rdlength = 0,
        .rdata = &[_]u8{},
        .rdata_offset = 0,
    };
    try std.testing.expectEqual(@as(u32, 3600), rr_ok.effectiveTtl());
}

test "MessageParser nameEqualsAt is case-insensitive (RFC 4343)" {
    // 报文里存 "ExAmPlE.CoM"，查询名 "example.com" 应匹配；反之亦然。
    // DNS 域名比较对 ASCII 大小写不敏感（RFC 1035 §2.3.3 / RFC 4343）。
    var packet: [64]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[12] = 7;
    @memcpy(packet[13..20], "ExAmPlE");
    packet[20] = 3;
    @memcpy(packet[21..24], "CoM");
    packet[24] = 0;

    const parser = MessageParser.init(packet[0..25]);
    try std.testing.expect(try parser.nameEqualsAt(12, "example.com"));
    try std.testing.expect(try parser.nameEqualsAt(12, "EXAMPLE.COM"));
    try std.testing.expect(!(try parser.nameEqualsAt(12, "example.net")));
}

test "MessageParser nameEqualsAt accepts trailing dot (FQDN)" {
    // 区域文件 FQDN 按惯例带尾点；须与无尾点形式同样匹配
    // （与 Builder.canonicalizeName 一致），否则服务端快速路径会误报不匹配。
    var packet: [64]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[12] = 7;
    @memcpy(packet[13..20], "example");
    packet[20] = 3;
    @memcpy(packet[21..24], "com");
    packet[24] = 0;

    const parser = MessageParser.init(packet[0..25]);
    try std.testing.expect(try parser.nameEqualsAt(12, "example.com."));
    try std.testing.expect(try parser.nameEqualsAt(12, "example.com"));
    try std.testing.expect(!(try parser.nameEqualsAt(12, "example.net.")));
}

test "MessageParser skipName rejects dangling compression pointer" {
    // 名字以单个 0xC0 指针字节结尾，缺少第二字节。skipName 不得把 pos 推过缓冲区末尾
    // 后再交给下游兜底；应在指针处直接报 PacketTooShort（与 NameCursor.next 的守卫一致）。
    var packet: [17]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[12] = 3;
    @memcpy(packet[13..16], "com");
    packet[16] = 0xC0; // 悬挂指针：缺少第二字节
    var parser = MessageParser.init(&packet);
    try std.testing.expectError(error.PacketTooShort, parser.nextQuestion());
}
