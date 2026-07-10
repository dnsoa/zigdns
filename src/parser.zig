const std = @import("std");
const mem = std.mem;
const ECSData = @import("types.zig").ECSData;
const CookieData = @import("types.zig").CookieData;
const Type = @import("types.zig").Type;
const parseECS = @import("rdata.zig").parseECS;
const parseCookie = @import("rdata.zig").parseCookie;
const RData = @import("rdata.zig").RData;
const NameCursor = @import("name.zig").NameCursor;
const formatDnsName = @import("name.zig").formatDnsName;
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
    pub fn effectiveTtl(self: ResourceRecord) u32 {
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
    /// RFC 1035: label max 63 bytes, total name max 255 bytes
    fn skipName(self: *MessageParser) !void {
        var total_len: usize = 0;
        while (self.pos < self.buffer.len) {
            const len = self.buffer[self.pos];
            if (len == 0) {
                self.pos += 1;
                return;
            }
            if (len & 0xC0 == 0xC0) { // Pointer
                // 指针占 2 字节；末尾仅剩 1 字节（悬挂指针）时直接报错，不得把 pos
                // 推过缓冲区末尾后依赖下游兜底（与 NameCursor.next 的守卫一致）。
                if (self.pos + 2 > self.buffer.len) return error.PacketTooShort;
                self.pos += 2;
                return;
            }
            // RFC 1035 2.3.4: label max 63 bytes
            if (len > 63) return error.LabelTooLong;
            // RFC 1035: total name max 255 bytes
            total_len += 1 + len;
            if (total_len > 255) return error.NameTooLong;
            if (self.pos + 1 + len > self.buffer.len) return error.PacketTooShort;
            self.pos += 1 + len;
        }
        return error.MalformedName;
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

    /// 返回附加区第一个 OPT 记录（快路径，不检测重复、不校验 owner 为根）。
    /// 需要 RFC 6891 §6.1.1 严格语义（多 OPT/非根 owner → FORMERR）时用 `findEdns`。
    pub fn findOptRecord(self: *const MessageParser, count: u16) !?ResourceRecord {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return rr;
        }
        return null;
    }

    /// 便捷：返回第一个 OPT 中的 ECS（快路径，不检测重复 OPT）。严格校验用 `findEdns`。

    pub fn findECS(self: *const MessageParser, count: u16) !?ECSData {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return parseECS(rr.rdata);
        }
        return null;
    }

    /// 扫描附加区第一个 OPT 记录并解出其 DNS Cookie（RFC 7873；快路径，不检测重复 OPT）。
    pub fn findCookie(self: *const MessageParser, count: u16) !?CookieData {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return parseCookie(rr.rdata);
        }
        return null;
    }

    pub const Edns = struct { opt: ResourceRecord, ecs: ?ECSData };

    /// 单趟扫描附加区：一次返回 OPT 记录及其中的 ECS（若有），
    /// 避免同时需要 OPT 与 ECS 时 findOptRecord + findECS 的双次扫描。
    /// 严格模式：扫描全程，若发现多于一个 OPT 记录则报 error.MultipleOptRecords
    /// （RFC 6891 §6.1.1：多 OPT 必须回 FORMERR）。
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
                found = .{ .opt = rr, .ecs = try parseECS(rr.rdata) };
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

        var cur = NameCursor.init(self.buffer, offset);
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
    /// 委托给 name.zig 的 `formatDnsName`（基于统一的 `NameCursor`），
    /// 保留入口 InvalidOffset 语义。
    pub fn formatNameAt(self: *const MessageParser, offset: usize, out_buf: []u8) ![]const u8 {
        if (offset >= self.buffer.len) return error.InvalidOffset;
        return formatDnsName(self.buffer, offset, out_buf);
    }

    /// Parse a resource record's RDATA. Domain names inside RDATA are returned as
    /// self-contained `Name` values bound to this parser's buffer, so they resolve
    /// compression pointers without any pointer arithmetic or aliasing assumptions.
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
    @memset(packet[0..12], 0);

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

    var parser = MessageParser.init(packet[0 .. pos + 4]);
    const question = (try parser.nextQuestion()).?;

    try std.testing.expectEqual(Type.A, question.qtype);
    try std.testing.expectEqual(@as(u16, 1), question.qclass);
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
