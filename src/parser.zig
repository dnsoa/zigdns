const std = @import("std");
const mem = std.mem;
const ECSData = @import("types.zig").ECSData;
const Type = @import("types.zig").Type;
const parseECS = @import("rdata.zig").parseECS;

pub const Question = struct {
    qname_end_pos: usize, // Where the name ends in the buffer
    qtype: Type,
    qclass: u16,
};

pub const ResourceRecord = struct {
    name_end_pos: usize,
    rtype: Type,
    class: u16,
    ttl: u32,
    rdlength: u16,
    rdata: []const u8, // Slice pointing into the original packet
};

pub fn CountedIterator(comptime T: type) type {
    return struct {
        parser: *MessageParser,
        remaining: u16,
        nextFn: *const fn (*MessageParser) anyerror!?T,

        pub fn next(self: *@This()) !?T {
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

        try self.skipName();
        const end_name = self.pos;

        if (self.pos + 4 > self.buffer.len) return error.PacketTooShort;

        const qtype = @as(Type, @enumFromInt(mem.readInt(u16, self.buffer[self.pos..][0..2], .big)));
        const qclass = mem.readInt(u16, self.buffer[self.pos + 2 ..][0..2], .big);
        self.pos += 4;

        return Question{
            .qname_end_pos = end_name,
            .qtype = qtype,
            .qclass = qclass,
        };
    }

    /// Parses the next Resource Record (Answer/Authority/Additional)
    pub fn nextRR(self: *MessageParser) !?ResourceRecord {
        if (self.pos >= self.buffer.len) return null;

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
        const rdata = self.buffer[self.pos .. self.pos + rdlen];
        self.pos += rdlen;

        return ResourceRecord{
            .name_end_pos = end_name,
            .rtype = rtype,
            .class = class,
            .ttl = ttl,
            .rdlength = rdlen,
            .rdata = rdata,
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

    pub fn findOptRecord(self: *const MessageParser, count: u16) !?ResourceRecord {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return rr;
        }
        return null;
    }

    pub fn findECS(self: *const MessageParser, count: u16) !?ECSData {
        var scan = self.*;
        var remaining = count;
        while (remaining > 0) : (remaining -= 1) {
            const rr = (try scan.nextRR()) orelse return error.PacketTooShort;
            if (rr.rtype == .OPT) return parseECS(rr.rdata);
        }
        return null;
    }

    pub fn nameEqualsAt(self: *const MessageParser, offset: usize, expected: []const u8) !bool {
        if (offset >= self.buffer.len) return error.InvalidOffset;

        var read_pos = offset;
        var expected_pos: usize = 0;
        var redirects: u8 = 16;
        var first_label = true;

        while (read_pos < self.buffer.len) {
            const len = self.buffer[read_pos];

            if (len == 0) {
                return expected_pos == expected.len;
            }

            if (len & 0xC0 == 0xC0) {
                if (read_pos + 1 >= self.buffer.len) return error.PacketTooShort;
                if (redirects == 0) return error.MalformedName;
                redirects -= 1;
                read_pos = ((@as(u16, len & 0x3F)) << 8) | self.buffer[read_pos + 1];
                if (read_pos >= self.buffer.len) return error.InvalidOffset;
                continue;
            }

            if (len > 63) return error.LabelTooLong;
            if (read_pos + 1 + len > self.buffer.len) return error.PacketTooShort;

            if (!first_label) {
                if (expected_pos >= expected.len or expected[expected_pos] != '.') return false;
                expected_pos += 1;
            }
            first_label = false;

            if (expected_pos + len > expected.len) return false;
            if (!mem.eql(u8, self.buffer[read_pos + 1 .. read_pos + 1 + len], expected[expected_pos .. expected_pos + len])) {
                return false;
            }

            expected_pos += len;
            read_pos += 1 + len;
        }

        return error.MalformedName;
    }

    fn formatNameFast(self: *const MessageParser, start_offset: usize, out_buf: []u8) !?[]const u8 {
        var read_pos = start_offset;
        var write_pos: usize = 0;

        while (read_pos < self.buffer.len) {
            const len = self.buffer[read_pos];

            if (len == 0) {
                if (write_pos == 0) {
                    if (out_buf.len == 0) return error.BufferTooSmall;
                    out_buf[0] = '.';
                    return out_buf[0..1];
                }
                return out_buf[0..write_pos];
            }

            if (len & 0xC0 == 0xC0) return null;
            if (len > 63) return error.LabelTooLong;
            if (read_pos + 1 + len > self.buffer.len) return error.PacketTooShort;

            if (write_pos != 0) {
                if (write_pos >= out_buf.len) return error.BufferTooSmall;
                out_buf[write_pos] = '.';
                write_pos += 1;
            }

            if (write_pos + len > out_buf.len) return error.BufferTooSmall;
            @memcpy(out_buf[write_pos .. write_pos + len], self.buffer[read_pos + 1 .. read_pos + 1 + len]);
            write_pos += len;
            read_pos += 1 + len;
        }

        return error.MalformedName;
    }

    /// Format a DNS name at a specific offset in the packet
    /// Follows compression pointers and returns dotted format
    pub fn formatNameAt(self: *const MessageParser, offset: usize, out_buf: []u8) ![]const u8 {
        if (offset >= self.buffer.len) return error.InvalidOffset;

        const first_len = self.buffer[offset];
        if (first_len & 0xC0 == 0xC0) {
            if (offset + 1 >= self.buffer.len) return error.PacketTooShort;

            const ptr = ((@as(u16, first_len & 0x3F)) << 8) | self.buffer[offset + 1];
            if (ptr >= self.buffer.len) return error.InvalidOffset;

            if (try self.formatNameFast(ptr, out_buf)) |name| {
                return name;
            }
        }

        var read_pos: usize = offset;
        var write_pos: usize = 0;
        var first_label = true;
        var visited_offsets: [16]usize = undefined; // Track visited offsets to detect loops
        var visited_count: usize = 0;

        while (read_pos < self.buffer.len) {
            const len = self.buffer[read_pos];

            // 结束符
            if (len == 0) {
                if (write_pos == 0) {
                    out_buf[write_pos] = '.';
                    write_pos += 1;
                }
                return out_buf[0..write_pos];
            }

            // 指针压缩 - 跟随指针
            if (len & 0xC0 == 0xC0) {
                const offset_ptr = mem.readInt(u16, self.buffer[read_pos..][0..2], .big) & 0x3FFF;

                // 检测循环引用
                for (visited_offsets[0..visited_count]) |v| {
                    if (v == offset_ptr) return error.MalformedName;
                }
                if (visited_count >= 16) return error.MalformedName; // Too many redirects
                visited_offsets[visited_count] = offset_ptr;
                visited_count += 1;

                read_pos = offset_ptr;
                continue;
            }

            // 验证标签长度
            if (len > 63) return error.LabelTooLong;
            if (read_pos + 1 + len > self.buffer.len) return error.PacketTooShort;

            // 添加点分隔符（第一个标签前不加）
            if (!first_label) {
                if (write_pos >= out_buf.len) return error.BufferTooSmall;
                out_buf[write_pos] = '.';
                write_pos += 1;
            }
            first_label = false;

            // 检查输出缓冲区大小
            if (write_pos + len > out_buf.len) return error.BufferTooSmall;

            // 复制标签内容
            @memcpy(out_buf[write_pos .. write_pos + len], self.buffer[read_pos + 1 .. read_pos + 1 + len]);
            write_pos += len;
            read_pos += 1 + len;
        }

        return error.MalformedName;
    }

    /// Format a DNS name from a slice that points into the packet
    /// Computes the offset and uses formatNameAt
    pub fn formatNameFromSlice(self: *const MessageParser, name_slice: []const u8, out_buf: []u8) ![]const u8 {
        // 计算切片在缓冲区中的偏移量
        const offset = @intFromPtr(name_slice.ptr) - @intFromPtr(self.buffer.ptr);
        if (offset >= self.buffer.len) return error.InvalidOffset;
        return self.formatNameAt(offset, out_buf);
    }
};

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
