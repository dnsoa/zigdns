const std = @import("std");
const mem = std.mem;
const Header = @import("header.zig").Header;
const Type = @import("types.zig").Type;
const Error = @import("errors.zig").Error;

const MAX_COMPRESSION = 32; // 最多追踪 32 个域名

/// 核心解析/构造器
pub const Message = struct {
    header: Header,
    buffer: []const u8, // 原始数据引用

    /// 初始化解析 (零分配)
    pub fn parse(raw: []const u8) !Message {
        if (raw.len < 12) return error.PacketTooShort;
        const header = Header.decode(raw[0..12]);
        return Message{ .header = header, .buffer = raw };
    }

    /// 高性能响应构造器
    pub const Builder = struct {
        buf: []u8,
        pos: usize,
        // 压缩指针表：域名哈希 -> 位置
        compression_table: [MAX_COMPRESSION]struct { hash: u64, pos: u16 },
        compression_count: u8,

        pub fn init(dest: []u8) Builder {
            return .{
                .buf = dest,
                .pos = 12, // 跳过 header 空间
                .compression_table = undefined,
                .compression_count = 0,
            };
        }

        /// 写入 A 记录
        pub fn addARecord(self: *Builder, name: []const u8, ttl: u32, ip: [4]u8) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.A));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            try self.writeU16(4); // RDLength
            @memcpy(self.buf[self.pos..][0..4], &ip);
            self.pos += 4;
        }

        /// 写入 AAAA 记录
        pub fn addAAAARecord(self: *Builder, name: []const u8, ttl: u32, ip: [16]u8) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.AAAA));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            try self.writeU16(16); // RDLength
            @memcpy(self.buf[self.pos..][0..16], &ip);
            self.pos += 16;
        }

        /// 写入 CNAME 记录
        pub fn addCNAMERecord(self: *Builder, name: []const u8, ttl: u32, cname: []const u8) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.CNAME));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeNameRaw(cname);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
        }

        /// 写入 MX 记录
        pub fn addMXRecord(self: *Builder, name: []const u8, ttl: u32, preference: u16, exchange: []const u8) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.MX));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeU16(preference);
            try self.writeNameRaw(exchange);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
        }

        /// 写入 NS 记录
        pub fn addNSRecord(self: *Builder, name: []const u8, ttl: u32, nsdname: []const u8) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.NS));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeNameRaw(nsdname);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
        }

        /// 写入 PTR 记录
        pub fn addPTRRecord(self: *Builder, name: []const u8, ttl: u32, ptrdname: []const u8) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.PTR));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeNameRaw(ptrdname);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
        }

        /// 写入 TXT 记录
        pub fn addTXTRecord(self: *Builder, name: []const u8, ttl: u32, txt: []const u8) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.TXT));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            if (txt.len > 255) return Error.LabelTooLong;
            try self.writeU16(@intCast(txt.len + 1)); // RDLength
            self.buf[self.pos] = @intCast(txt.len);
            self.pos += 1;
            @memcpy(self.buf[self.pos..][0..txt.len], txt);
            self.pos += txt.len;
        }

        /// 写入 SOA 记录
        pub fn addSOARecord(
            self: *Builder,
            name: []const u8,
            ttl: u32,
            mname: []const u8,
            rname: []const u8,
            serial: u32,
            refresh: u32,
            retry: u32,
            expire: u32,
            minimum: u32,
        ) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.SOA));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeNameRaw(mname);
            try self.writeNameRaw(rname);
            try self.writeU32(serial);
            try self.writeU32(refresh);
            try self.writeU32(retry);
            try self.writeU32(expire);
            try self.writeU32(minimum);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
        }

        /// 写入 SRV 记录
        pub fn addSRVRecord(
            self: *Builder,
            name: []const u8,
            ttl: u32,
            priority: u16,
            weight: u16,
            port: u16,
            target: []const u8,
        ) !void {
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.SRV));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeU16(priority);
            try self.writeU16(weight);
            try self.writeU16(port);
            try self.writeNameRaw(target);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
        }

        /// 写入 Question
        pub fn addQuestion(self: *Builder, qname: []const u8, qtype: Type, qclass: u16) !void {
            try self.writeName(qname);
            try self.writeU16(@intFromEnum(qtype));
            try self.writeU16(qclass);
        }

        /// 写入域名，支持压缩指针
        fn writeName(self: *Builder, name: []const u8) !void {
            const hash = std.hash.Wyhash.hash(0, name);

            // 检查是否可以使用压缩指针
            if (self.compression_count > 0) {
                for (self.compression_table[0..self.compression_count]) |entry| {
                    if (entry.hash == hash) {
                        // 使用压缩指针
                        if (entry.pos < 0x3FFF) {
                            self.buf[self.pos] = 0xC0 | @as(u8, @intCast(entry.pos >> 8));
                            self.buf[self.pos + 1] = @as(u8, @intCast(entry.pos & 0xFF));
                            self.pos += 2;
                            return;
                        }
                    }
                }
            }

            // 写入完整域名
            const start = self.pos;
            var it = mem.splitScalar(u8, name, '.');
            while (it.next()) |label| {
                self.buf[self.pos] = @intCast(label.len);
                @memcpy(self.buf[self.pos + 1 ..][0..label.len], label);
                self.pos += 1 + label.len;
            }
            self.buf[self.pos] = 0;
            self.pos += 1;

            // 记录到压缩表（追踪后缀域名）
            if (self.compression_count < MAX_COMPRESSION) {
                var label_it = mem.splitScalar(u8, name, '.');
                var suffix_offset: usize = 0;
                while (label_it.next()) |label| {
                    const suffix = name[suffix_offset..];
                    const suffix_hash = std.hash.Wyhash.hash(0, suffix);
                    self.compression_table[self.compression_count] = .{
                        .hash = suffix_hash,
                        .pos = @intCast(start + suffix_offset),
                    };
                    self.compression_count += 1;
                    if (self.compression_count >= MAX_COMPRESSION) break;
                    suffix_offset += label.len + 1; // 跳过标签和点
                }
            }
        }

        /// 写入原始域名（不压缩，用于 rdata 中的域名）
        fn writeNameRaw(self: *Builder, name: []const u8) !void {
            var it = mem.splitScalar(u8, name, '.');
            while (it.next()) |label| {
                self.buf[self.pos] = @intCast(label.len);
                @memcpy(self.buf[self.pos + 1 ..][0..label.len], label);
                self.pos += 1 + label.len;
            }
            self.buf[self.pos] = 0;
            self.pos += 1;
        }

        fn writeU16(self: *Builder, val: u16) !void {
            mem.writeInt(u16, self.buf[self.pos..][0..2], val, .big);
            self.pos += 2;
        }

        fn writeU32(self: *Builder, val: u32) !void {
            mem.writeInt(u32, self.buf[self.pos..][0..4], val, .big);
            self.pos += 4;
        }

        pub fn finish(self: *Builder, header: Header) []u8 {
            const h_bytes = header.encode();
            @memcpy(self.buf[0..12], &h_bytes);
            return self.buf[0..self.pos];
        }
    };
};

test "Message.Builder addQuestion" {
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    try builder.addQuestion("example.com", .A, 1);

    const header = Header{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 1, .ancount = 0, .nscount = 0, .arcount = 0 };
    const packet = builder.finish(header);

    // 验证: Header(12) + Name(13) + Type(2) + Class(2) = 29
    try std.testing.expectEqual(@as(usize, 29), packet.len);
}

test "Message.Builder addARecord" {
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });

    const header = Header{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 1, .nscount = 0, .arcount = 0 };
    const packet = builder.finish(header);

    // 12(header) + 13(name) + 2(type) + 2(class) + 4(ttl) + 2(rdlen) + 4(rdata) = 39
    try std.testing.expectEqual(@as(usize, 39), packet.len);
}

test "Message.Builder compression pointer" {
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    // 写入相同域名两次，第二次应使用压缩指针
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });
    const pos1 = builder.pos;
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 2 });
    const pos2 = builder.pos;

    // 第二次写入应短 11 字节 (压缩指针 2 字节 vs 完整域名 13 字节)
    // 2(ptr) + 2+2+4+2+4 = 16 vs 13(name) + 2+2+4+2+4 = 27，差 11
    try std.testing.expectEqual(@as(usize, 16), pos2 - pos1);
}

test "Message.Builder addMXRecord" {
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    try builder.addMXRecord("example.com", 3600, 10, "mail.example.com");

    const header = Header{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 1, .nscount = 0, .arcount = 0 };
    const packet = builder.finish(header);

    // 12 + 13 (example.com) + 10 (fixed) + 2 (pref) + 18 (mail.example.com) = 55
    try std.testing.expectEqual(@as(usize, 55), packet.len);
}
