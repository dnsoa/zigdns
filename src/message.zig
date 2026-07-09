const std = @import("std");
const mem = std.mem;
const Header = @import("header.zig").Header;
const Type = @import("types.zig").Type;
const OptionCode = @import("types.zig").OptionCode;
const ECSData = @import("types.zig").ECSData;
const Error = @import("errors.zig").Error;

const MAX_COMPRESSION = 32; // 最多追踪 32 个域名
const MAX_NAME_LENGTH = 255;

/// DNS 报文分区（RFC 1035 4.1）。构造时记录必须按此顺序添加。
pub const Section = enum { question, answer, authority, additional };

/// EDNS(0) OPT 记录参数（RFC 6891 / 7871）。
pub const Edns = struct {
    udp_payload_size: u16 = 1232, // 存于 OPT 记录的 CLASS 字段
    extended_rcode: u8 = 0, // 扩展 RCODE 高 8 位（存于 TTL[31:24]）
    version: u8 = 0, // EDNS 版本（存于 TTL[23:16]）
    dnssec_ok: bool = false, // DO 标志（存于 TTL flags 最高位）
    ecs: ?ECSData = null, // 若设置则写入 ECS 选项
};

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

    /// 解析 TCP 组帧报文：2 字节大端长度前缀 + DNS 报文（RFC 1035 4.2.2）。
    /// buffer 引用去除前缀后的 DNS 报文切片（零拷贝）。
    pub fn parseTcp(raw: []const u8) !Message {
        if (raw.len < 2) return error.PacketTooShort;
        const msg_len = mem.readInt(u16, raw[0..2], .big);
        if (raw.len < 2 + @as(usize, msg_len)) return error.PacketTooShort;
        return Message.parse(raw[2 .. 2 + msg_len]);
    }

    /// 高性能响应构造器
    pub const Builder = struct {
        buf: []u8, // DNS 报文区域（TCP 时为 dest[2..]）
        dest: []u8, // 完整目标缓冲区（含可能的 2 字节 TCP 长度前缀）
        prefix_len: usize, // DNS 报文前保留字节数：0=UDP, 2=TCP
        pos: usize,
        // 压缩指针表：域名哈希 -> 位置
        compression_table: [MAX_COMPRESSION]struct { hash: u64, pos: u16 },
        compression_count: u8,
        section: Section, // 当前分区，用于自动计数
        qd: u16,
        an: u16,
        ns: u16,
        ar: u16,

        pub fn init(dest: []u8) Builder {
            return initFramed(dest, 0);
        }

        /// 构造 TCP 报文：预留 2 字节长度前缀，DNS 报文写入 dest[2..]，用 finishTcp 收尾。
        pub fn initTcp(dest: []u8) !Builder {
            if (dest.len < 2) return Error.BufferTooSmall;
            return initFramed(dest, 2);
        }

        fn initFramed(dest: []u8, prefix_len: usize) Builder {
            return .{
                .buf = dest[prefix_len..],
                .dest = dest,
                .prefix_len = prefix_len,
                .pos = 12, // 跳过 header 空间（相对 DNS 报文起始）
                .compression_table = undefined,
                .compression_count = 0,
                .section = .answer, // RR 默认写入回答区
                .qd = 0,
                .an = 0,
                .ns = 0,
                .ar = 0,
            };
        }

        const Snapshot = struct { pos: usize, compression_count: u8 };

        fn snapshot(self: *const Builder) Snapshot {
            return .{ .pos = self.pos, .compression_count = self.compression_count };
        }

        /// 回滚到快照（用于 add* 失败时保持原子性，使截断可安全恢复）。
        fn restore(self: *Builder, s: Snapshot) void {
            self.pos = s.pos;
            self.compression_count = s.compression_count;
        }

        /// 切换当前分区（后续 RR 计入 authority/additional）。分区只能向后推进。
        pub fn setSection(self: *Builder, s: Section) void {
            std.debug.assert(@intFromEnum(s) >= @intFromEnum(self.section));
            self.section = s;
        }

        /// 校验 buf[pos..] 处已写入的（展开的）线格式域名是否等于 canonical 点分名。
        /// 用于压缩指针复用前的字节级确认，防止 64 位 hash 碰撞导致指向错误域名。
        fn nameMatchesAt(self: *const Builder, pos: u16, canonical: []const u8) bool {
            var read: usize = pos;
            var exp: usize = 0;
            var first = true;
            while (read < self.pos) {
                const len = self.buf[read];
                if (len == 0) return exp == canonical.len;
                if (len & 0xC0 == 0xC0) return false; // 压缩表仅记录展开写入的名字，不应出现指针
                if (len > 63) return false;
                if (read + 1 + len > self.pos) return false;
                if (!first) {
                    if (exp >= canonical.len or canonical[exp] != '.') return false;
                    exp += 1;
                }
                first = false;
                if (exp + len > canonical.len) return false;
                if (!mem.eql(u8, self.buf[read + 1 .. read + 1 + len], canonical[exp .. exp + len])) return false;
                exp += len;
                read += 1 + len;
            }
            return false;
        }

        fn countRecord(self: *Builder) void {
            switch (self.section) {
                .question => self.qd += 1,
                .answer => self.an += 1,
                .authority => self.ns += 1,
                .additional => self.ar += 1,
            }
        }

        fn ensureCapacity(self: *Builder, need: usize) !void {
            if (need > self.buf.len -| self.pos) return Error.BufferTooSmall;
        }

        fn canonicalizeName(name: []const u8) []const u8 {
            if (name.len > 1 and name[name.len - 1] == '.') {
                return name[0 .. name.len - 1];
            }
            return name;
        }

        fn validateName(name: []const u8) ![]const u8 {
            const canonical = canonicalizeName(name);
            var total_len: usize = 1; // root terminator
            var label_len: usize = 0;

            for (canonical) |byte| {
                if (byte == '.') {
                    if (label_len == 0) return Error.MalformedName;
                    if (label_len > 63) return Error.LabelTooLong;
                    total_len += 1 + label_len;
                    if (total_len > MAX_NAME_LENGTH) return Error.NameTooLong;
                    label_len = 0;
                } else {
                    label_len += 1;
                }
            }

            if (label_len == 0) return Error.MalformedName;
            if (label_len > 63) return Error.LabelTooLong;
            total_len += 1 + label_len;
            if (total_len > MAX_NAME_LENGTH) return Error.NameTooLong;

            return canonical;
        }

        fn analyzeName(name: []const u8) !struct { canonical: []const u8, hash: u64 } {
            const canonical = try validateName(name);
            return .{
                .canonical = canonical,
                .hash = std.hash.Wyhash.hash(0, canonical),
            };
        }

        /// 写入 A 记录
        pub fn addARecord(self: *Builder, name: []const u8, ttl: u32, ip: [4]u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.A));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            try self.writeU16(4); // RDLength
            try self.ensureCapacity(4);
            @memcpy(self.buf[self.pos..][0..4], &ip);
            self.pos += 4;
            self.countRecord();
        }

        /// 写入 AAAA 记录
        pub fn addAAAARecord(self: *Builder, name: []const u8, ttl: u32, ip: [16]u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.AAAA));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            try self.writeU16(16); // RDLength
            try self.ensureCapacity(16);
            @memcpy(self.buf[self.pos..][0..16], &ip);
            self.pos += 16;
            self.countRecord();
        }

        /// 写入 CNAME 记录
        pub fn addCNAMERecord(self: *Builder, name: []const u8, ttl: u32, cname: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.CNAME));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeNameRaw(cname);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入 MX 记录
        pub fn addMXRecord(self: *Builder, name: []const u8, ttl: u32, preference: u16, exchange: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
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
            self.countRecord();
        }

        /// 写入 NS 记录
        pub fn addNSRecord(self: *Builder, name: []const u8, ttl: u32, nsdname: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.NS));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeNameRaw(nsdname);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入 PTR 记录
        pub fn addPTRRecord(self: *Builder, name: []const u8, ttl: u32, ptrdname: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.PTR));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeNameRaw(ptrdname);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入 TXT 记录
        pub fn addTXTRecord(self: *Builder, name: []const u8, ttl: u32, txt: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.TXT));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            if (txt.len > 255) return Error.LabelTooLong;
            try self.writeU16(@intCast(txt.len + 1)); // RDLength
            try self.ensureCapacity(txt.len + 1);
            self.buf[self.pos] = @intCast(txt.len);
            self.pos += 1;
            @memcpy(self.buf[self.pos..][0..txt.len], txt);
            self.pos += txt.len;
            self.countRecord();
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
            const snap = self.snapshot();
            errdefer self.restore(snap);
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
            self.countRecord();
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
            const snap = self.snapshot();
            errdefer self.restore(snap);
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
            self.countRecord();
        }

        /// 写入 Question（必须先于所有 RR 添加）
        pub fn addQuestion(self: *Builder, qname: []const u8, qtype: Type, qclass: u16) !void {
            std.debug.assert(self.an == 0 and self.ns == 0 and self.ar == 0);
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(qname);
            try self.writeU16(@intFromEnum(qtype));
            try self.writeU16(qclass);
            self.qd += 1;
        }

        /// 写入 EDNS(0) OPT 记录（RFC 6891）。自动置于附加区（additional）。
        /// 若 edns.ecs 非空，附带 ECS 选项（RFC 7871）。
        pub fn addOptRecord(self: *Builder, edns: Edns) !void {
            self.setSection(.additional);
            const snap = self.snapshot();
            errdefer self.restore(snap);

            try self.writeU8(0); // OPT 的 owner name 必须为根
            try self.writeU16(@intFromEnum(Type.OPT));
            try self.writeU16(edns.udp_payload_size); // CLASS = 请求方 UDP 载荷大小
            const flags: u32 = if (edns.dnssec_ok) 0x8000 else 0;
            const ttl = (@as(u32, edns.extended_rcode) << 24) |
                (@as(u32, edns.version) << 16) | flags;
            try self.writeU32(ttl);

            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            if (edns.ecs) |ecs| try self.writeEcsOption(ecs);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 低级：写入 OPT 记录，options 为调用方自行编码的完整 RDATA。
        pub fn addOptRecordRaw(self: *Builder, udp_payload_size: u16, ttl: u32, options: []const u8) !void {
            if (options.len > 0xFFFF) return Error.MessageTooLong;
            self.setSection(.additional);
            const snap = self.snapshot();
            errdefer self.restore(snap);

            try self.writeU8(0);
            try self.writeU16(@intFromEnum(Type.OPT));
            try self.writeU16(udp_payload_size);
            try self.writeU32(ttl);
            try self.writeU16(@intCast(options.len));
            try self.ensureCapacity(options.len);
            @memcpy(self.buf[self.pos..][0..options.len], options);
            self.pos += options.len;
            self.countRecord();
        }

        /// 写入 ECS 选项 TLV（RFC 7871）。按 family/prefix 校验地址长度。
        fn writeEcsOption(self: *Builder, ecs: ECSData) !void {
            const max_prefix: u8 = switch (ecs.family) {
                1 => 32, // IPv4
                2 => 128, // IPv6
                else => return Error.MalformedECS,
            };
            if (ecs.source_prefix > max_prefix) return Error.MalformedECS;
            const addr_len = (@as(usize, ecs.source_prefix) + 7) / 8;
            if (ecs.address.len < addr_len) return Error.MalformedECS;

            try self.writeU16(@intFromEnum(OptionCode.ECS));
            try self.writeU16(@intCast(4 + addr_len)); // OPTION-LENGTH
            try self.writeU16(ecs.family);
            try self.writeU8(ecs.source_prefix);
            try self.writeU8(ecs.scope_prefix);
            try self.ensureCapacity(addr_len);
            @memcpy(self.buf[self.pos..][0..addr_len], ecs.address[0..addr_len]);
            self.pos += addr_len;
        }

        /// 写入域名，支持压缩指针
        fn writeName(self: *Builder, name: []const u8) !void {
            if (name.len == 0 or mem.eql(u8, name, ".")) {
                try self.ensureCapacity(1);
                self.buf[self.pos] = 0;
                self.pos += 1;
                return;
            }

            const analyzed = try analyzeName(name);
            const canonical = analyzed.canonical;
            const hash = analyzed.hash;

            // 检查是否可以使用压缩指针（hash 命中后必须字节级确认，避免碰撞指向错误域名）
            if (self.compression_count > 0) {
                for (self.compression_table[0..self.compression_count]) |entry| {
                    if (entry.hash == hash and entry.pos < 0x3FFF and self.nameMatchesAt(entry.pos, canonical)) {
                        try self.ensureCapacity(2);
                        self.buf[self.pos] = 0xC0 | @as(u8, @intCast(entry.pos >> 8));
                        self.buf[self.pos + 1] = @as(u8, @intCast(entry.pos & 0xFF));
                        self.pos += 2;
                        return;
                    }
                }
            }

            // 写入完整域名
            const start = self.pos;
            var it = mem.splitScalar(u8, canonical, '.');
            while (it.next()) |label| {
                try self.ensureCapacity(1 + label.len);
                self.buf[self.pos] = @intCast(label.len);
                @memcpy(self.buf[self.pos + 1 ..][0..label.len], label);
                self.pos += 1 + label.len;
            }
            try self.ensureCapacity(1);
            self.buf[self.pos] = 0;
            self.pos += 1;

            // 记录到压缩表（追踪后缀域名）
            if (self.compression_count < MAX_COMPRESSION) {
                var label_it = mem.splitScalar(u8, canonical, '.');
                var suffix_offset: usize = 0;
                while (label_it.next()) |label| {
                    const suffix = canonical[suffix_offset..];
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
            if (name.len == 0 or mem.eql(u8, name, ".")) {
                try self.ensureCapacity(1);
                self.buf[self.pos] = 0;
                self.pos += 1;
                return;
            }

            const canonical = try validateName(name);
            var it = mem.splitScalar(u8, canonical, '.');
            while (it.next()) |label| {
                try self.ensureCapacity(1 + label.len);
                self.buf[self.pos] = @intCast(label.len);
                @memcpy(self.buf[self.pos + 1 ..][0..label.len], label);
                self.pos += 1 + label.len;
            }
            try self.ensureCapacity(1);
            self.buf[self.pos] = 0;
            self.pos += 1;
        }

        fn writeU8(self: *Builder, val: u8) !void {
            try self.ensureCapacity(1);
            self.buf[self.pos] = val;
            self.pos += 1;
        }

        fn writeU16(self: *Builder, val: u16) !void {
            try self.ensureCapacity(2);
            mem.writeInt(u16, self.buf[self.pos..][0..2], val, .big);
            self.pos += 2;
        }

        fn writeU32(self: *Builder, val: u32) !void {
            try self.ensureCapacity(4);
            mem.writeInt(u32, self.buf[self.pos..][0..4], val, .big);
            self.pos += 4;
        }

        /// 收尾：自动回填 header 的四个分区计数（防止 desync），返回 DNS 报文。
        pub fn finish(self: *Builder, header: Header) []u8 {
            var h = header;
            h.qdcount = self.qd;
            h.ancount = self.an;
            h.nscount = self.ns;
            h.arcount = self.ar;
            return self.finishRaw(h);
        }

        /// 收尾但原样使用调用方 header 的计数（不自动回填）。
        pub fn finishRaw(self: *Builder, header: Header) []u8 {
            const h_bytes = header.encode();
            @memcpy(self.buf[0..12], &h_bytes);
            return self.buf[0..self.pos];
        }

        /// TCP 收尾：写入 2 字节大端长度前缀（RFC 1035 4.2.2），返回含前缀的完整帧。
        /// 必须由 initTcp 创建。计数同样自动回填。
        pub fn finishTcp(self: *Builder, header: Header) Error![]u8 {
            std.debug.assert(self.prefix_len == 2);
            const msg = self.finish(header);
            if (msg.len > 0xFFFF) return Error.MessageTooLong;
            mem.writeInt(u16, self.dest[0..2], @intCast(msg.len), .big);
            return self.dest[0 .. 2 + msg.len];
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

test "Message.Builder returns BufferTooSmall on short destination" {
    var buf: [20]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    try std.testing.expectError(error.BufferTooSmall, builder.addQuestion("example.com", .A, 1));
}

test "Message.Builder finish auto-counts sections" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    try builder.addQuestion("example.com", .A, 1);
    try builder.addARecord("example.com", 60, .{ 1, 2, 3, 4 });
    try builder.addARecord("example.com", 60, .{ 5, 6, 7, 8 });
    builder.setSection(.authority);
    try builder.addNSRecord("example.com", 60, "ns1.example.com");
    builder.setSection(.additional);
    try builder.addARecord("ns1.example.com", 60, .{ 9, 9, 9, 9 });

    // 传入全 0 计数，finish 应自动回填正确值
    const packet = builder.finish(.{
        .id = 1,
        .rd = 0,
        .tc = 0,
        .aa = 1,
        .opcode = 0,
        .qr = 1,
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    });

    const msg = try Message.parse(packet);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 2), msg.header.ancount);
    try std.testing.expectEqual(@as(u16, 1), msg.header.nscount);
    try std.testing.expectEqual(@as(u16, 1), msg.header.arcount);

    // 结构可被完整遍历
    var parser = MessageParser.init(packet);
    try parser.skipQuestions(msg.header.qdcount);
    try parser.skipResourceRecords(msg.header.ancount + msg.header.nscount);
    const rr = (try parser.nextRR()).?;
    try std.testing.expectEqual(@as(u32, 60), rr.ttl);
}

test "Message.Builder failed add is atomic (enables TC truncation)" {
    // 缓冲区仅够放下 question + 第一条 A 记录，第二条应失败且不破坏已写内容。
    var buf: [45]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    try builder.addQuestion("example.com", .A, 1); // 12 + 13 + 4 = 29
    try builder.addARecord("example.com", 60, .{ 1, 2, 3, 4 }); // 压缩后 2 + 12 = 14 -> pos=43

    const pos_before = builder.pos;
    const an_before = builder.an;

    // 第二条放不下 -> BufferTooSmall，且必须原子回滚
    try std.testing.expectError(error.BufferTooSmall, builder.addARecord("example.com", 60, .{ 5, 6, 7, 8 }));
    try std.testing.expectEqual(pos_before, builder.pos);
    try std.testing.expectEqual(an_before, builder.an);

    // 服务器此时置 TC=1 并正常收尾，得到有效的截断报文
    const packet = builder.finish(.{
        .id = 1,
        .rd = 0,
        .tc = 1,
        .aa = 1,
        .opcode = 0,
        .qr = 1,
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    });
    const msg = try Message.parse(packet);
    try std.testing.expectEqual(@as(u1, 1), msg.header.tc);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 1), msg.header.ancount);
}

test "Message TCP framing round-trip" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.initTcp(&buf);

    try builder.addQuestion("example.com", .A, 1);
    try builder.addARecord("example.com", 60, .{ 93, 184, 216, 34 });

    const frame = try builder.finishTcp(.{
        .id = 0x1234,
        .rd = 0,
        .tc = 0,
        .aa = 1,
        .opcode = 0,
        .qr = 1,
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    });

    // 前 2 字节为大端长度前缀，等于其后 DNS 报文长度
    const prefix_len = mem.readInt(u16, frame[0..2], .big);
    try std.testing.expectEqual(@as(usize, prefix_len), frame.len - 2);

    // parseTcp 应剥离前缀并正确解析
    const msg = try Message.parseTcp(frame);
    try std.testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 1), msg.header.ancount);
}

test "Message.parseTcp rejects truncated frame" {
    // 前缀声称 100 字节，实际不足
    var buf: [10]u8 = undefined;
    mem.writeInt(u16, buf[0..2], 100, .big);
    try std.testing.expectError(error.PacketTooShort, Message.parseTcp(&buf));
}

test "Message.Builder addOptRecord with ECS round-trips" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{
        .udp_payload_size = 4096,
        .dnssec_ok = true,
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0, .address = &[_]u8{ 192, 0, 2 } },
    });

    const packet = builder.finish(.{
        .id = 1,
        .rd = 0,
        .tc = 0,
        .aa = 0,
        .opcode = 0,
        .qr = 0,
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    });

    const msg = try Message.parse(packet);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 0), msg.header.ancount);
    try std.testing.expectEqual(@as(u16, 1), msg.header.arcount);

    var parser = MessageParser.init(packet);
    try parser.skipQuestions(msg.header.qdcount);
    try parser.skipResourceRecords(msg.header.ancount + msg.header.nscount);

    const opt = (try parser.findOptRecord(msg.header.arcount)).?;
    try std.testing.expectEqual(Type.OPT, opt.rtype);
    try std.testing.expectEqual(@as(u16, 4096), opt.class); // UDP payload size
    try std.testing.expect((opt.ttl & 0x8000) != 0); // DO flag
    try std.testing.expectEqual(@as(u8, 0), @as(u8, @truncate(opt.ttl >> 16))); // version 0

    const ecs = (try parser.findECS(msg.header.arcount)).?;
    try std.testing.expectEqual(@as(u16, 1), ecs.family);
    try std.testing.expectEqual(@as(u8, 24), ecs.source_prefix);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2 }, ecs.address);
}

test "Message.Builder addOptRecord without ECS (bare EDNS)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{ .udp_payload_size = 1232 });

    const packet = builder.finish(.{
        .id = 1,
        .rd = 1,
        .tc = 0,
        .aa = 0,
        .opcode = 0,
        .qr = 0,
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    });
    const msg = try Message.parse(packet);
    try std.testing.expectEqual(@as(u16, 1), msg.header.arcount);

    var parser = MessageParser.init(packet);
    try parser.skipQuestions(msg.header.qdcount);
    const opt = (try parser.findOptRecord(msg.header.arcount)).?;
    try std.testing.expectEqual(@as(u16, 1232), opt.class);
    try std.testing.expectEqual(@as(u16, 0), opt.rdlength); // 无选项
    try std.testing.expect((opt.ttl & 0x8000) == 0); // 未设 DO
}

test "Message.Builder addOptRecord rejects invalid ECS" {
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);
    // IPv4 prefix=24 需 3 字节，但只给 2 字节
    try std.testing.expectError(error.MalformedECS, builder.addOptRecord(.{
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0, .address = &[_]u8{ 192, 0 } },
    }));
    // 失败后应原子回滚：pos 回到初始 header 之后
    try std.testing.expectEqual(@as(usize, 12), builder.pos);
    try std.testing.expectEqual(@as(u16, 0), builder.ar);
}

test "Message.Builder compression verifies bytes on hash collision" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = Message.Builder.init(&buf);

    // 第一条：owner "foo.example" 展开写入（偏移 12），记录压缩项
    try builder.addARecord("foo.example", 60, .{ 1, 1, 1, 1 });

    // 伪造 hash 碰撞：把所有压缩项的 hash 改成 "bar.example" 的 hash，
    // 但它们的 pos 仍指向 "foo.example"/"example"。
    const collide = std.hash.Wyhash.hash(0, "bar.example");
    for (builder.compression_table[0..builder.compression_count]) |*e| e.hash = collide;

    // 第二条：owner "bar.example" —— hash 命中被篡改项，但字节不符，
    // 必须写完整名字而非坏指针（偏移 39 开始）。
    try builder.addARecord("bar.example", 60, .{ 2, 2, 2, 2 });

    const packet = builder.finish(.{
        .id = 1,
        .rd = 0,
        .tc = 0,
        .aa = 1,
        .opcode = 0,
        .qr = 1,
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    });

    var parser = MessageParser.init(packet);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("foo.example", try parser.formatNameAt(12, &nbuf));
    // 若压缩守卫失效，此处会跟随坏指针得到 "foo.example"
    try std.testing.expectEqualStrings("bar.example", try parser.formatNameAt(39, &nbuf));
}

test "Message.Builder addARecord guards final RDATA copy" {
    // "example.com" A 记录需要 39 字节；所有带守卫的写入到 pos=35。
    // 36 字节缓冲区恰好让守卫写入通过，仅最后 4 字节 RDATA 拷贝越界。
    // 修复前：Debug 下 panic，ReleaseFast 下静默越界写。
    var buf: [36]u8 = undefined;
    var builder = Message.Builder.init(&buf);
    try std.testing.expectError(error.BufferTooSmall, builder.addARecord("example.com", 3600, .{ 1, 2, 3, 4 }));
}

test "Message.Builder addAAAARecord guards final RDATA copy" {
    // AAAA RDATA 为 16 字节；48 字节缓冲区让守卫写入通过（到 pos=35），
    // 仅 16 字节 RDATA 拷贝越界 (35+16=51 > 48)。
    var buf: [48]u8 = undefined;
    var builder = Message.Builder.init(&buf);
    const ip = [_]u8{0} ** 16;
    try std.testing.expectError(error.BufferTooSmall, builder.addAAAARecord("example.com", 3600, ip));
}
