const std = @import("std");
const mem = std.mem;
const Header = @import("header.zig").Header;
const Type = @import("types.zig").Type;
const OptionCode = @import("types.zig").OptionCode;
const ECSData = @import("types.zig").ECSData;
const CookieData = @import("types.zig").CookieData;
const Error = @import("errors.zig").Error;
const ResourceRecord = @import("parser.zig").ResourceRecord;
const parseECS = @import("rdata.zig").parseECS;
const parseCookie = @import("rdata.zig").parseCookie;

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
    cookie: ?CookieData = null, // 若设置则写入 COOKIE 选项（RFC 7873）

    /// 从已解析的 OPT 记录解码 EDNS 参数（RFC 6891 §6.1.3）。
    /// CLASS 字段承载 UDP 载荷大小；TTL 承载 扩展 RCODE 高 8 位 / 版本 / flags。
    /// RDATA 中若含 ECS / COOKIE 选项则一并解出（RFC 7871 / 7873）。
    pub fn fromOpt(rr: ResourceRecord) !Edns {
        return .{
            .udp_payload_size = rr.class,
            .extended_rcode = @truncate(rr.ttl >> 24),
            .version = @truncate(rr.ttl >> 16),
            .dnssec_ok = (rr.ttl & 0x8000) != 0,
            .ecs = try parseECS(rr.rdata),
            .cookie = try parseCookie(rr.rdata),
        };
    }
};

/// 核心解析/构造器
pub const Message = struct {
    header: Header,
    buffer: []const u8, // 原始数据引用

    /// 初始化解析 (零分配)
    pub fn parse(raw: []const u8) !Message {
        if (raw.len < 12) return error.PacketTooShort;
        // DNS 报文上限 65535（TCP 长度前缀为 u16；偏移/指针亦以 u16 计）。
        if (raw.len > 0xFFFF) return error.MessageTooLong;
        const header = Header.decode(raw[0..12]);
        return Message{ .header = header, .buffer = raw };
    }

    /// 解析 TCP 组帧报文：2 字节大端长度前缀 + DNS 报文（RFC 1035 4.2.2）。
    /// buffer 引用去除前缀后的 DNS 报文切片（零拷贝）。
    pub fn parseTcp(raw: []const u8) !Message {
        return (try parseTcpFrame(raw)).message;
    }

    pub const TcpFrame = struct { message: Message, frame_len: usize };

    /// 同 parseTcp，但额外返回本帧消耗的总字节数（含 2 字节前缀）。
    /// 供 RFC 7766 单连接多查询（TCP 流水线）时定位下一帧：next = buf[frame_len..]。
    pub fn parseTcpFrame(raw: []const u8) !TcpFrame {
        if (raw.len < 2) return error.PacketTooShort;
        const msg_len = mem.readInt(u16, raw[0..2], .big);
        const frame_len = 2 + @as(usize, msg_len);
        if (raw.len < frame_len) return error.PacketTooShort;
        return .{ .message = try Message.parse(raw[2..frame_len]), .frame_len = frame_len };
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

        pub fn init(dest: []u8) !Builder {
            return initFramed(dest, 0);
        }

        /// 构造 TCP 报文：预留 2 字节长度前缀，DNS 报文写入 dest[2..]，用 finishTcp 收尾。
        pub fn initTcp(dest: []u8) !Builder {
            return initFramed(dest, 2);
        }

        fn initFramed(dest: []u8, prefix_len: usize) !Builder {
            // DNS 报文区必须至少容纳 12 字节 header，否则 finish 回填 header 会越界。
            if (dest.len < prefix_len + 12) return Error.BufferTooSmall;
            // DNS 报文上限 65535（偏移/压缩指针以 u16 计）。即使 dest 更大也把可写区
            // 截到 65535，防止 pos 超过 0xFFFF 时压缩表 pos 的 u16 @intCast 溢出（UB）。
            const avail = @min(dest.len - prefix_len, 0xFFFF);
            return .{
                .buf = dest[prefix_len .. prefix_len + avail],
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

        const Snapshot = struct { pos: usize, compression_count: u8, section: Section };

        fn snapshot(self: *const Builder) Snapshot {
            return .{ .pos = self.pos, .compression_count = self.compression_count, .section = self.section };
        }

        /// 回滚到快照（用于 add* 失败时保持原子性，使截断可安全恢复）。
        /// 包含 section，使 addOptRecord 等先切分区再写入的方法失败后完全原子。
        fn restore(self: *Builder, s: Snapshot) void {
            self.pos = s.pos;
            self.compression_count = s.compression_count;
            self.section = s.section;
        }

        /// 切换当前分区（后续 RR 计入 authority/additional）。分区只能向后推进；
        /// 回退返回 error.InvalidRecordOrder（调用方误用，不做 UB）。
        pub fn setSection(self: *Builder, s: Section) !void {
            if (@intFromEnum(s) < @intFromEnum(self.section)) return Error.InvalidRecordOrder;
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
            try self.writeName(cname); // RFC 1035 允许压缩 CNAME 的 rdata 域名
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
            try self.writeName(exchange); // RFC 1035 允许压缩 MX 的 exchange
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
            try self.writeName(nsdname); // RFC 1035 允许压缩 NS 的 rdata 域名
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
            try self.writeName(ptrdname); // RFC 1035 允许压缩 PTR 的 rdata 域名
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入单个 character-string（1 字节长度前缀 + 内容），内容须 ≤255 字节。
        fn writeCharString(self: *Builder, s: []const u8) !void {
            if (s.len > 255) return Error.LabelTooLong;
            try self.ensureCapacity(1 + s.len);
            self.buf[self.pos] = @intCast(s.len);
            @memcpy(self.buf[self.pos + 1 ..][0..s.len], s);
            self.pos += 1 + s.len;
        }

        /// 写入 TXT 记录（RFC 1035 §3.3.14）。
        /// 将 txt 作为单个逻辑值，自动切分为 ≤255 字节的 character-string；
        /// 空文本写为单个零长 character-string。
        pub fn addTXTRecord(self: *Builder, name: []const u8, ttl: u32, txt: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.TXT));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            if (txt.len == 0) {
                try self.writeCharString("");
            } else {
                var remaining = txt;
                while (remaining.len > 0) {
                    const chunk = @min(remaining.len, 255);
                    try self.writeCharString(remaining[0..chunk]);
                    remaining = remaining[chunk..];
                }
            }
            if (self.pos - rdlen_pos - 2 > 0xFFFF) return Error.MessageTooLong;
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入 TXT 记录，strings 为显式的多个 character-string，每段须 ≤255 字节。
        pub fn addTXTRecordStrings(self: *Builder, name: []const u8, ttl: u32, strings: []const []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.TXT));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            if (strings.len == 0) {
                try self.writeCharString(""); // 至少一段
            } else {
                for (strings) |s| try self.writeCharString(s);
            }
            if (self.pos - rdlen_pos - 2 > 0xFFFF) return Error.MessageTooLong;
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
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
            try self.writeName(mname); // RFC 1035 允许压缩 SOA 的 mname/rname
            try self.writeName(rname);
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
            try self.writeNameRaw(target); // RFC 2782: SRV target 不得压缩
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 通用记录写入（RFC 3597）：type/class 为原始 u16，RDATA 原样写入。
        /// 用于本库未建模的类型、非 IN class、以及需按 RFC 3597 §4 视 RDATA 为不透明
        /// （其中的域名不得压缩）的场景。owner name 仍照常压缩。
        pub fn addRecordRaw(self: *Builder, name: []const u8, rtype: u16, class: u16, ttl: u32, rdata: []const u8) !void {
            if (rdata.len > 0xFFFF) return Error.MessageTooLong;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(rtype);
            try self.writeU16(class);
            try self.writeU32(ttl);
            try self.writeU16(@intCast(rdata.len));
            try self.ensureCapacity(rdata.len);
            @memcpy(self.buf[self.pos..][0..rdata.len], rdata);
            self.pos += rdata.len;
            self.countRecord();
        }

        /// 写入 CAA 记录（RFC 8659）。tag 须为 1..255 字节，value 原样写入。
        pub fn addCAARecord(self: *Builder, name: []const u8, ttl: u32, flags: u8, tag: []const u8, value: []const u8) !void {
            if (tag.len == 0) return Error.InvalidRData;
            if (tag.len > 255) return Error.LabelTooLong;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.CAA));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen = 2 + tag.len + value.len;
            if (rdlen > 0xFFFF) return Error.MessageTooLong;
            try self.writeU16(@intCast(rdlen));
            try self.writeU8(flags);
            try self.writeU8(@intCast(tag.len));
            try self.ensureCapacity(tag.len + value.len);
            @memcpy(self.buf[self.pos..][0..tag.len], tag);
            self.pos += tag.len;
            @memcpy(self.buf[self.pos..][0..value.len], value);
            self.pos += value.len;
            self.countRecord();
        }

        /// 写入 SVCB 记录（RFC 9460）。target 不压缩；params 为预编码的 SvcParams 原始字节。
        pub fn addSVCBRecord(self: *Builder, name: []const u8, ttl: u32, priority: u16, target: []const u8, params: []const u8) !void {
            return self.addSvcbLike(Type.SVCB, name, ttl, priority, target, params);
        }

        /// 写入 HTTPS 记录（RFC 9460，与 SVCB 同格式）。target 不压缩；params 为原始字节。
        pub fn addHTTPSRecord(self: *Builder, name: []const u8, ttl: u32, priority: u16, target: []const u8, params: []const u8) !void {
            return self.addSvcbLike(Type.HTTPS, name, ttl, priority, target, params);
        }

        fn addSvcbLike(self: *Builder, rtype: Type, name: []const u8, ttl: u32, priority: u16, target: []const u8, params: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(rtype));
            try self.writeU16(1); // Class IN
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0); // 占位 RDLength
            try self.writeU16(priority);
            try self.writeNameRaw(target); // RFC 9460 §2.2: TargetName 不得压缩
            try self.ensureCapacity(params.len);
            @memcpy(self.buf[self.pos..][0..params.len], params);
            self.pos += params.len;
            if (self.pos - rdlen_pos - 2 > 0xFFFF) return Error.MessageTooLong;
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入 NSEC/NSEC3 类型位图（RFC 4034 §4.1.2）。types 须为严格升序去重——
        /// 否则窗口分组与位图长度推算失效，会越界写并发出损坏位图，故先校验。
        fn writeTypeBitmap(self: *Builder, types: []const u16) !void {
            if (types.len > 1) {
                for (types[1..], types[0 .. types.len - 1]) |cur, prev| {
                    if (cur <= prev) return Error.InvalidRecordOrder;
                }
            }
            var i: usize = 0;
            while (i < types.len) {
                const window: u8 = @intCast(types[i] >> 8);
                var j = i;
                var max_off: usize = 0;
                while (j < types.len and types[j] >> 8 == window) : (j += 1) {
                    max_off = types[j] & 0xFF; // 升序 -> 窗口内末项即最大
                }
                const blen = max_off / 8 + 1;
                try self.ensureCapacity(2 + blen);
                self.buf[self.pos] = window;
                self.buf[self.pos + 1] = @intCast(blen);
                const bstart = self.pos + 2;
                @memset(self.buf[bstart..][0..blen], 0);
                var k = i;
                while (k < j) : (k += 1) {
                    const off = types[k] & 0xFF;
                    self.buf[bstart + off / 8] |= @as(u8, 0x80) >> @intCast(off % 8);
                }
                self.pos += 2 + blen;
                i = j;
            }
        }

        /// 写入 DNSKEY 记录（RFC 4034）。
        pub fn addDNSKEYRecord(self: *Builder, name: []const u8, ttl: u32, flags: u16, protocol: u8, algorithm: u8, public_key: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.DNSKEY));
            try self.writeU16(1);
            try self.writeU32(ttl);
            const rdlen = 4 + public_key.len;
            if (rdlen > 0xFFFF) return Error.MessageTooLong;
            try self.writeU16(@intCast(rdlen));
            try self.writeU16(flags);
            try self.writeU8(protocol);
            try self.writeU8(algorithm);
            try self.ensureCapacity(public_key.len);
            @memcpy(self.buf[self.pos..][0..public_key.len], public_key);
            self.pos += public_key.len;
            self.countRecord();
        }

        /// 写入 DS 记录（RFC 4034）。
        pub fn addDSRecord(self: *Builder, name: []const u8, ttl: u32, key_tag: u16, algorithm: u8, digest_type: u8, digest: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.DS));
            try self.writeU16(1);
            try self.writeU32(ttl);
            const rdlen = 4 + digest.len;
            if (rdlen > 0xFFFF) return Error.MessageTooLong;
            try self.writeU16(@intCast(rdlen));
            try self.writeU16(key_tag);
            try self.writeU8(algorithm);
            try self.writeU8(digest_type);
            try self.ensureCapacity(digest.len);
            @memcpy(self.buf[self.pos..][0..digest.len], digest);
            self.pos += digest.len;
            self.countRecord();
        }

        pub const Rrsig = struct {
            type_covered: u16,
            algorithm: u8,
            labels: u8,
            original_ttl: u32,
            expiration: u32,
            inception: u32,
            key_tag: u16,
            signer: []const u8,
            signature: []const u8,
        };

        /// 写入 RRSIG 记录（RFC 4034）。signer name 不压缩；signature 原样写入。
        pub fn addRRSIGRecord(self: *Builder, name: []const u8, ttl: u32, sig: Rrsig) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.RRSIG));
            try self.writeU16(1);
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0);
            try self.writeU16(sig.type_covered);
            try self.writeU8(sig.algorithm);
            try self.writeU8(sig.labels);
            try self.writeU32(sig.original_ttl);
            try self.writeU32(sig.expiration);
            try self.writeU32(sig.inception);
            try self.writeU16(sig.key_tag);
            try self.writeNameRaw(sig.signer); // RFC 4034 §3.1.7: 不得压缩
            try self.ensureCapacity(sig.signature.len);
            @memcpy(self.buf[self.pos..][0..sig.signature.len], sig.signature);
            self.pos += sig.signature.len;
            if (self.pos - rdlen_pos - 2 > 0xFFFF) return Error.MessageTooLong;
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], @intCast(self.pos - rdlen_pos - 2), .big);
            self.countRecord();
        }

        /// 写入 NSEC 记录（RFC 4034）。next_domain 不压缩；types 须升序去重。
        pub fn addNSECRecord(self: *Builder, name: []const u8, ttl: u32, next_domain: []const u8, types: []const u16) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.NSEC));
            try self.writeU16(1);
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0);
            try self.writeNameRaw(next_domain); // RFC 4034 §4.1.1: 不压缩
            try self.writeTypeBitmap(types);
            if (self.pos - rdlen_pos - 2 > 0xFFFF) return Error.MessageTooLong;
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], @intCast(self.pos - rdlen_pos - 2), .big);
            self.countRecord();
        }

        /// 写入 NSEC3PARAM 记录（RFC 5155）。salt 须 ≤255 字节。
        pub fn addNSEC3PARAMRecord(self: *Builder, name: []const u8, ttl: u32, hash_algorithm: u8, flags: u8, iterations: u16, salt: []const u8) !void {
            if (salt.len > 255) return Error.InvalidRData;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.NSEC3PARAM));
            try self.writeU16(1);
            try self.writeU32(ttl);
            try self.writeU16(@intCast(5 + salt.len));
            try self.writeU8(hash_algorithm);
            try self.writeU8(flags);
            try self.writeU16(iterations);
            try self.writeU8(@intCast(salt.len));
            try self.ensureCapacity(salt.len);
            @memcpy(self.buf[self.pos..][0..salt.len], salt);
            self.pos += salt.len;
            self.countRecord();
        }

        pub const Nsec3 = struct {
            hash_algorithm: u8,
            flags: u8,
            iterations: u16,
            salt: []const u8,
            next_hashed_owner: []const u8,
            types: []const u16, // 升序去重
        };

        /// 写入 NSEC3 记录（RFC 5155）。salt 与 next_hashed_owner 均须 ≤255 字节；types 须升序。
        pub fn addNSEC3Record(self: *Builder, name: []const u8, ttl: u32, n3: Nsec3) !void {
            if (n3.salt.len > 255 or n3.next_hashed_owner.len > 255) return Error.InvalidRData;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(name);
            try self.writeU16(@intFromEnum(Type.NSEC3));
            try self.writeU16(1);
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0);
            try self.writeU8(n3.hash_algorithm);
            try self.writeU8(n3.flags);
            try self.writeU16(n3.iterations);
            try self.writeU8(@intCast(n3.salt.len));
            try self.ensureCapacity(n3.salt.len);
            @memcpy(self.buf[self.pos..][0..n3.salt.len], n3.salt);
            self.pos += n3.salt.len;
            try self.writeU8(@intCast(n3.next_hashed_owner.len));
            try self.ensureCapacity(n3.next_hashed_owner.len);
            @memcpy(self.buf[self.pos..][0..n3.next_hashed_owner.len], n3.next_hashed_owner);
            self.pos += n3.next_hashed_owner.len;
            try self.writeTypeBitmap(n3.types);
            if (self.pos - rdlen_pos - 2 > 0xFFFF) return Error.MessageTooLong;
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], @intCast(self.pos - rdlen_pos - 2), .big);
            self.countRecord();
        }

        /// 写入 Question（必须先于所有 RR 添加）
        pub fn addQuestion(self: *Builder, qname: []const u8, qtype: Type, qclass: u16) !void {
            if (self.an != 0 or self.ns != 0 or self.ar != 0) return Error.InvalidRecordOrder;
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
            const snap = self.snapshot(); // 先快照（含 section），失败可完全回滚
            errdefer self.restore(snap);
            try self.setSection(.additional);

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
            if (edns.cookie) |cookie| try self.writeCookieOption(cookie);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 低级：写入 OPT 记录，options 为调用方自行编码的完整 RDATA。
        pub fn addOptRecordRaw(self: *Builder, udp_payload_size: u16, ttl: u32, options: []const u8) !void {
            if (options.len > 0xFFFF) return Error.MessageTooLong;
            const snap = self.snapshot(); // 先快照（含 section），失败可完全回滚
            errdefer self.restore(snap);
            try self.setSection(.additional);

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
            if (ecs.source_prefix > max_prefix or ecs.scope_prefix > max_prefix) return Error.MalformedECS;
            const addr_len = (@as(usize, ecs.source_prefix) + 7) / 8;
            if (ecs.address.len < addr_len) return Error.MalformedECS;

            try self.writeU16(@intFromEnum(OptionCode.ECS));
            try self.writeU16(@intCast(4 + addr_len)); // OPTION-LENGTH
            try self.writeU16(ecs.family);
            try self.writeU8(ecs.source_prefix);
            try self.writeU8(ecs.scope_prefix);
            try self.ensureCapacity(addr_len);
            @memcpy(self.buf[self.pos..][0..addr_len], ecs.address[0..addr_len]);
            // RFC 7871 §7.1.3: 超出 source_prefix 的地址位必须为 0（MUST）。
            if (addr_len > 0) {
                const rem: u3 = @intCast(ecs.source_prefix % 8);
                if (rem != 0) self.buf[self.pos + addr_len - 1] &= @as(u8, 0xFF) << @intCast(8 - @as(u4, rem));
            }
            self.pos += addr_len;
        }

        /// 写入 COOKIE 选项 TLV（RFC 7873）。server cookie 须为空或 8..32 字节。
        fn writeCookieOption(self: *Builder, cookie: CookieData) !void {
            if (cookie.server.len != 0 and (cookie.server.len < 8 or cookie.server.len > 32)) return Error.MalformedCookie;
            const opt_len = 8 + cookie.server.len;
            try self.writeU16(@intFromEnum(OptionCode.COOKIE));
            try self.writeU16(@intCast(opt_len)); // OPTION-LENGTH
            try self.ensureCapacity(opt_len);
            @memcpy(self.buf[self.pos..][0..8], &cookie.client);
            self.pos += 8;
            @memcpy(self.buf[self.pos..][0..cookie.server.len], cookie.server);
            self.pos += cookie.server.len;
        }

        /// 写入一串点分标签（不含结束符），每个标签带 1 字节长度前缀。
        /// canonical 必须已通过 validateName（无空标签 / 无首尾点）。
        fn writeLabels(self: *Builder, canonical: []const u8) !void {
            var it = mem.splitScalar(u8, canonical, '.');
            while (it.next()) |label| {
                try self.ensureCapacity(1 + label.len);
                self.buf[self.pos] = @intCast(label.len);
                @memcpy(self.buf[self.pos + 1 ..][0..label.len], label);
                self.pos += 1 + label.len;
            }
        }

        /// 写入域名，支持压缩指针（含共享后缀压缩）。
        fn writeName(self: *Builder, name: []const u8) !void {
            if (name.len == 0 or mem.eql(u8, name, ".")) {
                try self.ensureCapacity(1);
                self.buf[self.pos] = 0;
                self.pos += 1;
                return;
            }

            const analyzed = try analyzeName(name);
            const canonical = analyzed.canonical;

            // 从最长后缀（整名）开始逐段缩短，寻找压缩表中已写入的可复用后缀。
            // 命中后写「前缀标签 + 指向该后缀的指针」；hash 命中须字节级确认防碰撞。
            if (self.compression_count > 0) {
                var s: usize = 0;
                while (true) {
                    const suffix = canonical[s..];
                    const suffix_hash = if (s == 0) analyzed.hash else std.hash.Wyhash.hash(0, suffix);
                    for (self.compression_table[0..self.compression_count]) |entry| {
                        // 14 位指针可寻址偏移 0..=0x3FFF（含 0x3FFF）。
                        if (entry.hash == suffix_hash and entry.pos <= 0x3FFF and self.nameMatchesAt(entry.pos, suffix)) {
                            if (s > 0) try self.writeLabels(canonical[0 .. s - 1]); // 后缀前的前缀标签（去掉分隔点）
                            try self.ensureCapacity(2);
                            self.buf[self.pos] = 0xC0 | @as(u8, @intCast(entry.pos >> 8));
                            self.buf[self.pos + 1] = @as(u8, @intCast(entry.pos & 0xFF));
                            self.pos += 2;
                            return;
                        }
                    }
                    const next_dot = mem.indexOfScalar(u8, canonical[s..], '.') orelse break;
                    s += next_dot + 1;
                }
            }

            // 无可复用后缀：写完整域名并把其各后缀记入压缩表。
            const start = self.pos;
            try self.writeLabels(canonical);
            try self.ensureCapacity(1);
            self.buf[self.pos] = 0;
            self.pos += 1;

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

        /// 写入完整展开、不压缩的域名（用于 RFC 2782 规定不得压缩的 SRV target）。
        fn writeNameRaw(self: *Builder, name: []const u8) !void {
            if (name.len == 0 or mem.eql(u8, name, ".")) {
                try self.ensureCapacity(1);
                self.buf[self.pos] = 0;
                self.pos += 1;
                return;
            }

            const canonical = try validateName(name);
            try self.writeLabels(canonical);
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
            if (self.prefix_len != 2) return Error.InvalidRecordOrder; // 须由 initTcp 创建
            const msg = self.finish(header);
            if (msg.len > 0xFFFF) return Error.MessageTooLong;
            mem.writeInt(u16, self.dest[0..2], @intCast(msg.len), .big);
            return self.dest[0 .. 2 + msg.len];
        }
    };
};

test "Message.Builder caps effective buffer at 65535 even with larger dest" {
    // DNS 报文上限 65535；偏移/压缩指针以 u16 计。即使调用方给了 >64KB 缓冲区，
    // 写入也必须止于 65535，否则压缩表 pos 的 u16 @intCast 会 panic/UB。
    const dest = try std.testing.allocator.alloc(u8, 70000);
    defer std.testing.allocator.free(dest);
    var builder = try Message.Builder.init(dest);
    const big = try std.testing.allocator.alloc(u8, 65530);
    defer std.testing.allocator.free(big);
    @memset(big, 0);
    // 该记录会使 pos 超过 65535 -> 必须以 BufferTooSmall 拒绝，而非成功写入。
    try std.testing.expectError(error.BufferTooSmall, builder.addRecordRaw("", 1, 1, 0, big));
}

test "Message.Builder.init rejects buffer too small for header" {
    // 缓冲区不足 12 字节无法容纳 header；init 必须报错而非在 finish 时越界写。
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, Message.Builder.init(&buf));
}

test "Message.Builder setSection rejects backward move" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.setSection(.additional);
    // 分区只能向后推进；回退是调用方误用，须返回 error 而非 UB。
    try std.testing.expectError(error.InvalidRecordOrder, builder.setSection(.authority));
}

test "Message.Builder addQuestion after answer returns error" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addARecord("example.com", 60, .{ 1, 2, 3, 4 });
    // Question 必须先于所有 RR；晚加是误用，须返回 error 而非 UB。
    try std.testing.expectError(error.InvalidRecordOrder, builder.addQuestion("example.com", .A, 1));
}

test "Message.Builder addQuestion" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    try builder.addQuestion("example.com", .A, 1);

    const header = Header{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 1, .ancount = 0, .nscount = 0, .arcount = 0 };
    const packet = builder.finish(header);

    // 验证: Header(12) + Name(13) + Type(2) + Class(2) = 29
    try std.testing.expectEqual(@as(usize, 29), packet.len);
}

test "Message.Builder addARecord" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });

    const header = Header{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 1, .nscount = 0, .arcount = 0 };
    const packet = builder.finish(header);

    // 12(header) + 13(name) + 2(type) + 2(class) + 4(ttl) + 2(rdlen) + 4(rdata) = 39
    try std.testing.expectEqual(@as(usize, 39), packet.len);
}

test "Message.Builder compression pointer" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // 写入相同域名两次，第二次应使用压缩指针
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });
    const pos1 = builder.pos;
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 2 });
    const pos2 = builder.pos;

    // 第二次写入应短 11 字节 (压缩指针 2 字节 vs 完整域名 13 字节)
    // 2(ptr) + 2+2+4+2+4 = 16 vs 13(name) + 2+2+4+2+4 = 27，差 11
    try std.testing.expectEqual(@as(usize, 16), pos2 - pos1);
}

test "Message.Builder compresses shared suffix" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // 第一条 owner "example.com" 展开写入（偏移 12）。
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });
    // 第二条 owner "www.example.com" 应压缩共享后缀：写 "www" 标签 + 指向 example.com 的指针。
    const pos1 = builder.pos;
    const name2_off = pos1;
    try builder.addARecord("www.example.com", 3600, [_]u8{ 192, 0, 2, 2 });
    const pos2 = builder.pos;

    // owner 名字应为 "www"(4) + 指针(2) = 6 字节，而非完整 17 字节。
    // 记录其余固定部分 2+2+4+2+4 = 14 字节。
    try std.testing.expectEqual(@as(usize, 6 + 14), pos2 - pos1);

    // 且必须能正确解析回完整域名。
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
    try std.testing.expectEqualStrings("example.com", try parser.formatNameAt(12, &nbuf));
    try std.testing.expectEqualStrings("www.example.com", try parser.formatNameAt(name2_off, &nbuf));
}

test "Message.Builder compresses shorter shared suffix (com)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // "example.com" 展开写入，表中含 example.com@12 与 com@20。
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });
    // "other.com" 与前者仅共享 "com"：整名/次长后缀均不匹配，应缩短到 "com" 命中。
    const name2_off = builder.pos;
    const pos1 = builder.pos;
    try builder.addARecord("other.com", 3600, [_]u8{ 192, 0, 2, 2 });
    const pos2 = builder.pos;

    // owner = "other"(6) + 指向 com 的指针(2) = 8 字节；其余固定 14 字节。
    try std.testing.expectEqual(@as(usize, 8 + 14), pos2 - pos1);

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
    try std.testing.expectEqualStrings("other.com", try parser.formatNameAt(name2_off, &nbuf));
}

test "Message.Builder compresses NS rdata name (RFC 1035 type)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // owner "example.com" 写在偏移 12 并入表；NS rdata "ns1.example.com"
    // 应压缩共享后缀 -> "ns1"(4) + 指向 example.com 的指针(2) = 6 字节。
    try builder.setSection(.authority);
    try builder.addNSRecord("example.com", 3600, "ns1.example.com");

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
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    try std.testing.expectEqual(@as(u16, 6), rr.rdlength); // 压缩后仅 6 字节

    const rdata = try parser.parseRData(rr);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("ns1.example.com", try rdata.NS.str(&nbuf));
}

test "Message.Builder does not compress SRV target (RFC 2782)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // 先写 A 记录令 "example.com" 入表；SRV target 与之共享后缀，
    // 但 RFC 2782 规定 SRV target 不得压缩 -> 必须完整展开。
    try builder.addARecord("example.com", 3600, .{ 1, 2, 3, 4 });
    try builder.setSection(.authority);
    try builder.addSRVRecord("service.example.com", 3600, 10, 20, 5060, "sipserver.example.com");

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
    try parser.skipResourceRecords(1); // 跳过 A 记录
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    // rdata = prio/weight/port(6) + 完整 "sipserver.example.com"(23) = 29，未压缩
    try std.testing.expectEqual(@as(u16, 29), rr.rdlength);

    const rdata = try parser.parseRData(rr);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("sipserver.example.com", try rdata.SRV.target.str(&nbuf));
}

test "Message.Builder addTXTRecord auto-splits long text into character-strings" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [1024]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // 300 字节文本 -> 必须切成 255 + 45 两段（RFC 1035 §3.3.14）。
    var long: [300]u8 = undefined;
    @memset(&long, 'x');
    try builder.addTXTRecord("example.com", 60, &long);

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    const rdata = try parser.parseRData(rr);
    var it = rdata.TXT.iterator();
    try std.testing.expectEqual(@as(usize, 255), (try it.next()).?.len);
    try std.testing.expectEqual(@as(usize, 45), (try it.next()).?.len);
    try std.testing.expect((try it.next()) == null);
}

test "Message.Builder addTXTRecordStrings writes explicit multiple strings" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    try builder.addTXTRecordStrings("example.com", 60, &[_][]const u8{ "v=spf1", "include:_spf.example.com" });

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    const rdata = try parser.parseRData(rr);
    var it = rdata.TXT.iterator();
    try std.testing.expectEqualStrings("v=spf1", (try it.next()).?);
    try std.testing.expectEqualStrings("include:_spf.example.com", (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "Message.Builder addTXTRecordStrings rejects segment over 255 bytes" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    var big: [256]u8 = undefined;
    @memset(&big, 'a');
    try std.testing.expectError(error.LabelTooLong, builder.addTXTRecordStrings("example.com", 60, &[_][]const u8{&big}));
}

test "Message.Builder addRecordRaw writes unknown type verbatim (RFC 3597)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // CAA (type 257) 尚未在本库建模；服务器须能原样服务其 RDATA（RFC 3597 §3）。
    const caa_rdata = [_]u8{ 0x00, 0x05, 'i', 's', 's', 'u', 'e' };
    try builder.addRecordRaw("example.com", 257, 1, 3600, &caa_rdata);

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    try std.testing.expectEqual(@as(u16, 257), @intFromEnum(rr.rtype));
    try std.testing.expectEqual(@as(u16, 1), rr.class);
    try std.testing.expectEqual(@as(u32, 3600), rr.ttl);
    try std.testing.expectEqualSlices(u8, &caa_rdata, rr.rdata);
}

test "Message.Builder addRecordRaw supports non-IN class (CH)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // CH TXT version.bind 这类查询需要非 IN class。class=3 (CH), type=16 (TXT)。
    try builder.addRecordRaw("version.bind", 16, 3, 0, "\x08zigdns/1");

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    try std.testing.expectEqual(@as(u16, 3), rr.class); // CH
    try std.testing.expectEqual(@as(u16, 16), @intFromEnum(rr.rtype));
}

test "Message.Builder addCAARecord round-trips (RFC 8659)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addCAARecord("example.com", 3600, 0, "issue", "ca.example.net");

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    try std.testing.expectEqual(@as(u16, 257), @intFromEnum(rr.rtype));
    const rd = try parser.parseRData(rr);
    try std.testing.expectEqual(@as(u8, 0), rd.CAA.flags);
    try std.testing.expectEqualStrings("issue", rd.CAA.tag);
    try std.testing.expectEqualStrings("ca.example.net", rd.CAA.value);
}

test "Message.Builder addCAARecord rejects empty/oversized tag" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try std.testing.expectError(error.InvalidRData, builder.addCAARecord("example.com", 3600, 0, "", "x"));
    var big: [256]u8 = undefined;
    @memset(&big, 'a');
    try std.testing.expectError(error.LabelTooLong, builder.addCAARecord("example.com", 3600, 0, &big, "x"));
}

test "Message.Builder addHTTPSRecord round-trips with uncompressed target (RFC 9460)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    // 先写一条同后缀 A 记录，验证 SVCB/HTTPS target 不被压缩。
    try builder.addARecord("example.com", 60, .{ 1, 2, 3, 4 });
    // SvcParams: key=3(port) len=2 value=443
    const params = "\x00\x03\x00\x02\x01\xBB";
    try builder.addHTTPSRecord("example.com", 3600, 1, "svc.example.com", params);

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    try parser.skipResourceRecords(1); // 跳过 A
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    try std.testing.expectEqual(@as(u16, 65), @intFromEnum(rr.rtype));
    const rd = try parser.parseRData(rr);
    try std.testing.expectEqual(@as(u16, 1), rd.HTTPS.priority);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("svc.example.com", try rd.HTTPS.target.str(&nbuf));
    var it = rd.HTTPS.iterator();
    const p = (try it.next()).?;
    try std.testing.expectEqual(@as(u16, 3), p.key);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0xBB }, p.value);
}

test "Message.Builder addDNSKEYRecord round-trips and links via keyTag" {
    const MessageParser = @import("parser.zig").MessageParser;
    const keyTag = @import("rdata.zig").keyTag;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addDNSKEYRecord("example.com", 3600, 257, 3, 8, "ABCD");
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    try std.testing.expectEqual(@as(u16, 48), @intFromEnum(rr.rtype));
    const rd = try parser.parseRData(rr);
    try std.testing.expectEqual(@as(u16, 257), rd.DNSKEY.flags);
    try std.testing.expectEqualStrings("ABCD", rd.DNSKEY.public_key);
    // key tag 由整段 RDATA 计算，应与手工核算一致
    try std.testing.expectEqual(keyTag("\x01\x01\x03\x08ABCD"), keyTag(rr.rdata));
}

test "Message.Builder addDSRecord round-trips" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addDSRecord("example.com", 3600, 0x3039, 8, 2, "\xde\xad\xbe\xef");
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rd = try parser.parseRData((try rrs.next()).?);
    try std.testing.expectEqual(@as(u16, 0x3039), rd.DS.key_tag);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, rd.DS.digest);
}

test "Message.Builder addRRSIGRecord keeps signer uncompressed (RFC 4034)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    // 先写同后缀 A 记录令 example.com 入压缩表，验证 signer 不被压缩。
    try builder.addARecord("example.com", 60, .{ 1, 2, 3, 4 });
    try builder.addRRSIGRecord("example.com", 3600, .{
        .type_covered = 1,
        .algorithm = 8,
        .labels = 2,
        .original_ttl = 3600,
        .expiration = 0x5f000000,
        .inception = 0x5e000000,
        .key_tag = 0x3039,
        .signer = "example.com",
        .signature = "SIG!",
    });
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    try parser.skipResourceRecords(1);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    const rd = try parser.parseRData(rr);
    try std.testing.expectEqual(@as(u16, 1), rd.RRSIG.type_covered);
    try std.testing.expectEqual(@as(u16, 0x3039), rd.RRSIG.key_tag);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", try rd.RRSIG.signer.str(&nbuf));
    try std.testing.expectEqualStrings("SIG!", rd.RRSIG.signature);
    // signer 未压缩：signer(13) + signature(4) = 17；固定字段 18 -> rdlen 35
    try std.testing.expectEqual(@as(u16, 35), rr.rdlength);
}

test "Message.Builder addNSECRecord rejects unsorted types (guards OOB)" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    // 未排序输入若不校验会越界写并发出损坏位图；必须报错。
    try std.testing.expectError(error.InvalidRecordOrder, builder.addNSECRecord("example.com", 3600, "a.example.com", &[_]u16{ 47, 1 }));
    // 重复类型同样非法（须严格升序）。
    try std.testing.expectError(error.InvalidRecordOrder, builder.addNSECRecord("example.com", 3600, "a.example.com", &[_]u16{ 1, 1 }));
}

test "Message.Builder addNSECRecord writes type bitmap (RFC 4034)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    // 类型须升序：A(1), MX(15), RRSIG(46), NSEC(47)
    try builder.addNSECRecord("example.com", 3600, "a.example.com", &[_]u16{ 1, 15, 46, 47 });
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rd = try parser.parseRData((try rrs.next()).?);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("a.example.com", try rd.NSEC.next_domain.str(&nbuf));
    var it = rd.NSEC.types.iterator();
    try std.testing.expectEqual(@as(u16, 1), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 15), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 46), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 47), (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "Message.Builder addNSEC3Record and addNSEC3PARAMRecord round-trip (RFC 5155)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addNSEC3PARAMRecord("example.com", 0, 1, 0, 10, "\xaa\xbb\xcc\xdd");
    try builder.addNSEC3Record("example.com", 3600, .{
        .hash_algorithm = 1,
        .flags = 1,
        .iterations = 10,
        .salt = "\xaa\xbb\xcc\xdd",
        .next_hashed_owner = "\x01\x02\x03\x04\x05",
        .types = &[_]u16{ 1, 15 },
    });
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(2);
    const rd1 = try parser.parseRData((try rrs.next()).?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }, rd1.NSEC3PARAM.salt);
    const rd2 = try parser.parseRData((try rrs.next()).?);
    try std.testing.expectEqual(@as(u16, 10), rd2.NSEC3.iterations);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5 }, rd2.NSEC3.next_hashed_owner);
    var it = rd2.NSEC3.types.iterator();
    try std.testing.expectEqual(@as(u16, 1), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 15), (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "Message.Builder addMXRecord" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    try builder.addMXRecord("example.com", 3600, 10, "mail.example.com");

    const header = Header{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 1, .nscount = 0, .arcount = 0 };
    const packet = builder.finish(header);

    // exchange "mail.example.com" 压缩共享后缀 -> "mail"(5) + 指针(2) = 7（而非完整 18）。
    // 12 + 13 (example.com) + 10 (fixed) + 2 (pref) + 7 (mail + ptr) = 44
    try std.testing.expectEqual(@as(usize, 44), packet.len);

    // 压缩后仍能正确解析 exchange 域名。
    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(1);
    const rr = (try rrs.next()).?;
    const rdata = try parser.parseRData(rr);
    try std.testing.expectEqual(@as(u16, 10), rdata.MX.preference);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("mail.example.com", try rdata.MX.exchange.str(&nbuf));
}

test "Message.Builder returns BufferTooSmall on short destination" {
    var buf: [20]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    try std.testing.expectError(error.BufferTooSmall, builder.addQuestion("example.com", .A, 1));
}

test "Message.Builder finish auto-counts sections" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    try builder.addQuestion("example.com", .A, 1);
    try builder.addARecord("example.com", 60, .{ 1, 2, 3, 4 });
    try builder.addARecord("example.com", 60, .{ 5, 6, 7, 8 });
    try builder.setSection(.authority);
    try builder.addNSRecord("example.com", 60, "ns1.example.com");
    try builder.setSection(.additional);
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
    var builder = try Message.Builder.init(&buf);

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

test "Message.Builder finishTcp on UDP builder returns error (no UB)" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf); // UDP: prefix_len=0
    try builder.addQuestion("example.com", .A, 1);
    const h = Header{ .id = 1, .rd = 0, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 };
    try std.testing.expectError(error.InvalidRecordOrder, builder.finishTcp(h));
}

test "Message.Builder failed addOptRecord restores section (atomicity)" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    // 坏 ECS 使 addOptRecord 失败；它内部已切到 additional，须原子回滚 section。
    try std.testing.expectError(error.MalformedECS, builder.addOptRecord(.{
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0, .address = &[_]u8{ 192, 0 } },
    }));
    // 若 section 未回滚（卡在 additional），此处会 InvalidRecordOrder。
    try builder.setSection(.authority);
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

test "Message.parse rejects buffer larger than 65535 (DNS message max)" {
    const big = try std.testing.allocator.alloc(u8, 65536);
    defer std.testing.allocator.free(big);
    @memset(big, 0);
    try std.testing.expectError(error.MessageTooLong, Message.parse(big));
}

test "Message.parseTcpFrame reports frame length for TCP pipelining (RFC 7766)" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.initTcp(&buf);
    try builder.addQuestion("example.com", .A, 1);
    const frame = try builder.finishTcp(.{ .id = 0x1234, .rd = 0, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    // 模拟同一 TCP 流里 frame 之后紧跟另一条报文的字节。
    var stream: [600]u8 = undefined;
    @memcpy(stream[0..frame.len], frame);
    stream[frame.len] = 0xAB; // 下一条报文的起始字节（不应被本次消费）

    const parsed = try Message.parseTcpFrame(stream[0 .. frame.len + 1]);
    try std.testing.expectEqual(frame.len, parsed.frame_len);
    try std.testing.expectEqual(@as(u16, 0x1234), parsed.message.header.id);
}

test "Message.Builder compresses name at maximum pointer offset 0x3FFF" {
    const MessageParser = @import("parser.zig").MessageParser;
    const dest = try std.testing.allocator.alloc(u8, 17000);
    defer std.testing.allocator.free(dest);
    var builder = try Message.Builder.init(dest);

    // 用一条 root-owner 记录把 pos 精确推进到 0x3FFF=16383。
    // pos: 12 -> writeName("")=+1 -> +10 固定 -> +rdlen。令 23+rdlen=16383。
    const filler = try std.testing.allocator.alloc(u8, 16360);
    defer std.testing.allocator.free(filler);
    @memset(filler, 0);
    try builder.addRecordRaw("", 1, 1, 0, filler);
    try std.testing.expectEqual(@as(usize, 16383), builder.pos);

    // owner "a.bc" 写在偏移 16383（可被 14 位指针寻址）。
    try builder.addARecord("a.bc", 60, .{ 1, 2, 3, 4 });
    // 第二次同名：必须压缩为指向 16383 的指针，而非写完整域名。
    const pos1 = builder.pos;
    try builder.addARecord("a.bc", 60, .{ 5, 6, 7, 8 });
    const delta = builder.pos - pos1;
    // 压缩 owner(2) + 固定 14 = 16；未压缩会是 owner(6)+14 = 20。
    try std.testing.expectEqual(@as(usize, 16), delta);

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("a.bc", try parser.formatNameAt(16383, &nbuf));
}

test "Message.parseTcp rejects truncated frame" {
    // 前缀声称 100 字节，实际不足
    var buf: [10]u8 = undefined;
    mem.writeInt(u16, buf[0..2], 100, .big);
    try std.testing.expectError(error.PacketTooShort, Message.parseTcp(&buf));
}

test "Message.Builder addOptRecord with cookie round-trips (RFC 7873)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{
        .udp_payload_size = 1232,
        .cookie = .{ .client = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .server = "\xaa\xbb\xcc\xdd\xee\xff\x11\x22" },
    });
    const packet = builder.finish(.{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    try parser.skipQuestions(1);
    const cookie = (try parser.findCookie(1)).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &cookie.client);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 }, cookie.server);
}

test "Message.Builder addOptRecord with client-only cookie" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{ .cookie = .{ .client = .{ 8, 7, 6, 5, 4, 3, 2, 1 }, .server = "" } });
    const packet = builder.finish(.{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    try parser.skipQuestions(1);
    const cookie = (try parser.findCookie(1)).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 8, 7, 6, 5, 4, 3, 2, 1 }, &cookie.client);
    try std.testing.expectEqual(@as(usize, 0), cookie.server.len);
}

test "Message.Builder addOptRecord rejects invalid server cookie length" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    // server cookie 4 字节：非空但 <8，非法（RFC 7873）
    try std.testing.expectError(error.MalformedCookie, builder.addOptRecord(.{
        .cookie = .{ .client = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .server = "\x01\x02\x03\x04" },
    }));
}

test "Edns.fromOpt decodes cookie alongside ECS" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0, .address = &[_]u8{ 192, 0, 2 } },
        .cookie = .{ .client = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .server = "" },
    });
    const packet = builder.finish(.{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    try parser.skipQuestions(1);
    const opt = (try parser.findOptRecord(1)).?;
    const edns = try Edns.fromOpt(opt);
    try std.testing.expectEqual(@as(u16, 1), edns.ecs.?.family);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &edns.cookie.?.client);
}

test "Edns.fromOpt decodes payload size, version, DO flag and ECS" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{
        .udp_payload_size = 4096,
        .dnssec_ok = true,
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0, .address = &[_]u8{ 192, 0, 2 } },
    });
    const packet = builder.finish(.{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    const msg = try Message.parse(packet);
    var parser = MessageParser.init(packet);
    try parser.skipQuestions(msg.header.qdcount);
    const opt = (try parser.findOptRecord(msg.header.arcount)).?;

    const edns = try Edns.fromOpt(opt);
    try std.testing.expectEqual(@as(u16, 4096), edns.udp_payload_size);
    try std.testing.expectEqual(@as(u8, 0), edns.version);
    try std.testing.expectEqual(@as(u8, 0), edns.extended_rcode);
    try std.testing.expect(edns.dnssec_ok);
    try std.testing.expectEqual(@as(u16, 1), edns.ecs.?.family);
    try std.testing.expectEqual(@as(u8, 24), edns.ecs.?.source_prefix);
}

test "MessageParser findEdns rejects multiple OPT records (RFC 6891)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{ .udp_payload_size = 1232 });
    try builder.addOptRecord(.{ .udp_payload_size = 4096 }); // 第二个 OPT，非法
    const packet = builder.finish(.{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    const msg = try Message.parse(packet);
    var parser = MessageParser.init(packet);
    try parser.skipQuestions(msg.header.qdcount);
    try std.testing.expectError(error.MultipleOptRecords, parser.findEdns(msg.header.arcount));
}

test "Message.Builder addOptRecord with ECS round-trips" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

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
    var builder = try Message.Builder.init(&buf);
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

test "Message.Builder writeEcsOption masks address bits beyond prefix (RFC 7871)" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    // IPv4 prefix=20 -> 3 字节地址，末字节仅高 4 位有效，低 4 位必须清零。
    // 提供 0xFF 末字节，编码后必须被掩成 0xF0（RFC 7871 §7.1.3 MUST）。
    try builder.addOptRecord(.{
        .ecs = .{ .family = 1, .source_prefix = 20, .scope_prefix = 0, .address = &[_]u8{ 192, 168, 0xFF } },
    });
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });

    var parser = MessageParser.init(packet);
    try parser.skipQuestions(1);
    const ecs = (try parser.findECS(1)).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 0xF0 }, ecs.address);
}

test "Message.Builder writeEcsOption rejects invalid scope_prefix (RFC 7871)" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    // IPv4 scope_prefix=200 (>32) 非法
    try std.testing.expectError(error.MalformedECS, builder.addOptRecord(.{
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 200, .address = &[_]u8{ 192, 0, 2 } },
    }));
}

test "Message.Builder addOptRecord rejects invalid ECS" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
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
    var builder = try Message.Builder.init(&buf);

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
    var builder = try Message.Builder.init(&buf);
    try std.testing.expectError(error.BufferTooSmall, builder.addARecord("example.com", 3600, .{ 1, 2, 3, 4 }));
}

test "Message.Builder addAAAARecord guards final RDATA copy" {
    // AAAA RDATA 为 16 字节；48 字节缓冲区让守卫写入通过（到 pos=35），
    // 仅 16 字节 RDATA 拷贝越界 (35+16=51 > 48)。
    var buf: [48]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    const ip = [_]u8{0} ** 16;
    try std.testing.expectError(error.BufferTooSmall, builder.addAAAARecord("example.com", 3600, ip));
}
