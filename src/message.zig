const std = @import("std");
const mem = std.mem;
const Header = @import("header.zig").Header;
const Type = @import("types.zig").Type;
const OptionCode = @import("types.zig").OptionCode;
const ExtendedRcode = @import("types.zig").ExtendedRcode;
const Error = @import("errors.zig").Error;
const Question = @import("parser.zig").Question;
const ResourceRecord = @import("parser.zig").ResourceRecord;
const Parser = @import("parser.zig").MessageParser;
pub const Edns = @import("parser.zig").EdnsParams;
const RData = @import("rdata.zig").RData;
const validateSvcParams = @import("rdata.zig").validateSvcParams;
const validateOptOptionsForEncode = @import("rdata.zig").validateOptOptionsForEncode;
const NameCursor = @import("name.zig").NameCursor;
const DecodedPresentationName = @import("name.zig").DecodedPresentationName;
const decodePresentationName = @import("name.zig").decodePresentationName;

/// 压缩表槽位数。NSEC 链、大量胶水记录、ANY 应答很容易写出几十个不同后缀；
/// 表一满后续名字只能整名展开，报文变大 -> TC -> 退回 TCP。
const MAX_COMPRESSION = 128;
/// 14 位压缩指针可寻址的最大偏移。超过此偏移的名字永远不能作为指针目标，
/// 不占用压缩表槽位。
const MAX_POINTER_OFFSET = 0x3FFF;
const MAX_NAME_LENGTH = 255;

/// DNS 报文分区（RFC 1035 4.1）。构造时记录必须按此顺序添加。
pub const Section = enum { question, answer, authority, additional };

/// 绑定 Header 四分区计数的严格顺序报文解析器（RFC 1035 §4.1 / RFC 6891 §6.1.1）：
/// - 按 QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT 精确控制边界（QDCOUNT=0 时 nextQuestion 直接返回 null，防误把 OPT 当 Question）；
/// - 拒绝混入 Answer / Authority 区的 OPT 记录（error.MisplacedOptRecord）；
/// - 校验附加区至多一条单字节根 OPT 记录，并在首次消费 OPT 时直接缓存完整 `Edns`（通过 `edns()` 零重复获取）；
/// - 提供 `skipQuestions` / `skipAnswers` / `skipAuthorities` / `skipAdditionals` 快速跳过无需逐条消费的分区；
/// - `expectEnd()` 校验四分区全部消费完毕且报文末尾无残留字节（error.TrailingBytes）。
pub const SectionParser = struct {
    parser: Parser,
    qd_rem: u16,
    an_rem: u16,
    ns_rem: u16,
    ar_rem: u16,
    opt_edns: ?Edns = null,

    pub fn nextQuestion(self: *SectionParser) Error!?Question {
        if (self.qd_rem == 0) return null;
        const q = (try self.parser.nextQuestion()) orelse return error.PacketTooShort;
        self.qd_rem -= 1;
        return q;
    }

    pub fn skipQuestions(self: *SectionParser) Error!void {
        if (self.qd_rem == 0) return;
        try self.parser.skipQuestions(self.qd_rem);
        self.qd_rem = 0;
    }

    pub fn nextAnswer(self: *SectionParser) Error!?ResourceRecord {
        if (self.qd_rem != 0) return error.InvalidRecordOrder;
        if (self.an_rem == 0) return null;
        const rr = (try self.parser.nextRR()) orelse return error.PacketTooShort;
        if (rr.rtype == .OPT) return error.MisplacedOptRecord;
        self.an_rem -= 1;
        return rr;
    }

    pub fn skipAnswers(self: *SectionParser) Error!void {
        if (self.qd_rem != 0) return error.InvalidRecordOrder;
        if (self.an_rem == 0) return;
        try self.parser.skipNonAdditionalRecords(self.an_rem);
        self.an_rem = 0;
    }

    pub fn nextAuthority(self: *SectionParser) Error!?ResourceRecord {
        if (self.qd_rem != 0 or self.an_rem != 0) return error.InvalidRecordOrder;
        if (self.ns_rem == 0) return null;
        const rr = (try self.parser.nextRR()) orelse return error.PacketTooShort;
        if (rr.rtype == .OPT) return error.MisplacedOptRecord;
        self.ns_rem -= 1;
        return rr;
    }

    pub fn skipAuthorities(self: *SectionParser) Error!void {
        if (self.qd_rem != 0 or self.an_rem != 0) return error.InvalidRecordOrder;
        if (self.ns_rem == 0) return;
        try self.parser.skipNonAdditionalRecords(self.ns_rem);
        self.ns_rem = 0;
    }

    pub fn nextAdditional(self: *SectionParser) Error!?ResourceRecord {
        if (self.qd_rem != 0 or self.an_rem != 0 or self.ns_rem != 0) return error.InvalidRecordOrder;
        if (self.ar_rem == 0) return null;
        const rr = (try self.parser.nextRR()) orelse return error.PacketTooShort;
        if (rr.rtype == .OPT) {
            if (self.opt_edns != null) return error.MultipleOptRecords;
            if (rr.name_pos >= self.parser.buffer.len or self.parser.buffer[rr.name_pos] != 0) {
                return error.MalformedName;
            }
            self.opt_edns = try Edns.fromOpt(rr);
        }
        self.ar_rem -= 1;
        return rr;
    }

    pub fn skipAdditionals(self: *SectionParser) Error!void {
        if (self.qd_rem != 0 or self.an_rem != 0 or self.ns_rem != 0) return error.InvalidRecordOrder;
        while (try self.nextAdditional()) |_| {}
    }

    /// 返回附加区消费过程中已解析缓存的 EDNS(0) 参数（单趟零重复解码；未出现 OPT 或尚未读附加区时为 null）。
    pub fn edns(self: *const SectionParser) ?Edns {
        return self.opt_edns;
    }

    pub fn parseRData(self: *const SectionParser, rr: ResourceRecord) Error!RData {
        return self.parser.parseRData(rr);
    }

    pub fn formatNameAt(self: *const SectionParser, offset: usize, out_buf: []u8) Error![]const u8 {
        return self.parser.formatNameAt(offset, out_buf);
    }

    pub fn nameEqualsAt(self: *const SectionParser, offset: usize, expected: []const u8) Error!bool {
        return self.parser.nameEqualsAt(offset, expected);
    }

    /// 校验四个分区声明的记录均已按序消费完毕（未读完前置记录时返回 `error.InvalidRecordOrder`），
    /// 且报文末尾不存在未声明的残留字节（若有则返回 `error.TrailingBytes`）。
    pub fn expectEnd(self: *const SectionParser) Error!void {
        if (self.qd_rem != 0 or self.an_rem != 0 or self.ns_rem != 0 or self.ar_rem != 0) {
            return error.InvalidRecordOrder;
        }
        return self.parser.expectEnd();
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
        // DNS 报文头固定 12 字节；声明长度 <12 的 TCP 帧永远不可能合法，
        // 返回专用 MalformedHeader 以便与「半包未收齐」(PacketTooShort) 区分，防止流水线死等。
        if (msg_len < 12) return error.MalformedHeader;
        const frame_len = 2 + @as(usize, msg_len);
        if (raw.len < frame_len) return error.PacketTooShort;
        return .{ .message = try Message.parse(raw[2..frame_len]), .frame_len = frame_len };
    }

    /// 返回绑定本报文 Header 计数的严格四分区解析器。
    pub fn sections(self: Message) SectionParser {
        return .{
            .parser = Parser.init(self.buffer),
            .qd_rem = self.header.qdcount,
            .an_rem = self.header.ancount,
            .ns_rem = self.header.nscount,
            .ar_rem = self.header.arcount,
        };
    }

    /// 整包严格 EDNS(0) 解析与结构校验（RFC 1035 §4.1 / RFC 6891 §6.1.1）：
    /// 直接复用 `SectionParser` 单趟校验四分区边界、拒绝非附加区 OPT 与包尾残余字节。
    pub fn findEdns(self: Message) Error!?Edns {
        var secs = self.sections();
        try secs.skipQuestions();
        try secs.skipAnswers();
        try secs.skipAuthorities();
        try secs.skipAdditionals();
        try secs.expectEnd();
        return secs.edns();
    }

    /// 高性能响应构造器
    pub const Builder = struct {
        const BUCKET_COUNT = 64;
        const BUCKET_MASK: u8 = BUCKET_COUNT - 1;
        const BUCKET_THRESHOLD: u8 = 16; // <16 项走 L1 顺序扫描（免掉 init 清零开销），≥16 项惰性建桶转 O(1)
        const EMPTY_BUCKET: u8 = 0xFF;
        // 紧凑无填充 8 字节槽位（128 × 8 = 1024B，较 16B 对齐布局减半）；命中后由 nameMatchesWireAt 逐字节核验防碰撞。
        const CompressionEntry = struct {
            hash: u32,
            pos: u16,
            prev: u8,
            bucket: u8,
        };

        buf: []u8, // DNS 报文区域（TCP 时为 dest[2..]）
        dest: []u8, // 完整目标缓冲区（含可能的 2 字节 TCP 长度前缀）
        prefix_len: usize, // DNS 报文前保留字节数：0=UDP, 2=TCP
        pos: usize,
        // 压缩指针表：小报文零初始化顺序扫描，多名字大报文自动切换 64 桶 O(1) 索引
        compression_table: [MAX_COMPRESSION]CompressionEntry,
        compression_buckets: [BUCKET_COUNT]u8,
        compression_count: u8,
        // 首个非根名字仅记录偏移（0 表示无），延迟到第 2 个名字实际查表时再建后缀哈希，使单问题查询零哈希开销
        first_unindexed_pos: u16,
        section: Section, // 当前分区，用于自动计数
        opt_added: bool, // RFC 6891 §6.1.1: 一个报文至多一个 OPT 记录
        implicit_opt_section: bool, // addOptRecord 隐式跳到 .additional 后的保护锁，防后续误写回答变 NODATA
        tsig_added: bool, // RFC 8945 §5.1: TSIG 必须是附加区最后一条记录，其后禁止再追加任何记录
        reserved_edns: ?Edns, // setEdns 预留待 finish 自动落盘到附加区末尾的 OPT 配置（支持 TC=1 截断保留 OPT）
        reserved_bytes: usize, // 为 reserved_edns 预留的尾部字节数
        qd: u16,
        an: u16,
        ns: u16,
        ar: u16,

        pub inline fn init(dest: []u8) Error!Builder {
            return initFramed(dest, 0);
        }

        /// 构造 TCP 报文：预留 2 字节长度前缀，DNS 报文写入 dest[2..]，用 finishTcp 收尾。
        pub inline fn initTcp(dest: []u8) Error!Builder {
            return initFramed(dest, 2);
        }

        inline fn initFramed(dest: []u8, prefix_len: usize) Error!Builder {
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
                .compression_buckets = undefined,
                .compression_count = 0,
                .first_unindexed_pos = 0,
                .section = .question, // 初始位于 question；首次写数据 RR 自动推进到 .answer
                .opt_added = false,
                .implicit_opt_section = false,
                .tsig_added = false,
                .reserved_edns = null,
                .reserved_bytes = 0,
                .qd = 0,
                .an = 0,
                .ns = 0,
                .ar = 0,
            };
        }

        /// 就地重置为 UDP 报文构造器，供高频请求循环复用同一栈上 `Builder` 实例。
        pub fn reset(self: *Builder, dest: []u8) Error!void {
            return self.resetFramed(dest, 0);
        }

        /// 就地重置为 TCP 组帧报文构造器（预留 2 字节长度前缀）。
        pub fn resetTcp(self: *Builder, dest: []u8) Error!void {
            return self.resetFramed(dest, 2);
        }

        fn resetFramed(self: *Builder, dest: []u8, prefix_len: usize) Error!void {
            if (dest.len < prefix_len + 12) return Error.BufferTooSmall;
            const avail = @min(dest.len - prefix_len, 0xFFFF);
            self.buf = dest[prefix_len .. prefix_len + avail];
            self.dest = dest;
            self.prefix_len = prefix_len;
            self.pos = 12;
            self.compression_count = 0;
            self.first_unindexed_pos = 0;
            self.section = .question;
            self.opt_added = false;
            self.implicit_opt_section = false;
            self.tsig_added = false;
            self.reserved_edns = null;
            self.reserved_bytes = 0;
            self.qd = 0;
            self.an = 0;
            self.ns = 0;
            self.ar = 0;
        }

        // 轻量快照：仅保存 add* 作用域内可变状态（移除 112B reserved_edns/reserved_bytes 冗余拷贝）。
        const Snapshot = struct {
            pos: usize,
            first_unindexed_pos: u16,
            compression_count: u8,
            section: Section,
            opt_added: bool,
            implicit_opt_section: bool,
            tsig_added: bool,
        };

        inline fn snapshot(self: *const Builder) Snapshot {
            return .{
                .pos = self.pos,
                .first_unindexed_pos = self.first_unindexed_pos,
                .compression_count = self.compression_count,
                .section = self.section,
                .opt_added = self.opt_added,
                .implicit_opt_section = self.implicit_opt_section,
                .tsig_added = self.tsig_added,
            };
        }

        /// 回滚到快照（用于 add* 失败时保持原子性，使截断可安全恢复）。
        /// 包含 section、惰性首名偏移与桶链逆序摘除，使失败后状态完全复原。
        fn restore(self: *Builder, s: Snapshot) void {
            if (self.compression_count > BUCKET_THRESHOLD) {
                while (self.compression_count > s.compression_count and self.compression_count > BUCKET_THRESHOLD) {
                    self.compression_count -= 1;
                    const entry = self.compression_table[self.compression_count];
                    self.compression_buckets[entry.bucket] = entry.prev;
                }
            }
            self.compression_count = s.compression_count;
            self.first_unindexed_pos = s.first_unindexed_pos;
            self.pos = s.pos;
            self.section = s.section;
            self.opt_added = s.opt_added;
            self.implicit_opt_section = s.implicit_opt_section;
            self.tsig_added = s.tsig_added;
        }

        /// 切换当前分区（后续 RR 计入 answer/authority/additional）。分区只能向后推进；
        /// 回退返回 error.InvalidRecordOrder（调用方误用，不做 UB）。
        pub fn setSection(self: *Builder, s: Section) !void {
            if (@backingInt(s) < @backingInt(self.section)) return Error.InvalidRecordOrder;
            self.section = s;
            if (s == .additional) self.implicit_opt_section = false;
        }

        fn beginDataRecord(self: *Builder) Error!void {
            if (self.tsig_added or self.implicit_opt_section) return Error.InvalidRecordOrder;
            if (self.section == .question) self.section = .answer;
        }

        inline fn hashWireSuffix(suffix_wire: []const u8) u32 {
            return @truncate(std.hash.Wyhash.hash(0, suffix_wire));
        }

        /// 校验 buf[pos..] 处已写入的线格式域名是否逐字节等于展开后的线格式后缀 `suffix_wire`（不含末尾根 0）。
        /// 用于压缩指针复用前的字节级确认（防 32 位哈希碰撞，保持 0x20 大小写严格一致，同时天然支持含 '.' 或转义字节的标签）。
        fn nameMatchesWireAt(self: *const Builder, pos: u16, suffix_wire: []const u8) bool {
            var read: usize = pos;
            var exp: usize = 0;
            while (read < self.pos) {
                const len = self.buf[read];
                if (len == 0) return exp == suffix_wire.len;
                if (len & 0xC0 == 0xC0) {
                    if (read + 2 > self.pos) return false;
                    const target = (@as(usize, len & 0x3F) << 8) | self.buf[read + 1];
                    if (target >= read) return false; // 只允许向更早偏移跳（防环）
                    read = target;
                    continue;
                }
                if (len > 63 or read + 1 + len > self.pos) return false;
                const seg_len = 1 + @as(usize, len);
                if (exp + seg_len > suffix_wire.len) return false;
                if (!mem.eql(u8, self.buf[read .. read + seg_len], suffix_wire[exp .. exp + seg_len])) return false;
                exp += seg_len;
                read += seg_len;
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

        inline fn ensureCapacity(self: *Builder, need: usize) !void {
            const limit = self.buf.len -| self.reserved_bytes;
            if (need > limit -| self.pos) return Error.BufferTooSmall;
        }

        fn validateOptRdata(rdata: []const u8) Error!void {
            _ = try validateOptOptionsForEncode(rdata);
        }

        /// 写入 A 记录
        pub fn addARecord(self: *Builder, name: []const u8, ttl: u32, ip: [4]u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.A));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.AAAA));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.CNAME));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.MX));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.NS));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.PTR));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.TXT));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.TXT));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.SOA));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.SRV));
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
        ///
        /// - rtype == 41 (OPT)：同样受「至多一个 OPT、仅附加区、单字节根 owner、选项无重复/畸形」约束（RFC 6891 §6.1.1）；
        /// - rtype == 250 (TSIG)：按 RFC 8945 §5.1 仅允许位于 `.additional` 分区末尾；若此前调用了 `setEdns` 预留 OPT，
        ///   会自动先将预留 OPT 落盘再写入 TSIG（失败时一并原子回滚），保证线上顺序为 `[..., OPT, TSIG]`，且 TSIG 之后禁止再追加任何记录。
        pub fn addRecordRaw(self: *Builder, name: []const u8, rtype: u16, class: u16, ttl: u32, rdata: []const u8) !void {
            if (rdata.len > 0xFFFF) return Error.MessageTooLong;
            if (self.tsig_added) return Error.InvalidRecordOrder;
            const saved_edns = self.reserved_edns;
            const saved_res_bytes = self.reserved_bytes;
            const saved_ar = self.ar;
            const snap = self.snapshot();
            errdefer {
                self.restore(snap);
                self.reserved_edns = saved_edns;
                self.reserved_bytes = saved_res_bytes;
                self.ar = saved_ar;
            }
            if (rtype == @backingInt(Type.OPT)) {
                if (self.opt_added) return Error.MultipleOptRecords;
                if (self.section != .additional or self.implicit_opt_section) return Error.InvalidRecordOrder;
                if (name.len != 0 and !mem.eql(u8, name, ".")) return Error.MalformedName;
                try validateOptRdata(rdata);
                self.opt_added = true;
            } else if (rtype == @backingInt(Type.TSIG)) {
                if (self.section != .additional or self.implicit_opt_section) return Error.InvalidRecordOrder;
                self.flushEdns();
            } else {
                try self.beginDataRecord();
            }
            try self.writeName(name);
            try self.writeU16(rtype);
            try self.writeU16(class);
            try self.writeU32(ttl);
            try self.writeU16(@intCast(rdata.len));
            try self.ensureCapacity(rdata.len);
            @memcpy(self.buf[self.pos..][0..rdata.len], rdata);
            self.pos += rdata.len;
            if (rtype == @backingInt(Type.TSIG)) self.tsig_added = true;
            self.countRecord();
        }

        /// 写入 DNAME 记录（RFC 6672 §2.1）：target 不得压缩，后缀可供后续记录复用。
        pub fn addDNAMERecord(self: *Builder, name: []const u8, ttl: u32, target: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.DNAME));
            try self.writeU16(1);
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0);
            try self.writeNameRaw(target);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入 HINFO 记录（RFC 1035 §3.3.2 / RFC 8482）：cpu 与 os 各为一个 ≤255 字节的 character-string。
        pub fn addHINFORecord(self: *Builder, name: []const u8, ttl: u32, cpu: []const u8, os: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.HINFO));
            try self.writeU16(1);
            try self.writeU32(ttl);
            const rdlen_pos = self.pos;
            try self.writeU16(0);
            try self.writeCharString(cpu);
            try self.writeCharString(os);
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
            self.countRecord();
        }

        /// 写入 SSHFP 记录（RFC 4255 §3.1）：fingerprint 不可为空。
        pub fn addSSHFPRecord(self: *Builder, name: []const u8, ttl: u32, algorithm: u8, fp_type: u8, fingerprint: []const u8) !void {
            if (fingerprint.len == 0) return Error.InvalidRData;
            const rdlen = 2 + fingerprint.len;
            if (rdlen > 0xFFFF) return Error.MessageTooLong;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.SSHFP));
            try self.writeU16(1);
            try self.writeU32(ttl);
            try self.writeU16(@intCast(rdlen));
            try self.writeU8(algorithm);
            try self.writeU8(fp_type);
            try self.ensureCapacity(fingerprint.len);
            @memcpy(self.buf[self.pos..][0..fingerprint.len], fingerprint);
            self.pos += fingerprint.len;
            self.countRecord();
        }

        /// 写入 TLSA 记录（RFC 6698 §2.1）：cert_data 不可为空。
        pub fn addTLSARecord(self: *Builder, name: []const u8, ttl: u32, usage: u8, selector: u8, matching_type: u8, cert_data: []const u8) !void {
            if (cert_data.len == 0) return Error.InvalidRData;
            const rdlen = 3 + cert_data.len;
            if (rdlen > 0xFFFF) return Error.MessageTooLong;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.TLSA));
            try self.writeU16(1);
            try self.writeU32(ttl);
            try self.writeU16(@intCast(rdlen));
            try self.writeU8(usage);
            try self.writeU8(selector);
            try self.writeU8(matching_type);
            try self.ensureCapacity(cert_data.len);
            @memcpy(self.buf[self.pos..][0..cert_data.len], cert_data);
            self.pos += cert_data.len;
            self.countRecord();
        }

        /// 写入 CDS 记录（RFC 7344 §3.1，线格式与 DS 相同）。
        pub fn addCDSRecord(self: *Builder, name: []const u8, ttl: u32, key_tag: u16, algorithm: u8, digest_type: u8, digest: []const u8) !void {
            return self.addDsLike(.CDS, name, ttl, key_tag, algorithm, digest_type, digest);
        }

        /// 写入 CDNSKEY 记录（RFC 7344 §3.2，线格式与 DNSKEY 相同）。
        pub fn addCDNSKEYRecord(self: *Builder, name: []const u8, ttl: u32, flags: u16, protocol: u8, algorithm: u8, public_key: []const u8) !void {
            return self.addDnskeyLike(.CDNSKEY, name, ttl, flags, protocol, algorithm, public_key);
        }

        /// 写入 CAA 记录（RFC 8659）。tag 须为 1..255 字节的 ASCII 字母数字，value 原样写入。
        pub fn addCAARecord(self: *Builder, name: []const u8, ttl: u32, flags: u8, tag: []const u8, value: []const u8) !void {
            if (tag.len == 0) return Error.InvalidRData;
            if (tag.len > 255) return Error.LabelTooLong;
            for (tag) |c| {
                if (!std.ascii.isAlphanumeric(c)) return Error.InvalidRData;
            }
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.CAA));
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
            try validateSvcParams(params); // RFC 9460 §2.2 / §7: key 严格递增去重、TLV 平铺且知名值格式合法
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(rtype));
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
            return self.addDnskeyLike(.DNSKEY, name, ttl, flags, protocol, algorithm, public_key);
        }

        fn addDnskeyLike(self: *Builder, rtype: Type, name: []const u8, ttl: u32, flags: u16, protocol: u8, algorithm: u8, public_key: []const u8) !void {
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(rtype));
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

        /// 写入 DS 记录（RFC 4034）。digest 不可为空。
        pub fn addDSRecord(self: *Builder, name: []const u8, ttl: u32, key_tag: u16, algorithm: u8, digest_type: u8, digest: []const u8) !void {
            return self.addDsLike(.DS, name, ttl, key_tag, algorithm, digest_type, digest);
        }

        fn addDsLike(self: *Builder, rtype: Type, name: []const u8, ttl: u32, key_tag: u16, algorithm: u8, digest_type: u8, digest: []const u8) !void {
            if (digest.len == 0) return Error.InvalidRData;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(rtype));
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

        /// 写入 RRSIG 记录（RFC 4034）。signer name 不压缩；labels ≤ 127 且 signature 非空。
        pub fn addRRSIGRecord(self: *Builder, name: []const u8, ttl: u32, sig: Rrsig) !void {
            if (sig.labels > 127 or sig.signature.len == 0) return Error.InvalidRData;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.RRSIG));
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

        /// 写入 NSEC 记录（RFC 4034）。next_domain 不压缩；types 非空且须升序去重。
        pub fn addNSECRecord(self: *Builder, name: []const u8, ttl: u32, next_domain: []const u8, types: []const u16) !void {
            if (types.len == 0) return Error.InvalidRData;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.NSEC));
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
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.NSEC3PARAM));
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

        /// 写入 NSEC3 记录（RFC 5155）。salt ≤255 字节，next_hashed_owner 须 1..255 字节；types 须升序。
        pub fn addNSEC3Record(self: *Builder, name: []const u8, ttl: u32, n3: Nsec3) !void {
            if (n3.salt.len > 255 or n3.next_hashed_owner.len == 0 or n3.next_hashed_owner.len > 255) return Error.InvalidRData;
            // RFC 5155: SHA-1（算法 1）哈希固定 20 字节——与解析端一致，避免构造出解析器会拒的记录。
            if (n3.hash_algorithm == 1 and n3.next_hashed_owner.len != 20) return Error.InvalidRData;
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.beginDataRecord();
            try self.writeName(name);
            try self.writeU16(@backingInt(Type.NSEC3));
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

        /// 写入 Question（必须先于所有 RR 及非 question 分区设置）
        pub fn addQuestion(self: *Builder, qname: []const u8, qtype: Type, qclass: u16) !void {
            if (self.tsig_added or self.section != .question or self.an != 0 or self.ns != 0 or self.ar != 0) {
                return Error.InvalidRecordOrder;
            }
            const snap = self.snapshot();
            errdefer self.restore(snap);
            try self.writeName(qname);
            try self.writeU16(@backingInt(qtype));
            try self.writeU16(qclass);
            self.qd += 1;
        }

        /// 从已解析请求报文 `msg_buf` 中直接回显一条 `Question`（支持压缩或未压缩 QNAME，免去格式化为点分转义字符串再重解码）。
        /// 写出的 QNAME 同样登记供后续回答记录压缩复用。
        pub fn addQuestionFrom(self: *Builder, msg_buf: []const u8, q: Question) Error!void {
            if (self.tsig_added or self.section != .question or self.an != 0 or self.ns != 0 or self.ar != 0) {
                return Error.InvalidRecordOrder;
            }
            const snap = self.snapshot();
            errdefer self.restore(snap);

            var wire: [MAX_NAME_LENGTH]u8 = undefined;
            var offsets: [128]u8 = undefined;
            var cur = NameCursor.initInMessage(msg_buf, q.name_pos);
            var wpos: usize = 0;
            var n_labels: usize = 0;
            while (try cur.next()) |lbl| {
                offsets[n_labels] = @intCast(wpos);
                n_labels += 1;
                wire[wpos] = @intCast(lbl.len);
                @memcpy(wire[wpos + 1 ..][0..lbl.len], lbl);
                wpos += 1 + lbl.len;
            }
            if (cur.wire_end != q.qname_end_pos) return Error.InvalidOffset;
            wire[wpos] = 0;
            try self.writeDecodedWire(&wire, &offsets, .{ .wire_len = wpos + 1, .n_labels = n_labels }, true);
            try self.writeU16(@backingInt(q.qtype));
            try self.writeU16(q.qclass);
            self.qd += 1;
        }

        /// 预留 EDNS(0) OPT 尾部空间并在 finish/finishTcp（或显式 `flushEdns` / 追加 `TSIG` 前）自动写入附加区（RFC 6891 §6.1.1 / §7）。
        /// - 不改变当前分区：可在写 Question/Answer/Authority 前后任意时刻调用，不会导致后续回答误入附加区；
        /// - 截断安全：当回答区写满返回 `error.BufferTooSmall` 并置 `TC=1` 时，已预留的 OPT 空间不受侵占，
        ///   收尾时仍能按 RFC 6891 §7 在截断响应中完整发出 OPT 记录。
        pub fn setEdns(self: *Builder, edns: Edns) !void {
            if (self.tsig_added) return Error.InvalidRecordOrder;
            if (self.opt_added) return Error.MultipleOptRecords;
            const opt_len = try edns.wireLen();
            try self.ensureCapacity(opt_len);
            self.opt_added = true;
            self.reserved_edns = edns;
            self.reserved_bytes = opt_len;
        }

        /// 更新由 `setEdns` 预留但尚未落盘的 EDNS 参数（如查询后回填 ECS scope_prefix 或 BADCOOKIE）。
        pub fn updateEdns(self: *Builder, edns: Edns) !void {
            if (self.reserved_edns == null) return Error.InvalidRecordOrder;
            const opt_len = try edns.wireLen();
            if (opt_len > self.buf.len -| self.pos) return Error.BufferTooSmall;
            self.reserved_edns = edns;
            self.reserved_bytes = opt_len;
        }

        /// 将 `setEdns` 预留的 OPT 记录立即落盘至附加区（例如在计算 RFC 8945 TSIG 摘要并追加尾置 TSIG 记录之前调用）。
        /// 若调用前尚未显式 `setSection(.additional)`，将与 `addOptRecord` 一样开启隐式附加区保护锁。
        pub fn flushEdns(self: *Builder) void {
            if (self.reserved_edns) |edns| {
                const explicit_additional = (self.section == .additional) and !self.implicit_opt_section;
                self.reserved_edns = null;
                self.reserved_bytes = 0;
                self.section = .additional;
                self.implicit_opt_section = !explicit_additional;
                self.writeOptRecordUnchecked(edns);
                self.ar += 1;
            }
        }

        fn writeOptRecordUnchecked(self: *Builder, edns: Edns) void {
            self.buf[self.pos] = 0; // OPT 的 owner name 必须为单字节根
            self.pos += 1;
            mem.writeInt(u16, self.buf[self.pos..][0..2], @backingInt(Type.OPT), .big);
            self.pos += 2;
            mem.writeInt(u16, self.buf[self.pos..][0..2], edns.udp_payload_size, .big);
            self.pos += 2;
            const flags: u32 = (if (edns.dnssec_ok) @as(u32, 0x8000) else 0) | @as(u32, edns.z_flags);
            const ttl = (@as(u32, edns.extended_rcode) << 24) |
                (@as(u32, edns.version) << 16) | flags;
            mem.writeInt(u32, self.buf[self.pos..][0..4], ttl, .big);
            self.pos += 4;

            const rdlen_pos = self.pos;
            self.pos += 2; // 占位 RDLength
            if (edns.ecs) |ecs| {
                const addr_len = (@as(usize, ecs.source_prefix) + 7) / 8;
                mem.writeInt(u16, self.buf[self.pos..][0..2], @backingInt(OptionCode.ECS), .big);
                mem.writeInt(u16, self.buf[self.pos + 2 ..][0..2], @intCast(4 + addr_len), .big);
                mem.writeInt(u16, self.buf[self.pos + 4 ..][0..2], ecs.family, .big);
                self.buf[self.pos + 6] = ecs.source_prefix;
                self.buf[self.pos + 7] = ecs.scope_prefix;
                self.pos += 8;
                @memcpy(self.buf[self.pos..][0..addr_len], ecs.address[0..addr_len]);
                if (addr_len > 0) {
                    const rem: u3 = @intCast(ecs.source_prefix % 8);
                    if (rem != 0) self.buf[self.pos + addr_len - 1] &= @as(u8, 0xFF) << @intCast(8 - @as(u4, rem));
                }
                self.pos += addr_len;
            }
            if (edns.cookie) |cookie| {
                const opt_len = 8 + cookie.server.len;
                mem.writeInt(u16, self.buf[self.pos..][0..2], @backingInt(OptionCode.COOKIE), .big);
                mem.writeInt(u16, self.buf[self.pos + 2 ..][0..2], @intCast(opt_len), .big);
                self.pos += 4;
                @memcpy(self.buf[self.pos..][0..8], &cookie.client);
                self.pos += 8;
                @memcpy(self.buf[self.pos..][0..cookie.server.len], cookie.server);
                self.pos += cookie.server.len;
            }
            if (edns.preserve_raw_options and edns.options_raw.len > 0) {
                var it = edns.optionsIterator();
                while (it.next() catch unreachable) |opt| {
                    if (opt.code == .ECS or opt.code == .COOKIE) continue;
                    mem.writeInt(u16, self.buf[self.pos..][0..2], @backingInt(opt.code), .big);
                    mem.writeInt(u16, self.buf[self.pos + 2 ..][0..2], @intCast(opt.data.len), .big);
                    self.pos += 4;
                    @memcpy(self.buf[self.pos..][0..opt.data.len], opt.data);
                    self.pos += opt.data.len;
                }
            }
            if (edns.extra_options.len > 0) {
                @memcpy(self.buf[self.pos..][0..edns.extra_options.len], edns.extra_options);
                self.pos += edns.extra_options.len;
            }
            const rdlen = @as(u16, @intCast(self.pos - rdlen_pos - 2));
            mem.writeInt(u16, self.buf[rdlen_pos..][0..2], rdlen, .big);
        }

        fn flushReservedEdns(self: *Builder) bool {
            if (self.reserved_edns) |edns| {
                self.reserved_edns = null;
                self.reserved_bytes = 0;
                self.section = .additional;
                self.implicit_opt_section = false;
                self.writeOptRecordUnchecked(edns);
                self.ar += 1;
                return true;
            }
            return false;
        }

        /// 立即在附加区（additional）写入 EDNS(0) OPT 记录（RFC 6891）。
        /// 若调用前未显式 `setSection(.additional)`，后续若未显式声明附加区而继续调用 `add*Record`
        /// 将返回 `error.InvalidRecordOrder`，防止误把回答记录写进附加区造成静默 NODATA；
        /// 服务端推荐优先使用不改变分区的 `setEdns`。
        pub fn addOptRecord(self: *Builder, edns: Edns) !void {
            if (self.tsig_added) return Error.InvalidRecordOrder;
            const snap = self.snapshot(); // 先快照（含 section），失败可完全回滚
            errdefer self.restore(snap);
            if (self.opt_added) return Error.MultipleOptRecords;
            const opt_len = try edns.wireLen();
            try self.ensureCapacity(opt_len);
            const explicit_additional = (self.section == .additional) and !self.implicit_opt_section;
            self.opt_added = true;
            try self.setSection(.additional);
            self.implicit_opt_section = !explicit_additional;
            self.writeOptRecordUnchecked(edns);
            self.countRecord();
        }

        /// 低级：写入 OPT 记录，options 为调用方自行编码的完整 RDATA。
        /// 与 `addOptRecord` 共用「至多一个 OPT」及选项严格编码约束（RFC 6891 §6.1.1/§6.1.2、RFC 7873）。
        pub fn addOptRecordRaw(self: *Builder, udp_payload_size: u16, ttl: u32, options: []const u8) !void {
            if (options.len > 0xFFFF) return Error.MessageTooLong;
            if (self.tsig_added) return Error.InvalidRecordOrder;
            const snap = self.snapshot(); // 先快照（含 section），失败可完全回滚
            errdefer self.restore(snap);
            if (self.opt_added) return Error.MultipleOptRecords;
            try validateOptRdata(options);
            const explicit_additional = (self.section == .additional) and !self.implicit_opt_section;
            self.opt_added = true;
            try self.setSection(.additional);
            self.implicit_opt_section = !explicit_additional;

            try self.writeU8(0);
            try self.writeU16(@backingInt(Type.OPT));
            try self.writeU16(udp_payload_size);
            try self.writeU32(ttl);
            try self.writeU16(@intCast(options.len));
            try self.ensureCapacity(options.len);
            @memcpy(self.buf[self.pos..][0..options.len], options);
            self.pos += options.len;
            self.countRecord();
        }

        fn insertCompressionEntry(self: *Builder, h: u32, pos: usize) void {
            if (self.compression_count >= MAX_COMPRESSION or pos > MAX_POINTER_OFFSET) return;
            const bucket: u8 = @as(u8, @truncate(h)) & BUCKET_MASK;
            const idx = self.compression_count;
            if (idx == BUCKET_THRESHOLD) {
                self.compression_buckets = @splat(EMPTY_BUCKET);
                for (0..BUCKET_THRESHOLD) |j| {
                    const b = self.compression_table[j].bucket;
                    self.compression_table[j].prev = self.compression_buckets[b];
                    self.compression_buckets[b] = @intCast(j);
                }
            }
            const prev = if (idx >= BUCKET_THRESHOLD) self.compression_buckets[bucket] else EMPTY_BUCKET;
            self.compression_table[idx] = .{
                .hash = h,
                .pos = @intCast(pos),
                .prev = prev,
                .bucket = bucket,
            };
            if (idx >= BUCKET_THRESHOLD) {
                self.compression_buckets[bucket] = idx;
            }
            self.compression_count = idx + 1;
        }

        /// 将首个延迟索引的非根域名（完整未压缩展开在 `self.buf[first_unindexed_pos..]`）补入压缩表。
        fn flushFirstUnindexed(self: *Builder) void {
            if (self.first_unindexed_pos == 0) return;
            const start: usize = self.first_unindexed_pos;
            self.first_unindexed_pos = 0;
            var end = start;
            var offsets: [128]u8 = undefined;
            var n_labels: usize = 0;
            while (self.buf[end] != 0) {
                offsets[n_labels] = @intCast(end - start);
                n_labels += 1;
                end += 1 + self.buf[end];
            }
            const wire_no_root = self.buf[start..end];
            for (offsets[0..n_labels]) |off| {
                const pos = start + off;
                if (pos > MAX_POINTER_OFFSET or self.compression_count >= MAX_COMPRESSION) break;
                self.insertCompressionEntry(hashWireSuffix(wire_no_root[off..]), pos);
            }
        }

        fn registerWireSuffixes(
            self: *Builder,
            wire_no_root: []const u8,
            offsets_slice: []const u8,
            cached_hashes: ?*const [16]u32,
            start: usize,
        ) void {
            for (offsets_slice, 0..) |off, k| {
                const pos = start + off;
                if (pos > MAX_POINTER_OFFSET or self.compression_count >= MAX_COMPRESSION) return;
                const h = if (cached_hashes != null and k < 16)
                    cached_hashes.?[k]
                else
                    hashWireSuffix(wire_no_root[off..]);
                self.insertCompressionEntry(h, pos);
            }
        }

        fn writeDecodedWire(
            self: *Builder,
            wire: *const [MAX_NAME_LENGTH]u8,
            offsets: *const [128]u8,
            decoded: DecodedPresentationName,
            allow_compress: bool,
        ) Error!void {
            if (decoded.n_labels == 0) {
                try self.ensureCapacity(1);
                self.buf[self.pos] = 0;
                self.pos += 1;
                return;
            }

            if (self.compression_count == 0 and self.first_unindexed_pos == 0) {
                const start = self.pos;
                try self.ensureCapacity(decoded.wire_len);
                @memcpy(self.buf[start..][0..decoded.wire_len], wire[0..decoded.wire_len]);
                self.pos = start + decoded.wire_len;
                if (start <= MAX_POINTER_OFFSET) self.first_unindexed_pos = @intCast(start);
                return;
            }

            if (self.first_unindexed_pos != 0) self.flushFirstUnindexed();

            const wire_no_root = wire[0 .. decoded.wire_len - 1];
            const start = self.pos;

            if (allow_compress and self.compression_count > 0) {
                var suffix_hashes: [16]u32 = undefined;
                for (offsets[0..decoded.n_labels], 0..) |off, k| {
                    const suffix = wire_no_root[off..];
                    const suffix_hash = hashWireSuffix(suffix);
                    if (k < 16) suffix_hashes[k] = suffix_hash;

                    var matched_pos: ?u16 = null;
                    if (self.compression_count <= BUCKET_THRESHOLD) {
                        for (self.compression_table[0..self.compression_count]) |entry| {
                            if (entry.hash == suffix_hash and self.nameMatchesWireAt(entry.pos, suffix)) {
                                matched_pos = entry.pos;
                                break;
                            }
                        }
                    } else {
                        const bucket: u8 = @as(u8, @truncate(suffix_hash)) & BUCKET_MASK;
                        var idx = self.compression_buckets[bucket];
                        while (idx != EMPTY_BUCKET) : (idx = self.compression_table[idx].prev) {
                            const entry = self.compression_table[idx];
                            if (entry.hash == suffix_hash and self.nameMatchesWireAt(entry.pos, suffix)) {
                                matched_pos = entry.pos;
                                break;
                            }
                        }
                    }

                    if (matched_pos) |target_pos| {
                        const prefix_bytes: usize = off;
                        try self.ensureCapacity(prefix_bytes + 2);
                        if (prefix_bytes > 0) {
                            @memcpy(self.buf[start..][0..prefix_bytes], wire[0..prefix_bytes]);
                        }
                        self.buf[start + prefix_bytes] = 0xC0 | @as(u8, @intCast(target_pos >> 8));
                        self.buf[start + prefix_bytes + 1] = @as(u8, @intCast(target_pos & 0xFF));
                        self.pos = start + prefix_bytes + 2;
                        self.registerWireSuffixes(wire_no_root, offsets[0..k], &suffix_hashes, start);
                        return;
                    }
                }

                try self.ensureCapacity(decoded.wire_len);
                @memcpy(self.buf[start..][0..decoded.wire_len], wire[0..decoded.wire_len]);
                self.pos = start + decoded.wire_len;
                self.registerWireSuffixes(wire_no_root, offsets[0..decoded.n_labels], &suffix_hashes, start);
                return;
            }

            try self.ensureCapacity(decoded.wire_len);
            @memcpy(self.buf[start..][0..decoded.wire_len], wire[0..decoded.wire_len]);
            self.pos = start + decoded.wire_len;
            self.registerWireSuffixes(wire_no_root, offsets[0..decoded.n_labels], null, start);
        }

        /// 写入域名，支持压缩指针（基于线格式后缀统一支持普通名与 RFC 1035 §5.1 转义名压缩）。
        fn writeName(self: *Builder, name: []const u8) !void {
            if (name.len == 0 or mem.eql(u8, name, ".")) {
                try self.ensureCapacity(1);
                self.buf[self.pos] = 0;
                self.pos += 1;
                return;
            }

            // 首条非根域名零缓冲零哈希直写快路径（覆盖绝大多数单问题查询与响应首名）
            if (self.compression_count == 0 and self.first_unindexed_pos == 0) {
                const s = if (name.len > 1 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
                if (s.len == 0) return Error.MalformedName;
                if (s.len + 2 <= MAX_NAME_LENGTH and s.len + 2 <= (self.buf.len -| self.reserved_bytes) -| self.pos) {
                    const start = self.pos;
                    var out = start;
                    var len_slot = out;
                    out += 1;
                    var llen: usize = 0;
                    var has_escape = false;
                    for (s) |b| {
                        if (b == '\\') {
                            has_escape = true;
                            break;
                        }
                        if (b == '.') {
                            if (llen == 0) return Error.MalformedName;
                            if (llen > 63) return Error.LabelTooLong;
                            self.buf[len_slot] = @intCast(llen);
                            len_slot = out;
                            out += 1;
                            llen = 0;
                        } else {
                            self.buf[out] = b;
                            out += 1;
                            llen += 1;
                        }
                    }
                    if (!has_escape) {
                        if (llen == 0) return Error.MalformedName;
                        if (llen > 63) return Error.LabelTooLong;
                        self.buf[len_slot] = @intCast(llen);
                        self.buf[out] = 0;
                        self.pos = out + 1;
                        if (start <= MAX_POINTER_OFFSET) self.first_unindexed_pos = @intCast(start);
                        return;
                    }
                }
            }

            var wire: [MAX_NAME_LENGTH]u8 = undefined;
            var offsets: [128]u8 = undefined;
            const decoded = try decodePresentationName(name, &wire, &offsets);
            return self.writeDecodedWire(&wire, &offsets, decoded, true);
        }

        /// 写入完整展开、不压缩的域名（用于 SRV target、DNAME target、SVCB/HTTPS TargetName、
        /// RRSIG signer、NSEC next_domain 等 RFC 规定不得压缩的域名字段）。
        /// 展开写出后统一按线格式后缀登记到压缩表（含转义域名），供后续胶水记录或后续 owner 压缩复用。
        fn writeNameRaw(self: *Builder, name: []const u8) !void {
            if (name.len == 0 or mem.eql(u8, name, ".")) {
                try self.ensureCapacity(1);
                self.buf[self.pos] = 0;
                self.pos += 1;
                return;
            }
            var wire: [MAX_NAME_LENGTH]u8 = undefined;
            var offsets: [128]u8 = undefined;
            const decoded = try decodePresentationName(name, &wire, &offsets);
            return self.writeDecodedWire(&wire, &offsets, decoded, false);
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

        fn encodeFinalFrame(self: *Builder, header: Header) []u8 {
            const h_bytes = header.encode();
            @memcpy(self.buf[0..12], &h_bytes);
            if (self.prefix_len == 2) {
                mem.writeInt(u16, self.dest[0..2], @intCast(self.pos), .big);
                return self.dest[0 .. 2 + self.pos];
            }
            return self.buf[0..self.pos];
        }

        /// 收尾：若存在 `setEdns` 预留的 OPT 记录则自动落盘到附加区末尾，并自动回填四个分区计数。
        /// 若由 `initTcp` 创建，一并回填 2 字节大端长度前缀并返回含前缀的完整 TCP 帧。
        pub fn finish(self: *Builder, header: Header) []u8 {
            _ = self.flushReservedEdns();
            var h = header;
            h.qdcount = self.qd;
            h.ancount = self.an;
            h.nscount = self.ns;
            h.arcount = self.ar;
            return self.encodeFinalFrame(h);
        }

        /// 收尾但使用调用方 header 的计数；若此前通过 `setEdns` 预留了未落盘的 OPT，
        /// 落盘该条 OPT 时同步将 `header.arcount` 加 1 以免产生未计数的 `TrailingBytes`。
        pub fn finishRaw(self: *Builder, header: Header) []u8 {
            const flushed_opt = self.flushReservedEdns();
            var h = header;
            if (flushed_opt) h.arcount +|= 1;
            return self.encodeFinalFrame(h);
        }

        /// TCP 收尾：写入 2 字节大端长度前缀（RFC 1035 4.2.2），返回含前缀的完整帧。
        /// 必须由 initTcp 创建（UDP 构造器误调返回 `Error.InvalidRecordOrder`）。计数同样自动回填。
        pub fn finishTcp(self: *Builder, header: Header) Error![]u8 {
            if (self.prefix_len != 2) return Error.InvalidRecordOrder;
            return self.finish(header);
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

test "Parser and Builder share the 255-including-root name limit (RFC 1035 2.3.4)" {
    const MessageParser = @import("parser.zig").MessageParser;
    // 3×63 + 1×61 标签：线格式 = 64*3 + 62 + 1(根) = 255 -> 双方都必须接受；
    // 末标签改成 62 -> 256 -> 双方都必须拒绝。
    // 两侧规则若不一致，解析得到的 QNAME 就可能无法原样回显（权威/递归的常见路径）。
    const S = struct {
        fn dotted(out: []u8, last: usize) []const u8 {
            var pos: usize = 0;
            for (0..3) |_| {
                @memset(out[pos..][0..63], 'a');
                out[pos + 63] = '.';
                pos += 64;
            }
            @memset(out[pos..][0..last], 'b');
            return out[0 .. pos + last];
        }
    };

    var name_buf: [512]u8 = undefined;
    const ok_name = S.dotted(&name_buf, 61);

    // Builder 接受 255，且写出的线格式恰为 255 字节。
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion(ok_name, .A, 1);
    try std.testing.expectEqual(@as(usize, 12 + 255 + 4), builder.pos);

    // 该报文能被解析回来，名字一致（解析 -> 重建的闭环）。
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    const q = (try parser.nextQuestion()).?;
    try std.testing.expect(try parser.nameEqualsAt(q.name_pos, ok_name));

    // 256 在构造侧同样是 NameTooLong（解析侧见 parser.zig 的对应测试）。
    var long_buf: [512]u8 = undefined;
    const too_long = S.dotted(&long_buf, 62);
    var builder2 = try Message.Builder.init(&buf);
    try std.testing.expectError(error.NameTooLong, builder2.addQuestion(too_long, .A, 1));
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

test "Message.Builder registers prefixes of compressed names" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // "example.com" 展开写入。
    try builder.addARecord("example.com", 3600, [_]u8{ 192, 0, 2, 1 });
    // "www.example.com" 压缩为 "www" + 指针；此处新写出的 www.example.com 本身
    // 也必须进表，否则下面的 foo.www.example.com 只能指向 example.com。
    const www_off = builder.pos;
    try builder.addARecord("www.example.com", 3600, [_]u8{ 192, 0, 2, 2 });

    const pos1 = builder.pos;
    try builder.addARecord("foo.www.example.com", 3600, [_]u8{ 192, 0, 2, 3 });
    // owner = "foo"(4) + 指向 www.example.com 的指针(2) = 6 字节；固定部分 14。
    // 未登记前缀时只能指向 example.com，owner 会是 "foo"+"www"+指针 = 10 字节。
    try std.testing.expectEqual(@as(usize, 6 + 14), builder.pos - pos1);
    // 指针确实指向 www.example.com 的起点。
    try std.testing.expectEqual(@as(u16, 0xC000 | @as(u16, @intCast(www_off))), mem.readInt(u16, buf[pos1 + 4 ..][0..2], .big));

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com", try parser.formatNameAt(www_off, &nbuf));
    try std.testing.expectEqualStrings("foo.www.example.com", try parser.formatNameAt(pos1, &nbuf));
}

test "Message.Builder compression table survives more than 32 distinct suffixes" {
    // 32 槽的老表在 NSEC 链 / 大量胶水这类多名字应答里很快填满，之后所有名字整名展开。
    const MessageParser = @import("parser.zig").MessageParser;
    const dest = try std.testing.allocator.alloc(u8, 8192);
    defer std.testing.allocator.free(dest);
    var builder = try Message.Builder.init(dest);

    // 40 个互不相同的二级域，每个占 2 个后缀槽（nsN.example / example）——
    // 前 32 个之后老实现的表已满。
    var name_buf: [64]u8 = undefined;
    for (0..40) |i| {
        const name = try std.fmt.bufPrint(&name_buf, "ns{d}.zone{d}.example", .{ i, i });
        try builder.addARecord(name, 60, [_]u8{ 10, 0, 0, @intCast(i) });
    }

    // 复用第 39 个域名：表未满则应压缩成 2 字节指针（owner 6+14=20 -> 2+14=16）。
    const last = try std.fmt.bufPrint(&name_buf, "ns39.zone39.example", .{});
    const pos1 = builder.pos;
    try builder.addARecord(last, 60, [_]u8{ 10, 0, 1, 1 });
    try std.testing.expectEqual(@as(usize, 2 + 14), builder.pos - pos1);

    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("ns39.zone39.example", try parser.formatNameAt(pos1, &nbuf));
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
    try std.testing.expectEqual(@as(u16, 257), @backingInt(rr.rtype));
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
    try std.testing.expectEqual(@as(u16, 16), @backingInt(rr.rtype));
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
    try std.testing.expectEqual(@as(u16, 257), @backingInt(rr.rtype));
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

test "Message.Builder addSVCBRecord rejects out-of-order SvcParams (RFC 9460)" {
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    const params = "\x00\x03\x00\x00" ++ "\x00\x01\x00\x00"; // key 3 然后 key 1，递减非法
    try std.testing.expectError(error.InvalidRData, builder.addSVCBRecord("svc.example.com", 3600, 1, "svc.example.com", params));
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
    try std.testing.expectEqual(@as(u16, 65), @backingInt(rr.rtype));
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
    try std.testing.expectEqual(@as(u16, 48), @backingInt(rr.rtype));
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
        .next_hashed_owner = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14", // SHA-1 = 20 字节
        .types = &[_]u16{ 1, 15 },
    });
    const packet = builder.finish(.{ .id = 1, .rd = 0, .tc = 0, .aa = 1, .opcode = 0, .qr = 1, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    var parser = MessageParser.init(packet);
    var rrs = parser.resourceRecords(2);
    const rd1 = try parser.parseRData((try rrs.next()).?);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }, rd1.NSEC3PARAM.salt);
    const rd2 = try parser.parseRData((try rrs.next()).?);
    try std.testing.expectEqual(@as(u16, 10), rd2.NSEC3.iterations);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 }, rd2.NSEC3.next_hashed_owner);
    var it = rd2.NSEC3.types.iterator();
    try std.testing.expectEqual(@as(u16, 1), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 15), (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "Message.Builder addNSEC3Record rejects non-20-byte SHA-1 hash (RFC 5155)" {
    // SHA-1（算法 1）哈希须 20 字节；5 字节须在构造端即拒绝，避免发出解析器会拒的记录。
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try std.testing.expectError(error.InvalidRData, builder.addNSEC3Record("example.com", 3600, .{
        .hash_algorithm = 1,
        .flags = 0,
        .iterations = 0,
        .salt = "",
        .next_hashed_owner = "\x01\x02\x03\x04\x05",
        .types = &[_]u16{},
    }));
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
    // 非法报文必须手工拼字节：Builder 本身已拒绝写第二个 OPT（见下一条测试），
    // 用它构造这个 fixture 就等于用被测约束去证明另一处约束。
    var packet: [64]u8 = undefined;
    @memset(packet[0..12], 0);
    var pos: usize = 12;
    inline for (.{ 1232, 4096 }) |udp_size| {
        packet[pos] = 0; // 根 owner
        pos += 1;
        mem.writeInt(u16, packet[pos..][0..2], @backingInt(Type.OPT), .big);
        mem.writeInt(u16, packet[pos + 2 ..][0..2], udp_size, .big);
        mem.writeInt(u32, packet[pos + 4 ..][0..4], 0, .big);
        mem.writeInt(u16, packet[pos + 8 ..][0..2], 0, .big); // RDLENGTH=0
        pos += 10;
    }

    var parser = MessageParser.init(packet[0..pos]);
    try std.testing.expectError(error.MultipleOptRecords, parser.findEdns(2));
}

test "Message.Builder rejects a second OPT record (RFC 6891 6.1.1)" {
    // 只用 Builder 的服务端不得发出自家严格解析路径会判 FORMERR 的报文。
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addQuestion("example.com", .A, 1);
    try builder.addOptRecord(.{ .udp_payload_size = 1232 });

    const snap_pos = builder.pos;
    const snap_ar = builder.ar;
    try std.testing.expectError(error.MultipleOptRecords, builder.addOptRecord(.{ .udp_payload_size = 4096 }));
    try std.testing.expectError(error.MultipleOptRecords, builder.addOptRecordRaw(4096, 0, &[_]u8{}));
    // 失败必须完全原子：pos 与计数都不动。
    try std.testing.expectEqual(snap_pos, builder.pos);
    try std.testing.expectEqual(snap_ar, builder.ar);

    const packet = builder.finish(.{ .id = 1, .rd = 1, .tc = 0, .aa = 0, .opcode = 0, .qr = 0, .rcode = 0, .z = 0, .ra = 0, .qdcount = 0, .ancount = 0, .nscount = 0, .arcount = 0 });
    const msg = try Message.parse(packet);
    try std.testing.expectEqual(@as(u16, 1), msg.header.arcount);
    var parser = MessageParser.init(packet);
    try parser.skipQuestions(msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 1232), (try parser.findEdns(msg.header.arcount)).?.opt.class);
}

test "Message.Builder addRecordRaw cannot smuggle in a second OPT" {
    // addRecordRaw 接受原始 u16 type，若不认 41 就是绕过 addOptRecord 检查的后门：
    // 仍能发出自家 findEdns 判 MultipleOptRecords 的报文。
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addOptRecord(.{ .udp_payload_size = 1232 });

    const snap_pos = builder.pos;
    const snap_ar = builder.ar;
    try std.testing.expectError(error.MultipleOptRecords, builder.addRecordRaw("", @backingInt(Type.OPT), 4096, 0, &[_]u8{}));
    try std.testing.expectEqual(snap_pos, builder.pos);
    try std.testing.expectEqual(snap_ar, builder.ar);

    // 反向：先用 addRecordRaw 写 OPT，再走 addOptRecord 同样要被挡住。
    var builder2 = try Message.Builder.init(&buf);
    try builder2.setSection(.additional);
    try builder2.addRecordRaw("", @backingInt(Type.OPT), 1232, 0, &[_]u8{});
    try std.testing.expectError(error.MultipleOptRecords, builder2.addOptRecord(.{ .udp_payload_size = 4096 }));
    try std.testing.expectError(error.MultipleOptRecords, builder2.addRecordRaw("", @backingInt(Type.OPT), 4096, 0, &[_]u8{}));

    // 非 OPT 类型不受影响，可以写任意多条。
    try builder2.addRecordRaw("example.com", 99, 1, 60, "\x01\x02");
    try builder2.addRecordRaw("example.com", 99, 1, 60, "\x03\x04");
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

    // 第一条：owner "foo.example" 展开写入（偏移 12），触发惰性入表后篡改压缩项 hash
    try builder.addARecord("foo.example", 60, .{ 1, 1, 1, 1 });
    builder.flushFirstUnindexed();

    // 伪造 hash 碰撞：把所有压缩项的 hash 改成 "bar.example" 线格式后缀的 hash，
    // 但它们的 pos 仍指向 "foo.example"/"example"。
    const collide = Message.Builder.hashWireSuffix("\x03bar\x07example");
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
    const ip = @as([16]u8, @splat(0));
    try std.testing.expectError(error.BufferTooSmall, builder.addAAAARecord("example.com", 3600, ip));
}

test "Message.Builder round-trips escaped presentation names (RFC 1035 5.1)" {
    const MessageParser = @import("parser.zig").MessageParser;
    const cases = [_]struct { wire: []const u8, pres: []const u8 }{
        .{ .wire = "\x01.\x00", .pres = "\\." },
        .{ .wire = "\x0bexample.com\x00", .pres = "example\\.com" },
        .{ .wire = "\x01.\x03com\x00", .pres = "\\..com" },
        .{ .wire = "\x05a\\b\x00\xff\x03com\x00", .pres = "a\\\\b\\000\\255.com" },
    };
    for (cases) |c| {
        var msg_in: [64]u8 = @splat(0);
        @memcpy(msg_in[12..][0..c.wire.len], c.wire);
        const p_in = MessageParser.init(msg_in[0 .. 12 + c.wire.len]);
        var str_buf: [256]u8 = undefined;
        const formatted = try p_in.formatNameAt(12, &str_buf);
        try std.testing.expectEqualStrings(c.pres, formatted);

        // 重编码后线格式字节必须与原输入完全一致（无损闭环）
        var out_pkt: [128]u8 = undefined;
        var builder = try Message.Builder.init(&out_pkt);
        try builder.addQuestion(formatted, .A, 1);
        const pkt = builder.finish(.{ .id = 1 });
        try std.testing.expectEqualSlices(u8, c.wire, pkt[12 .. 12 + c.wire.len]);
    }
}

test "Message.parseTcpFrame distinguishes MalformedHeader (<12B) from PacketTooShort" {
    // 声明 msg_len=0 或 msg_len=4 (<12) 的帧永远不可能合法 -> MalformedHeader
    try std.testing.expectError(error.MalformedHeader, Message.parseTcpFrame("\x00\x00"));
    try std.testing.expectError(error.MalformedHeader, Message.parseTcpFrame("\x00\x04abcd"));
    // 仅收到 1 字节长度头，或 msg_len>=12 但载荷未收齐 -> PacketTooShort（继续读套接字）
    try std.testing.expectError(error.PacketTooShort, Message.parseTcpFrame("\x00"));
    try std.testing.expectError(error.PacketTooShort, Message.parseTcpFrame("\x00\x10abcd"));
}

test "Edns and Builder enforce strict OPT section, root owner, and TLV validity" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [512]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // 默认处于 .answer 分区：addRecordRaw 写 OPT 须报 InvalidRecordOrder
    try std.testing.expectError(error.InvalidRecordOrder, builder.addRecordRaw("", 41, 1232, 0, ""));
    try builder.setSection(.additional);
    // 非根 owner 写 OPT 须报 MalformedName
    try std.testing.expectError(error.MalformedName, builder.addRecordRaw("example.com", 41, 1232, 0, ""));
    // 畸形 TLV 写 OPT 须报 InvalidRData 且保持原子回滚（opt_added 仍为 false）
    try std.testing.expectError(error.InvalidRData, builder.addOptRecordRaw(1232, 0, "\xff\xff"));
    try builder.addOptRecordRaw(1232, 0, "");

    // Edns.fromOpt 拒绝非 OPT 记录与非单字节根 owner 的 OPT 记录
    const non_opt = ResourceRecord{
        .name_pos = 12,
        .name_end_pos = 13,
        .rtype = .A,
        .class = 1,
        .ttl = 60,
        .rdlength = 0,
        .rdata = "",
        .rdata_offset = 23,
    };
    try std.testing.expectError(error.InvalidType, Edns.fromOpt(non_opt));

    const bad_owner_opt = ResourceRecord{
        .name_pos = 12,
        .name_end_pos = 15, // 非单字节根（如 "\x01a\x00"）
        .rtype = .OPT,
        .class = 1232,
        .ttl = 0,
        .rdlength = 0,
        .rdata = "",
        .rdata_offset = 25,
    };
    try std.testing.expectError(error.MalformedName, Edns.fromOpt(bad_owner_opt));

    // NSEC 构造拒绝空位图；CAA 构造拒绝非字母数字 tag
    var b2 = try Message.Builder.init(&buf);
    try std.testing.expectError(error.InvalidRData, b2.addNSECRecord("example.com", 60, "a.example.com", &.{}));
    try std.testing.expectError(error.InvalidRData, b2.addCAARecord("example.com", 60, 0, "issue;", "ca.example.net"));
    _ = MessageParser;
}

test "Message.Builder restores bucket index cleanly after failed add above threshold" {
    const MessageParser = @import("parser.zig").MessageParser;
    var buf: [420]u8 = undefined;
    var builder = try Message.Builder.init(&buf);

    // 写入 10 个不同二级域（>16 个后缀槽，触发 64 桶索引构建）
    var nbuf: [64]u8 = undefined;
    for (0..10) |i| {
        const name = try std.fmt.bufPrint(&nbuf, "h{d}.z{d}.example", .{ i, i });
        try builder.addARecord(name, 60, .{ 10, 0, 0, @intCast(i) });
    }
    try std.testing.expect(builder.compression_count > Message.Builder.BUCKET_THRESHOLD);

    // 构造一条新名字 + 超长 TXT 令其在已写入部分前缀并入桶后触发 BufferTooSmall 回滚
    var big_txt: [200]u8 = @splat('x');
    const snap_pos = builder.pos;
    const snap_count = builder.compression_count;
    try std.testing.expectError(error.BufferTooSmall, builder.addTXTRecord("rollback.newzone.example", 60, &big_txt));
    try std.testing.expectEqual(snap_pos, builder.pos);
    try std.testing.expectEqual(snap_count, builder.compression_count);

    // 回滚后桶索引不得残留悬垂槽位，继续压缩已有名字仍须正常命中并可解析
    const reuse_pos = builder.pos;
    try builder.addARecord("h9.z9.example", 60, .{ 10, 0, 1, 9 });
    try std.testing.expectEqual(@as(usize, 2 + 14), builder.pos - reuse_pos);

    const pkt = builder.finish(.{ .id = 1, .qr = 1 });
    const parser = MessageParser.init(pkt);
    var out: [256]u8 = undefined;
    try std.testing.expectEqualStrings("h9.z9.example", try parser.formatNameAt(reuse_pos, &out));
}

test "Message.Builder setEdns preserves OPT across TC=1 truncation and prevents silent NODATA (RFC 6891 §7)" {
    // 缓冲区 56 字节：Header(12) + Question(17) + 预留裸 OPT(11) = 40，仅够再放 1 条压缩 A 记录(+16 -> 56)
    var buf: [56]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.setSection(.question); // 新建 Builder 允许显式 setSection(.question)
    try builder.addQuestion("example.com", .A, 1);

    // 提前预留 EDNS（含 CO 标志 0x4000 与小载荷 256），不改变当前分区
    var edns_cfg = Edns{ .udp_payload_size = 256, .z_flags = 0x4000 };
    try std.testing.expectEqual(@as(u16, 512), edns_cfg.effectiveUdpPayloadSize());
    try builder.setEdns(edns_cfg);

    // 第一条 A 自动进入 Answer 区，第二条因预留了 11B OPT 空间而触发 BufferTooSmall
    try builder.addARecord("example.com", 60, .{ 192, 0, 2, 1 });
    try std.testing.expectError(error.BufferTooSmall, builder.addARecord("example.com", 60, .{ 192, 0, 2, 2 }));

    var hdr = Header{ .id = 0x42, .qr = 1, .aa = 1, .tc = 1 };
    edns_cfg.setFullRcode(&hdr, .BADCOOKIE);
    try builder.updateEdns(edns_cfg);

    const pkt = builder.finish(hdr);
    try std.testing.expectEqual(@as(usize, 56), pkt.len);

    const parsed = try Message.parse(pkt);
    try std.testing.expectEqual(@as(u1, 1), parsed.header.tc);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.qdcount);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.ancount);
    try std.testing.expectEqual(@as(u16, 1), parsed.header.arcount);

    const decoded_edns = (try parsed.findEdns()).?;
    try std.testing.expectEqual(ExtendedRcode.BADCOOKIE, decoded_edns.fullRcode(parsed.header));
    try std.testing.expectEqual(@as(u15, 0x4000), decoded_edns.z_flags);
    try std.testing.expectEqual(@as(u16, 512), decoded_edns.effectiveUdpPayloadSize());

    // 直接走 addOptRecord 隐式跳到 additional 后若未 setSection(.additional) 继续写 A 记录须报错防静默 NODATA
    var buf2: [128]u8 = undefined;
    var b2 = try Message.Builder.init(&buf2);
    try b2.addQuestion("example.com", .A, 1);
    try b2.addOptRecord(.{});
    try std.testing.expectError(error.InvalidRecordOrder, b2.addARecord("example.com", 60, .{ 1, 2, 3, 4 }));
    // 显式确认处于 .additional 后允许继续添加附加区记录（如 TSIG）
    try b2.setSection(.additional);
    try b2.addARecord("ns1.example.com", 60, .{ 1, 2, 3, 4 });

    // 先切到 .authority 再调 addQuestion 须被拒绝
    var b3 = try Message.Builder.init(&buf2);
    try b3.setSection(.authority);
    try std.testing.expectError(error.InvalidRecordOrder, b3.addQuestion("example.com", .A, 1));

    // addOptRecordRaw 同样触发隐式附加区保护锁，显式 setSection(.additional) 后解锁
    var b4 = try Message.Builder.init(&buf2);
    try b4.addQuestion("example.com", .A, 1);
    try b4.addOptRecordRaw(1232, 0, "");
    try std.testing.expectError(error.InvalidRecordOrder, b4.addARecord("example.com", 60, .{ 1, 2, 3, 4 }));
    try b4.setSection(.additional);
    try b4.addRecordRaw("example.com", @backingInt(Type.TSIG), @backingInt(@import("types.zig").Class.ANY), 0, "\x01\x02");

    // setEdns 配合 initTcp / finishTcp 在 TCP 帧末尾自动落盘 OPT 且可由 parseTcp + findEdns 往返解析
    var tcp_buf: [128]u8 = undefined;
    var tb = try Message.Builder.initTcp(&tcp_buf);
    try tb.addQuestion("example.com", .A, 1);
    try tb.setEdns(.{ .udp_payload_size = 4096, .dnssec_ok = true });
    try tb.addARecord("example.com", 300, .{ 93, 184, 216, 34 });
    const tcp_frame = try tb.finishTcp(.{ .id = 0x99, .qr = 1, .aa = 1 });
    const tcp_msg = try Message.parseTcp(tcp_frame);
    try std.testing.expectEqual(@as(u16, 1), tcp_msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 1), tcp_msg.header.ancount);
    try std.testing.expectEqual(@as(u16, 1), tcp_msg.header.arcount);
    const tcp_edns = (try tcp_msg.findEdns()).?;
    try std.testing.expectEqual(@as(u16, 4096), tcp_edns.udp_payload_size);
    try std.testing.expect(tcp_edns.dnssec_ok);
}

test "Message.Builder writeNameRaw registers suffixes for subsequent glue compression and rolls back cleanly" {
    // 1. SRV target 自身不压缩（RFC 2782），但紧随其后的附加区胶水 A 记录 owner 压缩为 2 字节指针
    var buf: [256]u8 = undefined;
    var builder = try Message.Builder.init(&buf);
    try builder.addSRVRecord("_sip._tcp.example.com", 300, 10, 20, 5060, "sip1.svc.example.net");
    try builder.setSection(.additional);
    const glue_a_start = builder.pos;
    try builder.addARecord("sip1.svc.example.net", 300, .{ 192, 0, 2, 10 });
    // 胶水 A 记录总长应为 2(压缩指针) + 10(固定头) + 4(IPv4) = 16 字节
    try std.testing.expectEqual(@as(usize, 16), builder.pos - glue_a_start);

    // 2. HTTPS TargetName 自身不压缩（RFC 9460 §2.2），后续胶水 AAAA 记录 owner 同样压缩为 2 字节指针
    var b_https = try Message.Builder.init(&buf);
    try b_https.addHTTPSRecord("example.com", 300, 1, "h3.cdn.example.org", "\x00\x03\x00\x02\x01\xbb");
    try b_https.setSection(.additional);
    const glue_aaaa_start = b_https.pos;
    try b_https.addAAAARecord("h3.cdn.example.org", 300, @splat(1));
    // 2(压缩指针) + 10(固定头) + 16(IPv6) = 28 字节
    try std.testing.expectEqual(@as(usize, 28), b_https.pos - glue_aaaa_start);

    const pkt = b_https.finish(.{ .id = 1, .qr = 1, .aa = 1 });
    const msg = try Message.parse(pkt);
    var secs = msg.sections();
    const ans = (try secs.nextAnswer()).?;
    const https_rd = try secs.parseRData(ans);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("h3.cdn.example.org", try https_rd.HTTPS.target.str(&nbuf));
    const glue = (try secs.nextAdditional()).?;
    try std.testing.expect(try secs.nameEqualsAt(glue.name_pos, "h3.cdn.example.org"));
    try secs.expectEnd();

    // 3. SVCB 写完未压缩 target 并入压缩表后若因 params 超出缓冲区失败，压缩表登记必须随快照一并回滚：
    // Header(12) + owner "a.example"(11) + 固定头(10) + priority(2) + target "ghost.target.invalid"(22) = 57B <= 60B，
    // 确保 writeNameRaw 已完成写入与登记，随后因 20B params (57+20=77 > 60) 触发回滚。
    var tight: [60]u8 = undefined;
    var b_rollback = try Message.Builder.init(&tight);
    const big_params = "\x00\x04\x00\x10" ++ "\xc0\x00\x02\x01\xc0\x00\x02\x02\xc0\x00\x02\x03\xc0\x00\x02\x04";
    try std.testing.expectError(
        error.BufferTooSmall,
        b_rollback.addSVCBRecord("a.example", 60, 1, "ghost.target.invalid", big_params),
    );
    try std.testing.expectEqual(@as(u8, 0), b_rollback.compression_count);
    // 后续写入同名记录不得指向刚才已回滚废弃的字节，owner 必须完整展开为 22 字节而非 2 字节指针
    try b_rollback.addARecord("ghost.target.invalid", 60, .{ 1, 1, 1, 1 });
    const rb_pkt = b_rollback.finish(.{ .id = 2, .qr = 1 });
    var rb_parser = Parser.init(rb_pkt);
    const rb_rr = (try rb_parser.nextRR()).?;
    try std.testing.expectEqual(@as(usize, 22), rb_rr.name_end_pos - rb_rr.name_pos);
    try std.testing.expectEqualStrings("ghost.target.invalid", try rb_parser.formatNameAt(rb_rr.name_pos, &nbuf));
}

test "Message.findEdns and SectionParser handle QDCOUNT=0 Cookie probes, misplaced OPT, and trailing bytes" {
    // 1. RFC 7873 §5.4: QDCOUNT=0, ARCOUNT=1 的纯 Cookie 探测包
    var probe_buf: [64]u8 = undefined;
    var pb = try Message.Builder.init(&probe_buf);
    try pb.addOptRecord(.{
        .cookie = .{ .client = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .server = "" },
        .extra_options = "\x00\x0f\x00\x02\x00\x12", // 附带 EDE(15)
    });
    const probe_pkt = pb.finish(.{ .id = 7 });
    const probe_msg = try Message.parse(probe_pkt);
    try std.testing.expectEqual(@as(u16, 0), probe_msg.header.qdcount);

    var secs = probe_msg.sections();
    try std.testing.expect((try secs.nextQuestion()) == null); // 绝不误把 OPT 当 Question
    const opt_rr = (try secs.nextAdditional()).?;
    try std.testing.expectEqual(Type.OPT, opt_rr.rtype);
    try secs.expectEnd();

    const probe_edns = (try probe_msg.findEdns()).?;
    var opt_it = probe_edns.optionsIterator();
    try std.testing.expectEqual(OptionCode.COOKIE, (try opt_it.next()).?.code);
    try std.testing.expectEqual(OptionCode.EDE, (try opt_it.next()).?.code);
    try std.testing.expect((try opt_it.next()) == null);

    // 2. 报文末尾夹带多余字节 -> Message.findEdns 报 TrailingBytes
    var with_trail: [64]u8 = @splat(0);
    @memcpy(with_trail[0..probe_pkt.len], probe_pkt);
    const trail_msg = try Message.parse(with_trail[0 .. probe_pkt.len + 2]);
    try std.testing.expectError(error.TrailingBytes, trail_msg.findEdns());

    // 3. OPT 混入 Answer 区 -> Message.findEdns 与 SectionParser 均报 MisplacedOptRecord
    var bad_ans: [32]u8 = @splat(0);
    bad_ans[7] = 1; // ANCOUNT = 1
    bad_ans[12] = 0; // root
    mem.writeInt(u16, bad_ans[13..15], @backingInt(Type.OPT), .big);
    mem.writeInt(u16, bad_ans[15..17], 1232, .big);
    const bad_msg = try Message.parse(bad_ans[0..23]);
    try std.testing.expectError(error.MisplacedOptRecord, bad_msg.findEdns());
    var bad_secs = bad_msg.sections();
    try std.testing.expectError(error.MisplacedOptRecord, bad_secs.nextAnswer());
}

test "SectionParser caches single-pass edns() and supports skip* helpers; consumeEdns advances cursor" {
    var buf: [256]u8 = undefined;
    var b = try Message.Builder.init(&buf);
    try b.addQuestion("example.com", .A, 1);
    try b.addARecord("example.com", 60, .{ 93, 184, 216, 34 });
    try b.setSection(.authority);
    try b.addNSRecord("example.com", 300, "ns1.example.com");
    try b.setEdns(.{
        .udp_payload_size = 1400,
        .dnssec_ok = true,
        .cookie = .{ .client = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .server = "" },
    });
    const pkt = b.finish(.{ .id = 11, .qr = 1, .aa = 1 });

    // 1. SectionParser 单趟跳过中间分区并通过 edns() 直接拿到缓存的完整 Edns
    const msg = try Message.parse(pkt);
    var secs = msg.sections();
    _ = (try secs.nextQuestion()).?;
    try secs.skipAnswers();
    try secs.skipAuthorities();
    try secs.skipAdditionals();
    try secs.expectEnd();
    const cached = secs.edns().?;
    try std.testing.expectEqual(@as(u16, 1400), cached.udp_payload_size);
    try std.testing.expect(cached.dnssec_ok);
    try std.testing.expect(cached.cookie != null);

    // 2. MessageParser.consumeEdns 一次解出 params 并推进游标至末尾供 expectEnd 直接校验
    var mp = Parser.init(pkt);
    try mp.skipQuestions(msg.header.qdcount);
    try mp.skipNonAdditionalRecords(@as(usize, msg.header.ancount) + msg.header.nscount);
    const consumed = (try mp.consumeEdns(msg.header.arcount)).?;
    try std.testing.expectEqual(@as(u16, 1400), consumed.params.udp_payload_size);
    try std.testing.expect(consumed.params.dnssec_ok);
    try mp.expectEnd();
}

test "Builder rejects duplicate/malformed COOKIE on encode, supports withPreservedOptions, TSIG ordering, and TCP/Raw finish" {
    var buf: [512]u8 = undefined;
    const valid_cookie = @import("types.zig").CookieData{ .client = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .server = "" };
    const valid_cookie_tlv = "\x00\x0a\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08";
    const bad_cookie_tlv = "\x00\x0a\x00\x03\xff\xff\xff";

    // 1. 构造侧严禁重复 COOKIE 或夹带畸形次条 COOKIE
    var b1 = try Message.Builder.init(&buf);
    try std.testing.expectError(error.MalformedCookie, b1.addOptRecord(.{
        .cookie = valid_cookie,
        .extra_options = valid_cookie_tlv,
    }));
    try std.testing.expectError(error.MalformedCookie, b1.addOptRecordRaw(1232, 0, valid_cookie_tlv ++ bad_cookie_tlv));
    try b1.setSection(.additional);
    try std.testing.expectError(error.MalformedCookie, b1.addRecordRaw("", @backingInt(Type.OPT), 1232, 0, valid_cookie_tlv ++ bad_cookie_tlv));

    // 2. withPreservedOptions 过滤 ECS/COOKIE 并无损保留 NSID/EDE 等其余 TLV
    var b_in = try Message.Builder.init(&buf);
    try b_in.addOptRecord(.{
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0, .address = &[_]u8{ 192, 0, 2 } },
        .cookie = valid_cookie,
        .extra_options = "\x00\x03\x00\x03ns1\x00\x0f\x00\x02\x00\x12",
    });
    const in_pkt = b_in.finish(.{ .id = 1 });
    const parsed_edns = (try (try Message.parse(in_pkt)).findEdns()).?;

    var extra_buf: [64]u8 = undefined;
    var forwarded = try parsed_edns.withPreservedOptions(&extra_buf);
    forwarded.cookie = .{ .client = valid_cookie.client, .server = "\xaa\xbb\xcc\xdd\xee\xff\x11\x22" };

    var out_buf: [512]u8 = undefined;
    var b_out = try Message.Builder.init(&out_buf);
    try b_out.setEdns(forwarded);
    const out_pkt = b_out.finish(.{ .id = 1, .qr = 1 });
    const re_edns = (try (try Message.parse(out_pkt)).findEdns()).?;
    try std.testing.expectEqual(@as(usize, 8), re_edns.cookie.?.server.len);
    var it = re_edns.optionsIterator();
    try std.testing.expectEqual(OptionCode.ECS, (try it.next()).?.code);
    try std.testing.expectEqual(OptionCode.COOKIE, (try it.next()).?.code);
    try std.testing.expectEqual(OptionCode.NSID, (try it.next()).?.code);
    try std.testing.expectEqual(OptionCode.EDE, (try it.next()).?.code);
    try std.testing.expect((try it.next()) == null);

    // 3. setEdns 配合尾置 TSIG（RFC 8945 §5.1）：保证顺序为 [OPT, TSIG]，且 TSIG 后禁止追加记录；若 TSIG 失败则原子回滚预留 OPT
    var tight_tsig: [48]u8 = undefined;
    var b_tsig_rb = try Message.Builder.init(&tight_tsig);
    try b_tsig_rb.addQuestion("example.com", .A, 1); // pos = 29
    try b_tsig_rb.setEdns(.{ .udp_payload_size = 1232 }); // 预留 11B -> 剩余 8B
    try b_tsig_rb.setSection(.additional);
    try std.testing.expectError(
        error.BufferTooSmall,
        b_tsig_rb.addRecordRaw("key.example", @backingInt(Type.TSIG), @backingInt(@import("types.zig").Class.ANY), 0, "\x00\x01\x02\x03"),
    );
    // 失败后预留 OPT 与 pos 必须完整回滚，仍可置 TC=1 发出带 OPT 的截断响应
    const rb_pkt = b_tsig_rb.finish(.{ .id = 9, .qr = 1, .tc = 1 });
    const rb_msg = try Message.parse(rb_pkt);
    try std.testing.expectEqual(@as(u16, 1), rb_msg.header.arcount);
    try std.testing.expect((try rb_msg.findEdns()) != null);

    var b_tsig = try Message.Builder.init(&buf);
    try b_tsig.addQuestion("example.com", .A, 1);
    try b_tsig.setEdns(.{ .udp_payload_size = 1232 });
    try b_tsig.setSection(.additional);
    try b_tsig.addRecordRaw("key.example", @backingInt(Type.TSIG), @backingInt(@import("types.zig").Class.ANY), 0, "\x00\x00");
    // TSIG 之后禁止再追加任何记录
    try std.testing.expectError(error.InvalidRecordOrder, b_tsig.addARecord("example.com", 60, .{ 1, 2, 3, 4 }));
    const tsig_pkt = b_tsig.finish(.{ .id = 10, .qr = 1 });
    var tsig_secs = (try Message.parse(tsig_pkt)).sections();
    _ = (try tsig_secs.nextQuestion()).?;
    try std.testing.expectEqual(Type.OPT, (try tsig_secs.nextAdditional()).?.rtype);
    try std.testing.expectEqual(Type.TSIG, (try tsig_secs.nextAdditional()).?.rtype);
    try tsig_secs.expectEnd();

    // 4. initTcp + finish 自动回填 2B 长度头；setEdns + finishRaw 自动同步 arcount
    var tcp_buf: [128]u8 = @splat(0xAA);
    var b_tcp = try Message.Builder.initTcp(&tcp_buf);
    try b_tcp.addQuestion("example.com", .A, 1);
    const tcp_frame = b_tcp.finish(.{ .id = 0x55 });
    const parsed_tcp = try Message.parseTcp(tcp_frame);
    try std.testing.expectEqual(@as(u16, 0x55), parsed_tcp.header.id);

    var b_raw = try Message.Builder.init(&buf);
    try b_raw.setEdns(.{ .udp_payload_size = 1232 });
    const raw_pkt = b_raw.finishRaw(.{ .id = 0x66 });
    try std.testing.expect((try (try Message.parse(raw_pkt)).findEdns()) != null);
}

test "Builder supports CDS/CDNSKEY/DNAME/HINFO/SSHFP/TLSA, escaped-name compression, addQuestionFrom, and reset" {
    var buf: [1024]u8 = undefined;
    var b = try Message.Builder.init(&buf);
    try std.testing.expect(@sizeOf(Message.Builder) <= 1280);

    // 1. 含 `\032` 与 `\.` 的 DNS-SD 实例名参与整名及公共后缀压缩
    const dnssd = "My\\032Server\\.1._http._tcp.local";
    try b.addQuestion(dnssd, .SRV, 1);
    const p1 = b.pos;
    try b.addTXTRecord(dnssd, 120, "txtvers=1");
    // owner 压缩为 2 字节指针：2 + 10(固定头) + 10(TXT) = 22 字节
    try std.testing.expectEqual(@as(usize, 22), b.pos - p1);
    const p2 = b.pos;
    try b.addARecord("host._http._tcp.local", 120, .{ 192, 0, 2, 9 });
    // 共享后缀 "_http._tcp.local" 压缩为 2 字节指针："host"(5) + 2 + 10 + 4 = 21 字节
    try std.testing.expectEqual(@as(usize, 21), b.pos - p2);

    const dnssd_pkt = b.finish(.{ .id = 1, .qr = 1, .aa = 1 });
    const dnssd_msg = try Message.parse(dnssd_pkt);
    var dnssd_secs = dnssd_msg.sections();
    const q = (try dnssd_secs.nextQuestion()).?;
    try std.testing.expect(try dnssd_secs.nameEqualsAt(q.name_pos, dnssd));
    const txt_rr = (try dnssd_secs.nextAnswer()).?;
    try std.testing.expect(try dnssd_secs.nameEqualsAt(txt_rr.name_pos, dnssd));
    const a_rr = (try dnssd_secs.nextAnswer()).?;
    try std.testing.expect(try dnssd_secs.nameEqualsAt(a_rr.name_pos, "host._http._tcp.local"));
    try dnssd_secs.expectEnd();

    // 2. reset 复用 Builder + addQuestionFrom 零转义回显 Question + 新增 6 种记录往返
    var resp_buf: [1024]u8 = undefined;
    try b.reset(&resp_buf);
    try b.addQuestionFrom(dnssd_pkt, q);
    try b.addDNAMERecord("alias.example.com", 300, "target.example.com");
    try b.addHINFORecord("example.com", 60, "RFC8482", "");
    try b.addSSHFPRecord("example.com", 300, 4, 2, "\xaa\xbb\xcc\xdd");
    try b.addTLSARecord("_443._tcp.example.com", 300, 3, 1, 1, "\x11\x22\x33\x44");
    try b.addCDSRecord("example.com", 3600, 0x3039, 8, 2, "\xde\xad\xbe\xef");
    try b.addCDNSKEYRecord("example.com", 3600, 257, 3, 8, "PUBKEY");

    const all_pkt = b.finish(.{ .id = 2, .qr = 1, .aa = 1 });
    var secs = (try Message.parse(all_pkt)).sections();
    const echoed_q = (try secs.nextQuestion()).?;
    try std.testing.expect(try secs.nameEqualsAt(echoed_q.name_pos, dnssd));

    var nbuf: [256]u8 = undefined;
    const r_dname = try secs.parseRData((try secs.nextAnswer()).?);
    try std.testing.expectEqualStrings("target.example.com", try r_dname.DNAME.str(&nbuf));
    const r_hinfo = try secs.parseRData((try secs.nextAnswer()).?);
    try std.testing.expectEqualStrings("RFC8482", r_hinfo.HINFO.cpu);
    const r_sshfp = try secs.parseRData((try secs.nextAnswer()).?);
    try std.testing.expectEqual(@as(u8, 4), r_sshfp.SSHFP.algorithm);
    const r_tlsa = try secs.parseRData((try secs.nextAnswer()).?);
    try std.testing.expectEqual(@as(u8, 3), r_tlsa.TLSA.usage);
    const r_cds = try secs.parseRData((try secs.nextAnswer()).?);
    try std.testing.expectEqual(@as(u16, 0x3039), r_cds.CDS.key_tag);
    const r_cdnskey = try secs.parseRData((try secs.nextAnswer()).?);
    try std.testing.expectEqualStrings("PUBKEY", r_cdnskey.CDNSKEY.public_key);
    try secs.expectEnd();
}

test "Edns.preservingOptions forwards non-ECS/COOKIE TLVs zero-copy without duplication" {
    var qbuf: [256]u8 = undefined;
    var qb = try Message.Builder.init(&qbuf);
    try qb.addQuestion("example.com", .A, 1);
    try qb.setEdns(.{
        .udp_payload_size = 1232,
        .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0, .address = &[_]u8{ 198, 51, 100 } },
        .cookie = .{ .client = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .server = &.{} },
        .extra_options = "\x00\x03\x00\x04ns01\x00\x0c\x00\x02\x00\x00", // NSID + Padding
    });
    const qpkt = qb.finish(.{ .id = 0x77 });
    const parsed_edns = (try (try Message.parse(qpkt)).findEdns()).?;

    var fbuf: [256]u8 = undefined;
    var fb = try Message.Builder.init(&fbuf);
    try fb.addQuestion("example.com", .A, 1);
    var fwd = parsed_edns.preservingOptions();
    fwd.ecs.?.scope_prefix = 24;
    fwd.cookie = .{ .client = parsed_edns.cookie.?.client, .server = "SRVCOOK!" };
    try fb.setEdns(fwd);
    const fpkt = fb.finish(.{ .id = 0x77, .qr = 1 });

    const out_edns = (try (try Message.parse(fpkt)).findEdns()).?;
    try std.testing.expectEqual(@as(u8, 24), out_edns.ecs.?.scope_prefix);
    try std.testing.expectEqualStrings("SRVCOOK!", out_edns.cookie.?.server);
    var it = out_edns.optionsIterator();
    try std.testing.expectEqual(OptionCode.ECS, (try it.next()).?.code);
    try std.testing.expectEqual(OptionCode.COOKIE, (try it.next()).?.code);
    const nsid = (try it.next()).?;
    try std.testing.expectEqual(OptionCode.NSID, nsid.code);
    try std.testing.expectEqualStrings("ns01", nsid.data);
    const pad = (try it.next()).?;
    try std.testing.expectEqual(OptionCode.PADDING, pad.code);
    try std.testing.expectEqual(@as(usize, 2), pad.data.len);
    try std.testing.expect((try it.next()) == null);
}
