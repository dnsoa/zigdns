const std = @import("std");
const mem = std.mem;
const Type = @import("types.zig").Type;
const OptionCode = @import("types.zig").OptionCode;
const ECSData = @import("types.zig").ECSData;
const CookieData = @import("types.zig").CookieData;
const Error = @import("errors.zig").Error;
const Name = @import("name.zig").Name;

fn parseECSOption(option_payload: []const u8) !ECSData {
    if (option_payload.len < 4) return error.MalformedECS;

    const family = mem.readInt(u16, option_payload[0..2], .big);
    const source_prefix = option_payload[2];
    const scope_prefix = option_payload[3];
    const address = option_payload[4..];

    // RFC 7871: 地址字节数必须恰为 ceil(source_prefix / 8)，
    // 且 source_prefix 不得超过地址族上限（IPv4=32, IPv6=128）。
    const max_prefix: u8 = switch (family) {
        1 => 32, // IPv4
        2 => 128, // IPv6
        else => return error.MalformedECS,
    };
    // RFC 7871: source 与 scope 均不得超过地址族上限。
    if (source_prefix > max_prefix or scope_prefix > max_prefix) return error.MalformedECS;
    const expected_len = (@as(usize, source_prefix) + 7) / 8;
    if (address.len != expected_len) return error.MalformedECS;

    return ECSData{
        .family = family,
        .source_prefix = source_prefix,
        .scope_prefix = scope_prefix,
        .address = address,
    };
}

/// Parses an OPT record's RDATA to find the ECS option
pub fn parseECS(rdata: []const u8) !?ECSData {
    if (rdata.len >= 11 and rdata[0] == 0 and rdata[1] == @intFromEnum(OptionCode.ECS)) {
        const len = (@as(u16, rdata[2]) << 8) | rdata[3];
        if (len > rdata.len - 4) return error.PacketTooShort;
        return try parseECSOption(rdata[4 .. 4 + len]);
    }

    var pos: usize = 0;
    while (pos + 4 <= rdata.len) {
        const code = (@as(u16, rdata[pos]) << 8) | rdata[pos + 1];
        const len = (@as(u16, rdata[pos + 2]) << 8) | rdata[pos + 3];
        pos += 4;

        if (len > rdata.len -| pos) return error.PacketTooShort;

        if (code == @intFromEnum(OptionCode.ECS)) {
            return try parseECSOption(rdata[pos .. pos + len]);
        }
        pos += len;
    }
    return null;
}

/// TXT RDATA：一个或多个 character-string（RFC 1035 §3.3.14），零拷贝。
/// `raw` 为完整 RDATA 线格式（各段 1 字节长度前缀 + 内容）。
/// parse 时已校验各段恰好平铺整个 RDATA，故迭代不会越界。
pub const TxtData = struct {
    raw: []const u8,

    pub const Iterator = struct {
        data: []const u8,
        pos: usize = 0,

        /// 返回下一段 character-string 的内容切片（不含长度前缀）；遍历结束返回 null。
        pub fn next(self: *Iterator) !?[]const u8 {
            if (self.pos >= self.data.len) return null;
            const len = self.data[self.pos];
            const start = self.pos + 1;
            if (start + len > self.data.len) return error.InvalidRData;
            self.pos = start + len;
            return self.data[start .. start + len];
        }
    };

    pub fn iterator(self: TxtData) Iterator {
        return .{ .data = self.raw };
    }
};

/// CAA RDATA（RFC 8659 §4.1）：flags(1) + tag长度(1) + tag + value。
pub const CaaData = struct {
    flags: u8, // bit 0 (0x80) = Issuer Critical
    tag: []const u8, // US-ASCII 属性名（如 "issue" / "issuewild" / "iodef"）
    value: []const u8, // 属性值（二进制）
};

/// SVCB/HTTPS RDATA（RFC 9460 §2.2）：SvcPriority(2) + TargetName + SvcParams。
/// SVCB 与 HTTPS 共享线格式。SvcParams 为按 key 升序排列的 TLV 序列，此处零拷贝保留原始字节。
pub const SvcbData = struct {
    priority: u16, // SvcPriority；0 表示 AliasMode
    target: Name, // TargetName（RFC 9460 §2.2 规定不得压缩）
    params: []const u8, // 原始 SvcParams（key 升序的 {key(2),len(2),value(len)} TLV）

    pub const Param = struct { key: u16, value: []const u8 };

    pub const Iterator = struct {
        data: []const u8,
        pos: usize = 0,

        /// 返回下一个 SvcParam（key + value 切片）；结束返回 null，越界返回 error。
        pub fn next(self: *Iterator) !?Param {
            if (self.pos >= self.data.len) return null;
            if (self.pos + 4 > self.data.len) return error.InvalidRData;
            const key = mem.readInt(u16, self.data[self.pos..][0..2], .big);
            const len = mem.readInt(u16, self.data[self.pos + 2 ..][0..2], .big);
            const start = self.pos + 4;
            if (start + len > self.data.len) return error.InvalidRData;
            self.pos = start + len;
            return Param{ .key = key, .value = self.data[start .. start + len] };
        }
    };

    pub fn iterator(self: SvcbData) Iterator {
        return .{ .data = self.params };
    }
};

/// NSEC/NSEC3 类型位图（RFC 4034 §4.1.2）：window块(1)+位图长度(1)+位图 的窗口序列。
/// 零拷贝保留原始字节；迭代产出所有置位的 RR 类型编号（升序）。
pub const TypeBitmap = struct {
    raw: []const u8,

    pub const Iterator = struct {
        data: []const u8,
        hdr: usize = 0, // 当前窗口头字节索引
        bit: usize = 0, // 当前窗口内下一个待检查的位偏移
        prev_window: i16 = -1, // 上一窗口块编号，用于强制严格递增

        /// 返回下一个置位的类型编号；结束返回 null，位图畸形返回 error。
        pub fn next(self: *Iterator) !?u16 {
            while (self.hdr < self.data.len) {
                if (self.hdr + 2 > self.data.len) return error.InvalidRData;
                const window = self.data[self.hdr];
                const blen = self.data[self.hdr + 1];
                if (blen < 1 or blen > 32) return error.InvalidRData;
                // RFC 4034 §4.1.2: 窗口块须按编号严格递增；否则升序输出的不变量被破坏。
                if (self.bit == 0) {
                    if (@as(i16, window) <= self.prev_window) return error.InvalidRData;
                    self.prev_window = window;
                }
                const bstart = self.hdr + 2;
                if (bstart + blen > self.data.len) return error.InvalidRData;
                const total_bits = @as(usize, blen) * 8;
                while (self.bit < total_bits) {
                    const byte = self.data[bstart + self.bit / 8];
                    const set = (byte >> @intCast(7 - self.bit % 8)) & 1;
                    const cur = self.bit;
                    self.bit += 1;
                    if (set == 1) return @intCast(@as(usize, window) * 256 + cur);
                }
                self.hdr = bstart + blen;
                self.bit = 0;
            }
            return null;
        }
    };

    pub fn iterator(self: TypeBitmap) Iterator {
        return .{ .data = self.raw };
    }

    /// 位图是否包含某类型（线性扫描，适合零星查询）。
    /// 不做「present > t 提前退出」——那依赖升序假设，而畸形位图（窗口乱序）会因此
    /// 对实际存在的类型误报 false；完整迭代可让迭代器在遇到乱序窗口时报错。
    pub fn contains(self: TypeBitmap, t: u16) !bool {
        var it = self.iterator();
        while (try it.next()) |present| {
            if (present == t) return true;
        }
        return false;
    }
};

pub const DnskeyData = struct { flags: u16, protocol: u8, algorithm: u8, public_key: []const u8 };
pub const DsData = struct { key_tag: u16, algorithm: u8, digest_type: u8, digest: []const u8 };
pub const RrsigData = struct {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    expiration: u32,
    inception: u32,
    key_tag: u16,
    signer: Name, // RFC 4034 §3.1.7: 不得压缩
    signature: []const u8,
};
pub const NsecData = struct { next_domain: Name, types: TypeBitmap };
pub const Nsec3Data = struct {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: []const u8,
    next_hashed_owner: []const u8,
    types: TypeBitmap,
};
pub const Nsec3ParamData = struct { hash_algorithm: u8, flags: u8, iterations: u16, salt: []const u8 };

/// RFC 4034 附录 B：由 DNSKEY 的 RDATA 计算 key tag（用于关联 DS/RRSIG）。
/// 对算法 1(RSA/MD5) 之外的所有算法适用（算法 1 已废弃，不支持）。
pub fn keyTag(dnskey_rdata: []const u8) u16 {
    var acc: u32 = 0;
    for (dnskey_rdata, 0..) |b, i| {
        acc += if (i & 1 == 0) @as(u32, b) << 8 else @as(u32, b);
    }
    acc += (acc >> 16) & 0xFFFF;
    return @intCast(acc & 0xFFFF);
}

fn parseCookieOption(payload: []const u8) !CookieData {
    // RFC 7873 §4: OPTION-LENGTH 须为 8（仅客户端）或 16..40（8 客户端 + 8..32 服务端）。
    if (payload.len != 8 and (payload.len < 16 or payload.len > 40)) return error.MalformedCookie;
    var client: [8]u8 = undefined;
    @memcpy(&client, payload[0..8]);
    return CookieData{ .client = client, .server = payload[8..] };
}

/// 扫描 OPT 记录 RDATA，查找 COOKIE 选项（RFC 7873）。无则返回 null。
pub fn parseCookie(rdata: []const u8) !?CookieData {
    var pos: usize = 0;
    while (pos + 4 <= rdata.len) {
        const code = (@as(u16, rdata[pos]) << 8) | rdata[pos + 1];
        const len = (@as(u16, rdata[pos + 2]) << 8) | rdata[pos + 3];
        pos += 4;
        if (len > rdata.len -| pos) return error.PacketTooShort;
        if (code == @intFromEnum(OptionCode.COOKIE)) {
            return try parseCookieOption(rdata[pos .. pos + len]);
        }
        pos += len;
    }
    return null;
}

/// RDATA 表示 (零拷贝)。
/// 域名字段为 `Name`（自包含，可跟随压缩指针）；定长/文本字段为数组或切片。
pub const RData = union(Type) {
    A: [4]u8,
    NS: Name,
    CNAME: Name,
    SOA: struct {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    PTR: Name,
    MX: struct { preference: u16, exchange: Name },
    TXT: TxtData, // 一个或多个 character-string（RFC 1035 §3.3.14）
    AAAA: [16]u8,
    SRV: struct { priority: u16, weight: u16, port: u16, target: Name },
    OPT: []const u8, // EDNS 选项数据
    SVCB: SvcbData, // 服务绑定（RFC 9460）
    HTTPS: SvcbData, // HTTPS 服务绑定（RFC 9460，与 SVCB 同格式）
    CAA: CaaData, // 证书颁发机构授权（RFC 8659）
    DS: DsData, // 委派签名者（RFC 4034）
    RRSIG: RrsigData, // 资源记录签名（RFC 4034）
    NSEC: NsecData, // 下一安全记录（RFC 4034）
    DNSKEY: DnskeyData, // DNS 公钥（RFC 4034）
    NSEC3: Nsec3Data, // 哈希化 NSEC（RFC 5155）
    NSEC3PARAM: Nsec3ParamData, // NSEC3 参数（RFC 5155）

    /// 在 RDATA 内推进越过一个域名（含压缩指针），仅校验与定位，不复制。
    /// 用于跳到域名之后的定长字段。
    fn advanceName(data: []const u8, pos: *usize) Error!void {
        while (pos.* < data.len) {
            const len = data[pos.*];
            if (len == 0) {
                pos.* += 1;
                return;
            }
            if (len & 0xC0 == 0xC0) { // 压缩指针
                if (data.len - pos.* < 2) return error.PacketTooShort;
                pos.* += 2;
                return;
            }
            if (len > 63) return error.LabelTooLong;
            if (data.len - pos.* < 1 + len) return error.PacketTooShort;
            pos.* += 1 + len;
        }
        return error.MalformedName;
    }

    /// 同 advanceName，但禁止压缩指针（RFC 4034 §3.1.7/§4.1.1、RFC 9460 §2.2
    /// 规定 RRSIG signer / NSEC next_domain / SVCB target 不得压缩）。
    fn advanceNameNoPointer(data: []const u8, pos: *usize) Error!void {
        while (pos.* < data.len) {
            const len = data[pos.*];
            if (len == 0) {
                pos.* += 1;
                return;
            }
            if (len & 0xC0 == 0xC0) return error.MalformedName; // 禁止压缩
            if (len > 63) return error.LabelTooLong;
            if (data.len - pos.* < 1 + len) return error.PacketTooShort;
            pos.* += 1 + len;
        }
        return error.MalformedName;
    }

    /// 从完整报文中解析某条记录的 RDATA。
    /// msg: 完整 DNS 报文（用于解析内嵌域名的压缩指针）
    /// rdata_offset: RDATA 在报文中的起始绝对偏移
    /// rdlength: RDATA 长度
    /// 内嵌域名以 `Name{ .buffer = msg, .offset = 绝对偏移 }` 返回，自包含且可解压缩。
    pub fn parse(rtype: Type, msg: []const u8, rdata_offset: usize, rdlength: u16) Error!RData {
        if (rdata_offset > msg.len or rdlength > msg.len - rdata_offset) return error.PacketTooShort;
        const data = msg[rdata_offset..][0..rdlength];
        return switch (rtype) {
            .A => {
                if (data.len != 4) return error.InvalidRData;
                var ip: [4]u8 = undefined;
                @memcpy(&ip, data[0..4]);
                return RData{ .A = ip };
            },
            .AAAA => {
                if (data.len != 16) return error.InvalidRData;
                var ip: [16]u8 = undefined;
                @memcpy(&ip, data[0..16]);
                return RData{ .AAAA = ip };
            },
            .NS, .CNAME, .PTR => {
                var pos: usize = 0;
                try advanceName(data, &pos);
                if (pos != data.len) return error.InvalidRData; // 名字须精确覆盖 RDATA
                const name = Name{ .buffer = msg, .offset = rdata_offset };
                return switch (rtype) {
                    .NS => RData{ .NS = name },
                    .CNAME => RData{ .CNAME = name },
                    .PTR => RData{ .PTR = name },
                    else => unreachable,
                };
            },
            .MX => {
                if (data.len < 2) return error.InvalidRData;
                const preference = mem.readInt(u16, data[0..2], .big);
                var pos: usize = 2;
                try advanceName(data, &pos);
                if (pos != data.len) return error.InvalidRData; // exchange 须精确覆盖 RDATA
                return RData{ .MX = .{
                    .preference = preference,
                    .exchange = Name{ .buffer = msg, .offset = rdata_offset + 2 },
                } };
            },
            .TXT => {
                // TXT: 一个或多个 character-string（RFC 1035 §3.3.14）。
                // 至少一段；各段 1 字节长度前缀 + 内容，必须恰好平铺整个 RDATA。
                if (data.len < 1) return error.InvalidRData;
                var pos: usize = 0;
                while (pos < data.len) {
                    const seg_len = data[pos];
                    pos += 1;
                    if (pos + seg_len > data.len) return error.InvalidRData;
                    pos += seg_len;
                }
                return RData{ .TXT = .{ .raw = data } };
            },
            .SOA => {
                var pos: usize = 0;
                const mname_off = rdata_offset + pos;
                try advanceName(data, &pos);
                const rname_off = rdata_offset + pos;
                try advanceName(data, &pos);
                if (data.len != pos + 20) return error.InvalidRData; // 两名 + 20 字节须精确覆盖
                const serial = mem.readInt(u32, data[pos..][0..4], .big);
                const refresh = mem.readInt(u32, data[pos + 4 ..][0..4], .big);
                const retry = mem.readInt(u32, data[pos + 8 ..][0..4], .big);
                const expire = mem.readInt(u32, data[pos + 12 ..][0..4], .big);
                const minimum = mem.readInt(u32, data[pos + 16 ..][0..4], .big);
                return RData{ .SOA = .{
                    .mname = Name{ .buffer = msg, .offset = mname_off },
                    .rname = Name{ .buffer = msg, .offset = rname_off },
                    .serial = serial,
                    .refresh = refresh,
                    .retry = retry,
                    .expire = expire,
                    .minimum = minimum,
                } };
            },
            .SRV => {
                if (data.len < 6) return error.InvalidRData;
                const priority = mem.readInt(u16, data[0..2], .big);
                const weight = mem.readInt(u16, data[2..4], .big);
                const port = mem.readInt(u16, data[4..6], .big);
                var pos: usize = 6;
                try advanceName(data, &pos);
                if (pos != data.len) return error.InvalidRData; // target 须精确覆盖 RDATA
                return RData{ .SRV = .{
                    .priority = priority,
                    .weight = weight,
                    .port = port,
                    .target = Name{ .buffer = msg, .offset = rdata_offset + 6 },
                } };
            },
            .CAA => {
                // RFC 8659 §4.1: flags(1) + tag长度(1) + tag + value（其余全部）。
                if (data.len < 2) return error.InvalidRData;
                const tag_len: usize = data[1];
                if (tag_len == 0) return error.InvalidRData; // RFC 8659 §4.1: tag ≥1 字节
                if (2 + tag_len > data.len) return error.InvalidRData;
                return RData{ .CAA = .{
                    .flags = data[0],
                    .tag = data[2 .. 2 + tag_len],
                    .value = data[2 + tag_len ..],
                } };
            },
            .SVCB, .HTTPS => {
                // RFC 9460 §2.2: SvcPriority(2) + TargetName + SvcParams。
                if (data.len < 2) return error.InvalidRData;
                const priority = mem.readInt(u16, data[0..2], .big);
                var pos: usize = 2;
                try advanceNameNoPointer(data, &pos); // TargetName 不得压缩（RFC 9460 §2.2）
                // 校验 SvcParams 各 TLV 恰好平铺剩余字节。
                var pp = pos;
                while (pp < data.len) {
                    if (pp + 4 > data.len) return error.InvalidRData;
                    const plen = mem.readInt(u16, data[pp + 2 ..][0..2], .big);
                    pp += 4;
                    if (pp + plen > data.len) return error.InvalidRData;
                    pp += plen;
                }
                const svcb = SvcbData{
                    .priority = priority,
                    .target = Name{ .buffer = msg, .offset = rdata_offset + 2 },
                    .params = data[pos..],
                };
                return switch (rtype) {
                    .SVCB => RData{ .SVCB = svcb },
                    .HTTPS => RData{ .HTTPS = svcb },
                    else => unreachable,
                };
            },
            .DNSKEY => {
                if (data.len < 4) return error.InvalidRData;
                return RData{ .DNSKEY = .{
                    .flags = mem.readInt(u16, data[0..2], .big),
                    .protocol = data[2],
                    .algorithm = data[3],
                    .public_key = data[4..],
                } };
            },
            .DS => {
                if (data.len < 4) return error.InvalidRData;
                return RData{ .DS = .{
                    .key_tag = mem.readInt(u16, data[0..2], .big),
                    .algorithm = data[2],
                    .digest_type = data[3],
                    .digest = data[4..],
                } };
            },
            .RRSIG => {
                // 固定字段 18 字节 + signer name + signature（RFC 4034 §3.1）。
                if (data.len < 18) return error.InvalidRData;
                var pos: usize = 18;
                try advanceNameNoPointer(data, &pos); // signer 不得压缩（RFC 4034 §3.1.7）
                return RData{ .RRSIG = .{
                    .type_covered = mem.readInt(u16, data[0..2], .big),
                    .algorithm = data[2],
                    .labels = data[3],
                    .original_ttl = mem.readInt(u32, data[4..8], .big),
                    .expiration = mem.readInt(u32, data[8..12], .big),
                    .inception = mem.readInt(u32, data[12..16], .big),
                    .key_tag = mem.readInt(u16, data[16..18], .big),
                    .signer = Name{ .buffer = msg, .offset = rdata_offset + 18 },
                    .signature = data[pos..],
                } };
            },
            .NSEC => {
                // next_domain name + 类型位图（RFC 4034 §4.1）。
                var pos: usize = 0;
                try advanceNameNoPointer(data, &pos); // next_domain 不得压缩（RFC 4034 §4.1.1）
                return RData{ .NSEC = .{
                    .next_domain = Name{ .buffer = msg, .offset = rdata_offset },
                    .types = .{ .raw = data[pos..] },
                } };
            },
            .NSEC3 => {
                // hash(1)+flags(1)+iters(2)+salt_len(1)+salt+hash_len(1)+next_hash+位图（RFC 5155 §3）。
                if (data.len < 5) return error.InvalidRData;
                const salt_len: usize = data[4];
                if (5 + salt_len + 1 > data.len) return error.InvalidRData;
                const hash_len: usize = data[5 + salt_len];
                const hash_start = 6 + salt_len;
                if (hash_start + hash_len > data.len) return error.InvalidRData;
                return RData{ .NSEC3 = .{
                    .hash_algorithm = data[0],
                    .flags = data[1],
                    .iterations = mem.readInt(u16, data[2..4], .big),
                    .salt = data[5 .. 5 + salt_len],
                    .next_hashed_owner = data[hash_start .. hash_start + hash_len],
                    .types = .{ .raw = data[hash_start + hash_len ..] },
                } };
            },
            .NSEC3PARAM => {
                if (data.len < 5) return error.InvalidRData;
                const salt_len: usize = data[4];
                if (5 + salt_len != data.len) return error.InvalidRData; // salt 后不得有多余字节
                return RData{ .NSEC3PARAM = .{
                    .hash_algorithm = data[0],
                    .flags = data[1],
                    .iterations = mem.readInt(u16, data[2..4], .big),
                    .salt = data[5 .. 5 + salt_len],
                } };
            },
            .OPT => return error.InvalidRData, // OPT 需要特殊处理
            _ => return error.UnknownType,
        };
    }
};

test "keyTag computes RFC 4034 Appendix B tag" {
    // rdata = flags(0x0100) proto(3) alg(8) pubkey("ABCD")；手工核算 = 0x888E。
    const rdata = "\x01\x00\x03\x08ABCD";
    try std.testing.expectEqual(@as(u16, 0x888E), keyTag(rdata));
}

test "TypeBitmap rejects non-increasing window order (RFC 4034 4.1.2)" {
    // window 1 (type 256) 然后 window 0 (type 1)：窗口非递增，畸形位图。
    // 迭代器必须报错，否则 contains 的升序提前退出会漏判已存在的类型。
    const bm = TypeBitmap{ .raw = "\x01\x01\x80\x00\x01\x40" };
    var it = bm.iterator();
    try std.testing.expectEqual(@as(u16, 256), (try it.next()).?); // window 1
    try std.testing.expectError(error.InvalidRData, it.next()); // window 0 < 1 -> 报错
    // contains 不得因升序假设而对已存在类型误报 false
    try std.testing.expectError(error.InvalidRData, bm.contains(1));
}

test "TypeBitmap.contains finds present and rejects absent types" {
    // window 0: A(1), MX(15), RRSIG(46), NSEC(47)
    const bm = TypeBitmap{ .raw = "\x00\x06\x40\x01\x00\x00\x00\x03" };
    try std.testing.expect(try bm.contains(1));
    try std.testing.expect(try bm.contains(47));
    try std.testing.expect(!(try bm.contains(2)));
    try std.testing.expect(!(try bm.contains(48)));
}

test "RData parse DNSKEY record (RFC 4034)" {
    // flags=256, protocol=3, algorithm=8(RSASHA256), public_key="ABCD"
    const rdata = "\x01\x00\x03\x08ABCD";
    const rd = try RData.parse(.DNSKEY, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u16, 256), rd.DNSKEY.flags);
    try std.testing.expectEqual(@as(u8, 3), rd.DNSKEY.protocol);
    try std.testing.expectEqual(@as(u8, 8), rd.DNSKEY.algorithm);
    try std.testing.expectEqualStrings("ABCD", rd.DNSKEY.public_key);
}

test "RData parse DS record (RFC 4034)" {
    // key_tag=0x3039, algorithm=8, digest_type=2, digest=4 bytes
    const rdata = "\x30\x39\x08\x02\xde\xad\xbe\xef";
    const rd = try RData.parse(.DS, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u16, 0x3039), rd.DS.key_tag);
    try std.testing.expectEqual(@as(u8, 8), rd.DS.algorithm);
    try std.testing.expectEqual(@as(u8, 2), rd.DS.digest_type);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0xbe, 0xef }, rd.DS.digest);
}

test "RData parse NSEC3PARAM record (RFC 5155)" {
    // hash=1, flags=0, iterations=10, salt_len=4, salt=aabbccdd
    const rdata = "\x01\x00\x00\x0a\x04\xaa\xbb\xcc\xdd";
    const rd = try RData.parse(.NSEC3PARAM, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u8, 1), rd.NSEC3PARAM.hash_algorithm);
    try std.testing.expectEqual(@as(u16, 10), rd.NSEC3PARAM.iterations);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }, rd.NSEC3PARAM.salt);
}

test "RData parse RRSIG record (RFC 4034)" {
    const rdata = "\x00\x01" ++ // type_covered=A
        "\x08" ++ // algorithm
        "\x02" ++ // labels
        "\x00\x00\x0e\x10" ++ // original_ttl=3600
        "\x5f\x00\x00\x00" ++ // expiration
        "\x5e\x00\x00\x00" ++ // inception
        "\x30\x39" ++ // key_tag=0x3039
        "\x07example\x03com\x00" ++ // signer (uncompressed)
        "SIG!"; // signature
    const rd = try RData.parse(.RRSIG, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u16, 1), rd.RRSIG.type_covered);
    try std.testing.expectEqual(@as(u8, 8), rd.RRSIG.algorithm);
    try std.testing.expectEqual(@as(u8, 2), rd.RRSIG.labels);
    try std.testing.expectEqual(@as(u32, 3600), rd.RRSIG.original_ttl);
    try std.testing.expectEqual(@as(u32, 0x5f000000), rd.RRSIG.expiration);
    try std.testing.expectEqual(@as(u32, 0x5e000000), rd.RRSIG.inception);
    try std.testing.expectEqual(@as(u16, 0x3039), rd.RRSIG.key_tag);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("example.com", try rd.RRSIG.signer.str(&nbuf));
    try std.testing.expectEqualStrings("SIG!", rd.RRSIG.signature);
}

test "RData parse NSEC record with type bitmap (RFC 4034)" {
    const rdata = "\x01a\x07example\x03com\x00" ++ // next_domain
        "\x00\x06\x40\x01\x00\x00\x00\x03"; // window 0: A(1), MX(15), RRSIG(46), NSEC(47)
    const rd = try RData.parse(.NSEC, rdata, 0, rdata.len);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("a.example.com", try rd.NSEC.next_domain.str(&nbuf));
    var it = rd.NSEC.types.iterator();
    try std.testing.expectEqual(@as(u16, 1), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 15), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 46), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 47), (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "RData parse NSEC3 record (RFC 5155)" {
    const rdata = "\x01\x01\x00\x0a\x04\xaa\xbb\xcc\xdd" ++ // hash,flags,iters,salt
        "\x05\x01\x02\x03\x04\x05" ++ // hash_len=5, next_hashed_owner
        "\x00\x02\x40\x01"; // types: A(1), MX(15)
    const rd = try RData.parse(.NSEC3, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u8, 1), rd.NSEC3.hash_algorithm);
    try std.testing.expectEqual(@as(u8, 1), rd.NSEC3.flags);
    try std.testing.expectEqual(@as(u16, 10), rd.NSEC3.iterations);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd }, rd.NSEC3.salt);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5 }, rd.NSEC3.next_hashed_owner);
    var it = rd.NSEC3.types.iterator();
    try std.testing.expectEqual(@as(u16, 1), (try it.next()).?);
    try std.testing.expectEqual(@as(u16, 15), (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "RData rejects compressed names where RFC forbids compression" {
    // RRSIG signer (RFC 4034 §3.1.7), NSEC next_domain (§4.1.1),
    // SVCB/HTTPS target (RFC 9460 §2.2) 均不得压缩；压缩指针须报 MalformedName。
    const rrsig = "\x00\x01\x08\x02\x00\x00\x0e\x10\x5f\x00\x00\x00\x5e\x00\x00\x00\x30\x39" ++ "\xc0\x00" ++ "SIG!";
    try std.testing.expectError(error.MalformedName, RData.parse(.RRSIG, rrsig, 0, rrsig.len));
    const nsec = "\xc0\x00" ++ "\x00\x01\x40";
    try std.testing.expectError(error.MalformedName, RData.parse(.NSEC, nsec, 0, nsec.len));
    const svcb = "\x00\x01" ++ "\xc0\x00";
    try std.testing.expectError(error.MalformedName, RData.parse(.SVCB, svcb, 0, svcb.len));
}

test "RData parse RRSIG rejects truncated fixed fields" {
    const rdata = "\x00\x01\x08\x02"; // 只有 4 字节，不足 18
    try std.testing.expectError(error.InvalidRData, RData.parse(.RRSIG, rdata, 0, rdata.len));
}

test "RData parse NSEC3 rejects salt overrunning rdata" {
    const rdata = "\x01\x01\x00\x0a\x20\xaa"; // salt_len=32 但其后仅 1 字节
    try std.testing.expectError(error.InvalidRData, RData.parse(.NSEC3, rdata, 0, rdata.len));
}

test "RData parse CAA record (RFC 8659)" {
    // flags=0, tag="issue", value="ca.example.net"
    const rdata = "\x00\x05issue" ++ "ca.example.net";
    const rd = try RData.parse(.CAA, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u8, 0), rd.CAA.flags);
    try std.testing.expectEqualStrings("issue", rd.CAA.tag);
    try std.testing.expectEqualStrings("ca.example.net", rd.CAA.value);
}

test "RData parse CAA record with critical flag set" {
    // flags=0x80 (Issuer Critical), tag="iodef", value="mailto:sec@example.com"
    const rdata = "\x80\x05iodef" ++ "mailto:sec@example.com";
    const rd = try RData.parse(.CAA, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u8, 0x80), rd.CAA.flags);
    try std.testing.expectEqualStrings("iodef", rd.CAA.tag);
    try std.testing.expectEqualStrings("mailto:sec@example.com", rd.CAA.value);
}

test "RData parse CAA rejects tag length overrunning rdata" {
    // tag_len=10 但其后不足 10 字节。
    const rdata = "\x00\x0aabc";
    try std.testing.expectError(error.InvalidRData, RData.parse(.CAA, rdata, 0, rdata.len));
}

test "RData parse CAA rejects zero-length tag (RFC 8659)" {
    // tag_len=0：RFC 8659 §4.1 要求 tag 至少 1 字节。
    const rdata = "\x00\x00val";
    try std.testing.expectError(error.InvalidRData, RData.parse(.CAA, rdata, 0, rdata.len));
}

test "RData parse CAA allows empty value" {
    const rdata = "\x00\x05issue";
    const rd = try RData.parse(.CAA, rdata, 0, rdata.len);
    try std.testing.expectEqualStrings("issue", rd.CAA.tag);
    try std.testing.expectEqualStrings("", rd.CAA.value);
}

test "RData parse HTTPS record with SvcParams (RFC 9460)" {
    // priority=1, target="svc.example.net", 一个 SvcParam key=3(port) value={0x01,0xBB}=443
    const rdata = "\x00\x01" ++ // priority
        "\x03svc\x07example\x03net\x00" ++ // target (uncompressed)
        "\x00\x03\x00\x02\x01\xBB"; // key=3, len=2, value=443
    const rd = try RData.parse(.HTTPS, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u16, 1), rd.HTTPS.priority);
    var nbuf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("svc.example.net", try rd.HTTPS.target.str(&nbuf));
    var it = rd.HTTPS.iterator();
    const p = (try it.next()).?;
    try std.testing.expectEqual(@as(u16, 3), p.key);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0xBB }, p.value);
    try std.testing.expect((try it.next()) == null);
}

test "RData parse SVCB AliasMode (priority 0, no params)" {
    const rdata = "\x00\x00" ++ "\x03svc\x07example\x03net\x00";
    const rd = try RData.parse(.SVCB, rdata, 0, rdata.len);
    try std.testing.expectEqual(@as(u16, 0), rd.SVCB.priority);
    var it = rd.SVCB.iterator();
    try std.testing.expect((try it.next()) == null);
}

test "RData parse SVCB rejects SvcParam overrunning rdata" {
    // param 声称 value 长 10 字节但其后不足。
    const rdata = "\x00\x01" ++ "\x00" ++ "\x00\x01\x00\x0aab";
    try std.testing.expectError(error.InvalidRData, RData.parse(.SVCB, rdata, 0, rdata.len));
}

test "RData parse A record" {
    const ip = [_]u8{ 192, 0, 2, 1 };
    const rdata = try RData.parse(.A, &ip, 0, 4);
    try std.testing.expectEqualSlices(u8, &ip, &rdata.A);
}

test "RData rejects trailing data past name-terminated RDATA" {
    // RDLENGTH 必须精确覆盖内容；名字之后的多余字节属畸形（报文走私向量）。
    // CNAME: 根名(1) + 2 字节垃圾
    try std.testing.expectError(error.InvalidRData, RData.parse(.CNAME, "\x00\xde\xad", 0, 3));
    // MX: preference(2) + 根名(1) + 1 字节垃圾
    try std.testing.expectError(error.InvalidRData, RData.parse(.MX, "\x00\x0a\x00\xff", 0, 4));
    // SRV: prio/weight/port(6) + 根名(1) + 1 字节垃圾
    try std.testing.expectError(error.InvalidRData, RData.parse(.SRV, "\x00\x0a\x00\x14\x13\xc4\x00\xff", 0, 8));
    // NSEC3PARAM: hash/flags/iters(4) + salt_len=0 + 1 字节垃圾
    try std.testing.expectError(error.InvalidRData, RData.parse(.NSEC3PARAM, "\x01\x00\x00\x0a\x00\xff", 0, 6));
}

test "RData parse MX record resolves exchange name" {
    var data: [20]u8 = undefined;
    @memset(&data, 0);
    mem.writeInt(u16, data[0..2], 10, .big); // preference
    // mail.example.com (未压缩，以 0 结尾)
    data[2] = 4;
    @memcpy(data[3..7], "mail");
    data[7] = 7;
    @memcpy(data[8..15], "example");
    data[15] = 3;
    @memcpy(data[16..19], "com");
    data[19] = 0;

    const rdata = try RData.parse(.MX, &data, 0, 20);
    try std.testing.expectEqual(@as(u16, 10), rdata.MX.preference);
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("mail.example.com", try rdata.MX.exchange.str(&buf));
}

test "RData parse TXT single character-string" {
    var txt: [14]u8 = undefined;
    txt[0] = 12; // 长度前缀
    @memcpy(txt[1..13], "hello world!");
    const rdata = try RData.parse(.TXT, txt[0..13], 0, 13);
    var it = rdata.TXT.iterator();
    try std.testing.expectEqualStrings("hello world!", (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "RData parse TXT multiple character-strings (RFC 1035 3.3.14)" {
    // 两段字符串: "foo" + "barbaz"，均带 1 字节长度前缀。
    // 旧实现只返回第一段，丢弃 "barbaz"。
    const txt = "\x03foo\x06barbaz";
    const rdata = try RData.parse(.TXT, txt, 0, txt.len);
    var it = rdata.TXT.iterator();
    try std.testing.expectEqualStrings("foo", (try it.next()).?);
    try std.testing.expectEqualStrings("barbaz", (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "RData parse TXT rejects segment overrunning rdata" {
    // 长度前缀声称 10 字节，但只剩 2 字节。
    const txt = "\x0aab";
    try std.testing.expectError(error.InvalidRData, RData.parse(.TXT, txt, 0, txt.len));
}

test "RData parse TXT empty character-string is valid" {
    // 单个零长字符串是合法的 TXT（rdlength=1）。
    const txt = "\x00";
    const rdata = try RData.parse(.TXT, txt, 0, txt.len);
    var it = rdata.TXT.iterator();
    try std.testing.expectEqualStrings("", (try it.next()).?);
    try std.testing.expect((try it.next()) == null);
}

test "parseCookie parses client-only cookie (RFC 7873)" {
    // OPT rdata: code=10, len=8, 8 字节 client cookie
    const rdata = "\x00\x0a\x00\x08" ++ "\x01\x02\x03\x04\x05\x06\x07\x08";
    const c = (try parseCookie(rdata)).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &c.client);
    try std.testing.expectEqual(@as(usize, 0), c.server.len);
}

test "parseCookie parses client+server cookie" {
    // code=10, len=16, client(8) + server(8)
    const rdata = "\x00\x0a\x00\x10" ++ "\x01\x02\x03\x04\x05\x06\x07\x08" ++ "\xaa\xbb\xcc\xdd\xee\xff\x11\x22";
    const c = (try parseCookie(rdata)).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 }, &c.client);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 }, c.server);
}

test "parseCookie rejects invalid cookie length" {
    // len=9：既非 8 也不在 16..40 -> 非法
    const rdata = "\x00\x0a\x00\x09" ++ "\x01\x02\x03\x04\x05\x06\x07\x08\x09";
    try std.testing.expectError(error.MalformedCookie, parseCookie(rdata));
}

test "parseCookie returns null when no cookie option present" {
    // 只有 ECS 选项，无 cookie
    const rdata = "\x00\x08\x00\x07\x00\x01\x18\x00\xc0\x00\x02";
    try std.testing.expect((try parseCookie(rdata)) == null);
}

test "parseECS rejects truncated option payload" {
    const rdata = [_]u8{
        0x00, 0x08,
        0x00, 0x08,
        0x00, 0x01,
        0x18,
    };

    try std.testing.expectError(error.PacketTooShort, parseECS(&rdata));
}

test "parseECS rejects address length mismatch" {
    // IPv4, prefix=24 需 3 字节地址，但只给 2 字节
    const rdata = [_]u8{ 0x00, 0x08, 0x00, 0x06, 0x00, 0x01, 0x18, 0x00, 192, 0 };
    try std.testing.expectError(error.MalformedECS, parseECS(&rdata));
}

test "parseECS rejects scope_prefix exceeding family max (RFC 7871)" {
    // IPv4, source=24 (3 字节地址), scope=200 (>32) -> 非法
    const rdata = [_]u8{ 0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0xc8, 0xc0, 0x00, 0x02 };
    try std.testing.expectError(error.MalformedECS, parseECS(&rdata));
}

test "parseECS rejects prefix exceeding family max" {
    // IPv4 但 prefix=33 (>32)
    const rdata = [_]u8{ 0x00, 0x08, 0x00, 0x09, 0x00, 0x01, 0x21, 0x00, 1, 2, 3, 4, 5 };
    try std.testing.expectError(error.MalformedECS, parseECS(&rdata));
}

test "parseECS rejects unknown family" {
    const rdata = [_]u8{ 0x00, 0x08, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00 };
    try std.testing.expectError(error.MalformedECS, parseECS(&rdata));
}

test "parseECS accepts valid IPv6 subnet" {
    // family=2, prefix=32 -> 4 字节地址
    const rdata = [_]u8{ 0x00, 0x08, 0x00, 0x08, 0x00, 0x02, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8 };
    const ecs = (try parseECS(&rdata)).?;
    try std.testing.expectEqual(@as(u16, 2), ecs.family);
    try std.testing.expectEqual(@as(u8, 32), ecs.source_prefix);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x20, 0x01, 0x0d, 0xb8 }, ecs.address);
}

test "parseECS fast path parses first option" {
    const rdata = [_]u8{
        0x00, 0x08,
        0x00, 0x07,
        0x00, 0x01,
        0x18, 0x00,
        192,  0,
        2,
    };

    const ecs = (try parseECS(&rdata)).?;
    try std.testing.expectEqual(@as(u16, 1), ecs.family);
    try std.testing.expectEqual(@as(u8, 24), ecs.source_prefix);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 0, 2 }, ecs.address);
}

test "RData CNAME resolves compression pointer against full message" {
    var msg: [64]u8 = undefined;
    @memset(&msg, 0);
    // "example.com\0" 位于偏移 4
    msg[4] = 7;
    @memcpy(msg[5..12], "example");
    msg[12] = 3;
    @memcpy(msg[13..16], "com");
    msg[16] = 0;
    // CNAME RDATA 位于偏移 20: "www" + 指向偏移 4 的压缩指针，rdlength=6
    msg[20] = 3;
    @memcpy(msg[21..24], "www");
    msg[24] = 0xC0;
    msg[25] = 0x04;

    const rdata = try RData.parse(.CNAME, &msg, 20, 6);
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com", try rdata.CNAME.str(&buf));
}
