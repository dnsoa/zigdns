const std = @import("std");
const mem = std.mem;
const Type = @import("types.zig").Type;
const OptionCode = @import("types.zig").OptionCode;
const ECSData = @import("types.zig").ECSData;
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
    if (source_prefix > max_prefix) return error.MalformedECS;
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
    TXT: []const u8, // 文本，非域名
    AAAA: [16]u8,
    SRV: struct { priority: u16, weight: u16, port: u16, target: Name },
    OPT: []const u8, // EDNS 选项数据

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
                return RData{ .MX = .{
                    .preference = preference,
                    .exchange = Name{ .buffer = msg, .offset = rdata_offset + 2 },
                } };
            },
            .TXT => {
                // TXT: 长度前缀 + 文本
                if (data.len < 1) return error.InvalidRData;
                const len: usize = data[0];
                if (data.len < 1 + len) return error.InvalidRData;
                return RData{ .TXT = data[1 .. 1 + len] };
            },
            .SOA => {
                var pos: usize = 0;
                const mname_off = rdata_offset + pos;
                try advanceName(data, &pos);
                const rname_off = rdata_offset + pos;
                try advanceName(data, &pos);
                if (data.len < pos + 20) return error.InvalidRData;
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
                return RData{ .SRV = .{
                    .priority = priority,
                    .weight = weight,
                    .port = port,
                    .target = Name{ .buffer = msg, .offset = rdata_offset + 6 },
                } };
            },
            .OPT => return error.InvalidRData, // OPT 需要特殊处理
            _ => return error.UnknownType,
        };
    }
};

test "RData parse A record" {
    const ip = [_]u8{ 192, 0, 2, 1 };
    const rdata = try RData.parse(.A, &ip, 0, 4);
    try std.testing.expectEqualSlices(u8, &ip, &rdata.A);
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

test "RData parse TXT record" {
    var txt: [14]u8 = undefined;
    txt[0] = 12; // 长度前缀
    @memcpy(txt[1..13], "hello world!");
    const rdata = try RData.parse(.TXT, txt[0..13], 0, 13);
    try std.testing.expectEqualStrings("hello world!", rdata.TXT);
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
