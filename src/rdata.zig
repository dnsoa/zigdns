const std = @import("std");
const mem = std.mem;
const Type = @import("types.zig").Type;
const OptionCode = @import("types.zig").OptionCode;
const ECSData = @import("types.zig").ECSData;
const Error = @import("errors.zig").Error;

fn parseECSOption(option_payload: []const u8) !ECSData {
    if (option_payload.len < 4) return error.MalformedECS;

    return ECSData{
        .family = mem.readInt(u16, option_payload[0..2], .big),
        .source_prefix = option_payload[2],
        .scope_prefix = option_payload[3],
        .address = option_payload[4..],
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

/// RDATA 表示 (零拷贝，指向原始缓冲区)
pub const RData = union(Type) {
    A: [4]u8,
    NS: []const u8,
    CNAME: []const u8,
    SOA: struct {
        mname: []const u8,
        rname: []const u8,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    PTR: []const u8,
    MX: struct { preference: u16, exchange: []const u8 },
    TXT: []const u8,
    AAAA: [16]u8,
    SRV: struct { priority: u16, weight: u16, port: u16, target: []const u8 },
    OPT: []const u8, // EDNS 选项数据

    /// 解析域名 (简化的 NameIterator)
    fn parseName(data: []const u8, pos: *usize) Error![]const u8 {
        const start = pos.*;
        while (pos.* < data.len) {
            const len = data[pos.*];
            if (len == 0) {
                pos.* += 1;
                return data[start .. pos.* - 1];
            }
            if (len & 0xC0 == 0xC0) { // 压缩指针
                if (data.len - pos.* < 2) return error.PacketTooShort;
                pos.* += 2;
                return data[start..pos.*];
            }
            if (len > 63) return error.LabelTooLong;
            if (data.len - pos.* < 1 + len) return error.PacketTooShort;
            pos.* += 1 + len;
        }
        return error.MalformedName;
    }

    /// 从 RDATA 字节解析
    pub fn parse(rtype: Type, data: []const u8) Error!RData {
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
                const name = try parseName(data, &pos);
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
                const exchange = try parseName(data, &pos);
                return RData{ .MX = .{ .preference = preference, .exchange = exchange } };
            },
            .TXT => {
                // TXT: 长度前缀 + 文本
                if (data.len < 1) return error.InvalidRData;
                const len = data[0];
                if (data.len < 1 + len) return error.InvalidRData;
                return RData{ .TXT = data[1 .. 1 + len] };
            },
            .SOA => {
                var pos: usize = 0;
                const mname = try parseName(data, &pos);
                const rname = try parseName(data, &pos);
                if (data.len < pos + 20) return error.InvalidRData;
                const serial = mem.readInt(u32, data[pos..][0..4], .big);
                const refresh = mem.readInt(u32, data[pos + 4 ..][0..4], .big);
                const retry = mem.readInt(u32, data[pos + 8 ..][0..4], .big);
                const expire = mem.readInt(u32, data[pos + 12 ..][0..4], .big);
                const minimum = mem.readInt(u32, data[pos + 16 ..][0..4], .big);
                return RData{ .SOA = .{
                    .mname = mname,
                    .rname = rname,
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
                const target = try parseName(data, &pos);
                return RData{ .SRV = .{
                    .priority = priority,
                    .weight = weight,
                    .port = port,
                    .target = target,
                } };
            },
            .OPT => return error.InvalidRData, // OPT 需要特殊处理
            _ => return error.UnknownType,
        };
    }

    /// 计算编码后的长度 (不含域名长度前缀)
    pub fn calcLength(self: RData) usize {
        return switch (self) {
            .A => 4,
            .AAAA => 16,
            .NS, .CNAME, .PTR => |n| n.len + 1, // 域名 + 结束符
            .MX => |mx| 2 + mx.exchange.len + 1, // preference + 域名
            .TXT => |txt| 1 + txt.len, // 长度前缀 + 文本
            .SOA => |soa| soa.mname.len + 1 + soa.rname.len + 1 + 20,
            .SRV => |srv| 6 + srv.target.len + 1, // 3*u16 + 域名
        };
    }
};

test "RData parse A record" {
    const ip = [_]u8{ 192, 0, 2, 1 };
    const rdata = try RData.parse(.A, &ip);
    try std.testing.expectEqualSlices(u8, &ip, &rdata.A);
}

test "RData parse MX record" {
    var data: [20]u8 = undefined;
    @memset(&data, 0);
    mem.writeInt(u16, data[0..2], 10, .big); // preference
    // mail.example.com
    data[2] = 4;
    @memcpy(data[3..7], "mail");
    data[7] = 7;
    @memcpy(data[8..15], "example");
    data[15] = 3;
    @memcpy(data[16..19], "com");

    const rdata = try RData.parse(.MX, &data);
    try std.testing.expectEqual(@as(u16, 10), rdata.MX.preference);
}

test "RData parse TXT record" {
    var txt: [14]u8 = undefined;
    txt[0] = 12; // 长度前缀
    @memcpy(txt[1..13], "hello world!");
    const rdata = try RData.parse(.TXT, txt[0..13]);
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

test "RData parseName preserves compression pointer bytes" {
    const data = [_]u8{ 0x03, 'w', 'w', 'w', 0xC0, 0x0C };
    const rdata = try RData.parse(.CNAME, &data);

    try std.testing.expectEqualSlices(u8, &data, rdata.CNAME);
}
