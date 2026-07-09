//! 模糊测试入口。解析器直面不可信网络输入，核心不变量是：
//! 对任意字节序列既不 panic、不 UB、也不死循环——错误必须以 error 优雅返回。
//!
//! 平时随 `zig build test` 编译并跑一遍作冒烟；真正模糊用：
//!   zig build fuzz --fuzz
//! 或   zig build test --fuzz

const std = @import("std");
const Smith = std.testing.Smith;
const Message = @import("message.zig").Message;
const MessageParser = @import("parser.zig").MessageParser;
const NameIterator = @import("name.zig").NameIterator;
const parseECS = @import("rdata.zig").parseECS;

/// 从 Smith 取一段受控字节作为报文输入。
fn draw(s: *Smith, buf: []u8, hash: u32) []const u8 {
    const n = s.sliceWithHash(buf, hash);
    return buf[0..n];
}

/// 把一个 DNS 报文完整走一遍：header、question、所有 RR 的 rdata 与内嵌域名。
/// 任何一步出错都直接返回——目的是触发崩溃，不是校验正确性。
fn walk(input: []const u8) void {
    const msg = Message.parse(input) catch return;

    var parser = MessageParser.init(input);
    var qi = parser.questions(msg.header.qdcount);
    while (qi.next() catch return) |_| {}

    const total = @as(u32, msg.header.ancount) + msg.header.nscount + msg.header.arcount;
    var nbuf: [256]u8 = undefined;
    var i: u32 = 0;
    while (i < total) : (i += 1) {
        const rr = (parser.nextRR() catch return) orelse break;
        const rd = parser.parseRData(rr) catch continue;
        switch (rd) {
            .CNAME, .NS, .PTR => |n| {
                _ = n.str(&nbuf) catch {};
            },
            .MX => |mx| {
                _ = mx.exchange.str(&nbuf) catch {};
            },
            .SOA => |soa| {
                _ = soa.mname.str(&nbuf) catch {};
                _ = soa.rname.str(&nbuf) catch {};
            },
            .SRV => |srv| {
                _ = srv.target.str(&nbuf) catch {};
            },
            else => {},
        }
    }
}

test "fuzz Message.parse + full walk" {
    const F = struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var buf: [2048]u8 = undefined;
            walk(draw(s, &buf, 0xA1));
        }
    };
    try std.testing.fuzz({}, F.one, .{});
}

test "fuzz Message.parseTcp + walk framed message" {
    const F = struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var buf: [2048]u8 = undefined;
            const input = draw(s, &buf, 0xB2);
            _ = Message.parseTcp(input) catch {};
            if (input.len >= 2) {
                const l = std.mem.readInt(u16, input[0..2], .big);
                if (input.len >= 2 + @as(usize, l)) walk(input[2 .. 2 + l]);
            }
        }
    };
    try std.testing.fuzz({}, F.one, .{});
}

test "fuzz formatNameAt / nameEqualsAt at arbitrary offsets" {
    const F = struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var buf: [2048]u8 = undefined;
            const input = draw(s, &buf, 0xC3);
            if (input.len == 0) return;
            const parser = MessageParser.init(input);
            var nbuf: [256]u8 = undefined;
            // 少量派生偏移，覆盖典型/越界/压缩指针入口，避免 O(n^2)
            const offsets = [_]usize{ 0, 12, input[0] % input.len, input.len - 1 };
            for (offsets) |off| {
                _ = parser.formatNameAt(off, &nbuf) catch {};
                _ = parser.nameEqualsAt(off, "example.com") catch {};
            }
        }
    };
    try std.testing.fuzz({}, F.one, .{});
}

test "fuzz NameIterator" {
    const F = struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var buf: [2048]u8 = undefined;
            const input = draw(s, &buf, 0xD4);
            var it = NameIterator{ .buffer = input, .pos = 0 };
            var guard: usize = 0;
            while (guard < 100_000) : (guard += 1) {
                const label = it.next() catch break;
                if (label == null) break;
            }
        }
    };
    try std.testing.fuzz({}, F.one, .{});
}

test "fuzz parseECS" {
    const F = struct {
        fn one(_: void, s: *Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            _ = parseECS(draw(s, &buf, 0xE5)) catch {};
        }
    };
    try std.testing.fuzz({}, F.one, .{});
}
