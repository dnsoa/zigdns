const std = @import("std");
const mem = std.mem;

// RFC 1035 4.1.1. DNS 报文头 (12 字节)
// 使用 packed struct 确保内存布局与协议一致
pub const Header = packed struct(u96) {
    id: u16,
    // 标志位 (大端序处理)
    rd: u1, // 期望递归
    tc: u1, // 截断
    aa: u1, // 权威应答
    opcode: u4, // 操作码
    qr: u1, // 0:查询, 1:响应
    rcode: u4, // 响应码
    z: u3, // 保留
    ra: u1, // 递归可用

    qdcount: u16, // 问题数
    ancount: u16, // 回答数
    nscount: u16, // 权威记录数
    arcount: u16, // 附加记录数

    pub fn decode(data: *const [12]u8) Header {
        return @bitCast(mem.readInt(u96, data, .big));
    }

    pub fn encode(self: Header) [12]u8 {
        var buf: [12]u8 = undefined;
        mem.writeInt(u96, &buf, @bitCast(self), .big);
        return buf;
    }
};

test "Header encode/decode" {
    const original = Header{
        .id = 0x1234,
        .rd = 1,
        .tc = 0,
        .aa = 1,
        .opcode = 0,
        .qr = 0,
        .rcode = 0,
        .z = 0,
        .ra = 1,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    const encoded = original.encode();
    const decoded = Header.decode(&encoded);

    try std.testing.expectEqual(original.id, decoded.id);
    try std.testing.expectEqual(original.rd, decoded.rd);
    try std.testing.expectEqual(original.tc, decoded.tc);
    try std.testing.expectEqual(original.aa, decoded.aa);
    try std.testing.expectEqual(original.opcode, decoded.opcode);
    try std.testing.expectEqual(original.qr, decoded.qr);
    try std.testing.expectEqual(original.rcode, decoded.rcode);
    try std.testing.expectEqual(original.z, decoded.z);
    try std.testing.expectEqual(original.ra, decoded.ra);
    try std.testing.expectEqual(original.qdcount, decoded.qdcount);
    try std.testing.expectEqual(original.ancount, decoded.ancount);
    try std.testing.expectEqual(original.nscount, decoded.nscount);
    try std.testing.expectEqual(original.arcount, decoded.arcount);
}
