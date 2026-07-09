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
    // RFC 2535 起 byte3 的保留区细分为 Z/AD/CD 三个独立标志位（默认 0，向后兼容旧构造点）
    cd: u1 = 0, // 禁用校验 (Checking Disabled)
    ad: u1 = 0, // 已验证数据 (Authentic Data)
    z: u1 = 0, // 保留 (必须为 0)
    ra: u1, // 递归可用

    qdcount: u16, // 问题数
    ancount: u16, // 回答数
    nscount: u16, // 权威记录数
    arcount: u16, // 附加记录数

    // 显式按线格式字节解码，不依赖 packed struct 的隐式位序。
    // RFC 1035 4.1.1:
    //   byte2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
    //   byte3: RA(1) Z(1) AD(1) CD(1) RCODE(4)   (RFC 2535 起细分 Z/AD/CD)
    pub fn decode(data: *const [12]u8) Header {
        const b2 = data[2];
        const b3 = data[3];
        return .{
            .id = mem.readInt(u16, data[0..2], .big),
            .qr = @truncate(b2 >> 7),
            .opcode = @truncate(b2 >> 3),
            .aa = @truncate(b2 >> 2),
            .tc = @truncate(b2 >> 1),
            .rd = @truncate(b2),
            .ra = @truncate(b3 >> 7),
            .z = @truncate(b3 >> 6),
            .ad = @truncate(b3 >> 5),
            .cd = @truncate(b3 >> 4),
            .rcode = @truncate(b3),
            .qdcount = mem.readInt(u16, data[4..6], .big),
            .ancount = mem.readInt(u16, data[6..8], .big),
            .nscount = mem.readInt(u16, data[8..10], .big),
            .arcount = mem.readInt(u16, data[10..12], .big),
        };
    }

    pub fn encode(self: Header) [12]u8 {
        var buf: [12]u8 = undefined;
        mem.writeInt(u16, buf[0..2], self.id, .big);
        buf[2] = (@as(u8, self.qr) << 7) |
            (@as(u8, self.opcode) << 3) |
            (@as(u8, self.aa) << 2) |
            (@as(u8, self.tc) << 1) |
            @as(u8, self.rd);
        buf[3] = (@as(u8, self.ra) << 7) |
            (@as(u8, self.z) << 6) |
            (@as(u8, self.ad) << 5) |
            (@as(u8, self.cd) << 4) |
            @as(u8, self.rcode);
        mem.writeInt(u16, buf[4..6], self.qdcount, .big);
        mem.writeInt(u16, buf[6..8], self.ancount, .big);
        mem.writeInt(u16, buf[8..10], self.nscount, .big);
        mem.writeInt(u16, buf[10..12], self.arcount, .big);
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

// 真实线格式向量测试：断言具体字节 <-> 具体字段，而非往返恒等。
// 往返测试无法发现字节序错误（readInt/writeInt 与 bitCast 各自互逆），必须用固定向量锁定。

test "Header decode real query wire bytes" {
    // 标准查询: ID=0x1234, RD=1, QDCOUNT=1, 其余为 0
    // byte2=0x01 -> RD=1; byte3=0x00
    const wire = [_]u8{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const h = Header.decode(&wire);

    try std.testing.expectEqual(@as(u16, 0x1234), h.id);
    try std.testing.expectEqual(@as(u1, 0), h.qr);
    try std.testing.expectEqual(@as(u4, 0), h.opcode);
    try std.testing.expectEqual(@as(u1, 0), h.aa);
    try std.testing.expectEqual(@as(u1, 0), h.tc);
    try std.testing.expectEqual(@as(u1, 1), h.rd);
    try std.testing.expectEqual(@as(u1, 0), h.ra);
    try std.testing.expectEqual(@as(u1, 0), h.z);
    try std.testing.expectEqual(@as(u4, 0), h.rcode);
    try std.testing.expectEqual(@as(u16, 1), h.qdcount);
    try std.testing.expectEqual(@as(u16, 0), h.ancount);
    try std.testing.expectEqual(@as(u16, 0), h.nscount);
    try std.testing.expectEqual(@as(u16, 0), h.arcount);
}

test "Header decode real response wire bytes" {
    // 递归响应: ID=0x1234, byte2=0x81 (QR=1,RD=1), byte3=0x80 (RA=1),
    // QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=1
    const wire = [_]u8{ 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };
    const h = Header.decode(&wire);

    try std.testing.expectEqual(@as(u16, 0x1234), h.id);
    try std.testing.expectEqual(@as(u1, 1), h.qr);
    try std.testing.expectEqual(@as(u1, 1), h.rd);
    try std.testing.expectEqual(@as(u1, 1), h.ra);
    try std.testing.expectEqual(@as(u4, 0), h.rcode);
    try std.testing.expectEqual(@as(u16, 1), h.qdcount);
    try std.testing.expectEqual(@as(u16, 1), h.ancount);
    try std.testing.expectEqual(@as(u16, 0), h.nscount);
    try std.testing.expectEqual(@as(u16, 1), h.arcount);
}

test "Header decode packs opcode/rcode/flags into correct bits" {
    // byte2=0x96 -> QR=1, Opcode=2(STATUS), AA=1, TC=1, RD=0
    // byte3=0x83 -> RA=1, Z=0, RCODE=3(NXDOMAIN)
    const wire = [_]u8{ 0xAB, 0xCD, 0x96, 0x83, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    const h = Header.decode(&wire);

    try std.testing.expectEqual(@as(u16, 0xABCD), h.id);
    try std.testing.expectEqual(@as(u1, 1), h.qr);
    try std.testing.expectEqual(@as(u4, 2), h.opcode);
    try std.testing.expectEqual(@as(u1, 1), h.aa);
    try std.testing.expectEqual(@as(u1, 1), h.tc);
    try std.testing.expectEqual(@as(u1, 0), h.rd);
    try std.testing.expectEqual(@as(u1, 1), h.ra);
    try std.testing.expectEqual(@as(u1, 0), h.z);
    try std.testing.expectEqual(@as(u4, 3), h.rcode);
    try std.testing.expectEqual(@as(u16, 0x1234), h.qdcount);
    try std.testing.expectEqual(@as(u16, 0x5678), h.ancount);
    try std.testing.expectEqual(@as(u16, 0x9ABC), h.nscount);
    try std.testing.expectEqual(@as(u16, 0xDEF0), h.arcount);
}

test "Header encode produces exact wire bytes" {
    const h = Header{
        .id = 0x1234,
        .rd = 1,
        .tc = 0,
        .aa = 0,
        .opcode = 0,
        .qr = 1,
        .rcode = 0,
        .z = 0,
        .ra = 1,
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 1,
    };
    const expected = [_]u8{ 0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01 };
    try std.testing.expectEqualSlices(u8, &expected, &h.encode());
}

test "Header decodes AD and CD flags independently" {
    // RFC 2535: byte3 = RA(1) Z(1) AD(1) CD(1) RCODE(4)
    // byte3=0xA0 -> RA=1, Z=0, AD=1, CD=0, RCODE=0 (DNSSEC-validated response)
    const wire = [_]u8{ 0x12, 0x34, 0x81, 0xA0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    const h = Header.decode(&wire);
    try std.testing.expectEqual(@as(u1, 1), h.ra);
    try std.testing.expectEqual(@as(u1, 0), h.z);
    try std.testing.expectEqual(@as(u1, 1), h.ad);
    try std.testing.expectEqual(@as(u1, 0), h.cd);
    try std.testing.expectEqual(@as(u4, 0), h.rcode);
}

test "Header decodes CD flag independently" {
    // byte3=0x10 -> RA=0, Z=0, AD=0, CD=1, RCODE=0 (checking-disabled query)
    const wire = [_]u8{ 0x12, 0x34, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const h = Header.decode(&wire);
    try std.testing.expectEqual(@as(u1, 0), h.ra);
    try std.testing.expectEqual(@as(u1, 0), h.z);
    try std.testing.expectEqual(@as(u1, 0), h.ad);
    try std.testing.expectEqual(@as(u1, 1), h.cd);
    try std.testing.expectEqual(@as(u4, 0), h.rcode);
}

test "Header encodes AD and CD flags into byte3" {
    const h = Header{
        .id = 0x1234,
        .rd = 0,
        .tc = 0,
        .aa = 0,
        .opcode = 0,
        .qr = 1,
        .rcode = 0,
        .z = 0,
        .ad = 1,
        .cd = 1,
        .ra = 1,
        .qdcount = 1,
        .ancount = 1,
        .nscount = 0,
        .arcount = 0,
    };
    // byte3 = RA(1) Z(0) AD(1) CD(1) RCODE(0) = 0x80 | 0x20 | 0x10 = 0xB0
    const encoded = h.encode();
    try std.testing.expectEqual(@as(u8, 0xB0), encoded[3]);
}

test "Header decode matches parser's direct count reads" {
    // Header.decode 必须与 MessageParser 直接按偏移读取的 count 一致（互操作性）。
    const wire = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x05, 0x00, 0x07, 0x00, 0x09 };
    const h = Header.decode(&wire);
    try std.testing.expectEqual(mem.readInt(u16, wire[4..6], .big), h.qdcount);
    try std.testing.expectEqual(mem.readInt(u16, wire[6..8], .big), h.ancount);
    try std.testing.expectEqual(mem.readInt(u16, wire[8..10], .big), h.nscount);
    try std.testing.expectEqual(mem.readInt(u16, wire[10..12], .big), h.arcount);
}
