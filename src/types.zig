const std = @import("std");

/// DNS 资源记录类型与查询伪类型（RFC 1035 / RFC 6895 §3.1）
pub const Type = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13, // 主机信息 (RFC 1035 / RFC 8482)
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35, // 命名权威指针 (RFC 3403)
    DNAME = 39, // 子树别名 (RFC 6672)
    OPT = 41, // EDNS(0) 伪记录 (RFC 6891)
    DS = 43, // 委派签名者 (RFC 4034)
    SSHFP = 44, // SSH 公钥指纹 (RFC 4255)
    RRSIG = 46, // 资源记录签名 (RFC 4034)
    NSEC = 47, // 下一安全记录 (RFC 4034)
    DNSKEY = 48, // DNS 公钥 (RFC 4034)
    NSEC3 = 50, // 哈希化 NSEC (RFC 5155)
    NSEC3PARAM = 51, // NSEC3 参数 (RFC 5155)
    TLSA = 52, // DANE TLS 认证 (RFC 6698)
    CDS = 59, // 子区域 DS (RFC 7344)
    CDNSKEY = 60, // 子区域 DNSKEY (RFC 7344)
    CSYNC = 62, // 子到父同步 (RFC 7477)
    ZONEMD = 63, // 区域消息摘要 (RFC 8976)
    SVCB = 64, // 服务绑定 (RFC 9460)
    HTTPS = 65, // HTTPS 服务绑定 (RFC 9460)
    // QTYPE / Meta-TYPE（RFC 1035 §3.2.3 / RFC 6895 §3.1）
    TKEY = 249, // 事务密钥 (RFC 2930)
    TSIG = 250, // 事务签名 (RFC 8945)
    IXFR = 251, // 增量区域传输 (RFC 1995)
    AXFR = 252, // 完整区域传输 (RFC 1035 / RFC 5936)
    MAILB = 253, // 邮箱相关记录 (已废弃)
    MAILA = 254, // 邮件代理记录 (已废弃)
    ANY = 255, // 所有记录 (`*`, RFC 1035 / RFC 8482)
    CAA = 257, // 证书颁发机构授权 (RFC 8659)
    _,
};

/// EDNS(0) 选项码（RFC 6891 §6.1.2 / IANA DNS EDNS0 Option Codes）
pub const OptionCode = enum(u16) {
    NSID = 3, // Name Server Identifier (RFC 5001)
    DAU = 5, // DNSSEC Algorithm Understood (RFC 6975)
    DHU = 6, // DS Hash Understood (RFC 6975)
    N3U = 7, // NSEC3 Hash Understood (RFC 6975)
    ECS = 8, // Client Subnet (RFC 7871)
    EXPIRE = 9, // EDNS EXPIRE (RFC 7314)
    COOKIE = 10, // DNS Cookie (RFC 7873)
    TCP_KEEPALIVE = 11, // edns-tcp-keepalive (RFC 7828)
    PADDING = 12, // Padding (RFC 7830)
    CHAIN = 13, // CHAIN Query Requests (RFC 7901)
    KEY_TAG = 14, // edns-key-tag (RFC 8145)
    EDE = 15, // Extended DNS Errors (RFC 8914)
    ZONEVERSION = 19, // Zone Version (RFC 9660)
    _,
};

/// SVCB/HTTPS 服务参数键（RFC 9460 §14.3.2）
pub const SvcParamKey = enum(u16) {
    mandatory = 0,
    alpn = 1,
    no_default_alpn = 2,
    port = 3,
    ipv4hint = 4,
    ech = 5,
    ipv6hint = 6,
    _,
};

/// DNS 资源记录类
pub const Class = enum(u16) {
    IN = 1, // Internet
    CS = 2, // CSNET (已废弃)
    CH = 3, // Chaos
    HS = 4, // Hesiod
    NONE = 254,
    ANY = 255,
    _,
};

/// DNS 操作码
pub const Opcode = enum(u4) {
    QUERY = 0, // 标准查询
    IQUERY = 1, // 反向查询 (已废弃)
    STATUS = 2, // 服务器状态
    NOTIFY = 4, // 区域变更通知 (RFC 1996)
    UPDATE = 5, // 动态更新 (RFC 2136)
    DSO = 6, // DNS 有状态操作 (RFC 8490)
    _, // 保留/未知值 —— 不可信输入不得触发非法行为
};

/// DNS 头部 4 位响应码
pub const Rcode = enum(u4) {
    NOERROR = 0, // 无错误
    FORMERR = 1, // 格式错误
    SERVFAIL = 2, // 服务器失败
    NXDOMAIN = 3, // 域名不存在
    NOTIMP = 4, // 未实现
    REFUSED = 5, // 拒绝
    YXDOMAIN = 6, // 名字已存在
    YXRRSET = 7, // 资源记录集已存在
    NXRRSET = 8, // 资源记录集不存在
    NOTAUTH = 9, // 未授权
    NOTZONE = 10, // 不在区域中
    DSOTYPENI = 11, // DSO-TYPE 未实现 (RFC 8490)
    _, // 保留/未知值 —— 不可信输入不得触发非法行为
};

/// 12 位完整 DNS/EDNS 扩展响应码（RFC 6891 §6.1.3 / RFC 6895 §2.3）：
/// 高 8 位存于 OPT.TTL[31:24]，低 4 位存于 Header.RCODE。
pub const ExtendedRcode = enum(u12) {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    YXRRSET = 7,
    NXRRSET = 8,
    NOTAUTH = 9,
    NOTZONE = 10,
    DSOTYPENI = 11, // RFC 8490
    BADVERS = 16, // EDNS 版本不支持 (RFC 6891 §6.1.3；TSIG BADSIG 同值)
    BADKEY = 17, // 密钥未识别 (RFC 8945)
    BADTIME = 18, // 签名超出时间窗 (RFC 8945)
    BADMODE = 19, // TKEY 模式错误 (RFC 2930)
    BADNAME = 20, // 密钥名重复 (RFC 2930)
    BADALG = 21, // 算法不支持 (RFC 2930)
    BADTRUNC = 22, // 非法截断 (RFC 8945)
    BADCOOKIE = 23, // DNS Cookie 错误或缺失 (RFC 7873 §5.2.3)
    _,

    /// 由 Header 低 4 位 rcode 与 OPT 高 8 位 extended_rcode 合成 12 位响应码。
    pub fn fromParts(header_rcode: u4, opt_extended_rcode: u8) ExtendedRcode {
        return @fromBackingInt((@as(u12, opt_extended_rcode) << 4) | header_rcode);
    }

    /// 拆分为 Header 低 4 位与 OPT 高 8 位，避免把 BADCOOKIE(23) 误写入 extended_rcode=23。
    pub fn split(self: ExtendedRcode) struct { header_rcode: u4, extended_rcode: u8 } {
        const raw = @backingInt(self);
        return .{
            .header_rcode = @truncate(raw),
            .extended_rcode = @truncate(raw >> 4),
        };
    }
};

/// SOA SERIAL 序列号算术比较（RFC 1982 §3.2，模 2^32 半环序）。
/// 当两序列号相差恰为 0x80000000 时按 RFC 1982 §3.2 序关系未定义，返回 null。
pub fn serialCompare(s1: u32, s2: u32) ?std.math.Order {
    if (s1 == s2) return .eq;
    const diff = s2 -% s1;
    if (diff == 0x80000000) return null;
    return if (diff < 0x80000000) .lt else .gt;
}

pub const ECSData = struct {
    family: u16, // 1 for IPv4, 2 for IPv6
    source_prefix: u8,
    scope_prefix: u8,
    address: []const u8, // Slice into the original packet
};

/// DNS Cookie（RFC 7873 §4）：8 字节 Client Cookie + 可选 8..32 字节 Server Cookie。
pub const CookieData = struct {
    client: [8]u8,
    server: []const u8, // 空（仅客户端，通常出现在查询）或 8..32 字节（响应/后续查询）
};

test "Opcode/Rcode tolerate reserved/unknown values" {
    // 非穷举枚举：不可信输入里的保留值不得触发非法行为/panic
    const oc: Opcode = @fromBackingInt(@intCast(3));
    const rc: Rcode = @fromBackingInt(@intCast(15));
    try std.testing.expectEqual(@as(u4, 3), @backingInt(oc));
    try std.testing.expectEqual(@as(u4, 15), @backingInt(rc));
}

test "ExtendedRcode splits and combines 12-bit EDNS RCODE (RFC 6891 / RFC 7873)" {
    // BADVERS = 16 -> header.rcode=0, extended_rcode=1
    const badvers = ExtendedRcode.BADVERS.split();
    try std.testing.expectEqual(@as(u4, 0), badvers.header_rcode);
    try std.testing.expectEqual(@as(u8, 1), badvers.extended_rcode);
    try std.testing.expectEqual(ExtendedRcode.BADVERS, ExtendedRcode.fromParts(badvers.header_rcode, badvers.extended_rcode));

    // BADCOOKIE = 23 -> header.rcode=7, extended_rcode=1
    const badcookie = ExtendedRcode.BADCOOKIE.split();
    try std.testing.expectEqual(@as(u4, 7), badcookie.header_rcode);
    try std.testing.expectEqual(@as(u8, 1), badcookie.extended_rcode);
    try std.testing.expectEqual(ExtendedRcode.BADCOOKIE, ExtendedRcode.fromParts(badcookie.header_rcode, badcookie.extended_rcode));
}

test "serialCompare follows RFC 1982 wraparound semantics" {
    try std.testing.expectEqual(@as(?std.math.Order, .eq), serialCompare(100, 100));
    try std.testing.expectEqual(@as(?std.math.Order, .lt), serialCompare(100, 200));
    try std.testing.expectEqual(@as(?std.math.Order, .gt), serialCompare(200, 100));
    // 跨 2^32 回绕：0xFFFFFFF0 < 0x00000010
    try std.testing.expectEqual(@as(?std.math.Order, .lt), serialCompare(0xFFFFFFF0, 0x00000010));
    try std.testing.expectEqual(@as(?std.math.Order, .gt), serialCompare(0x00000010, 0xFFFFFFF0));
    // 相差恰为 2^31 时未定义
    try std.testing.expectEqual(@as(?std.math.Order, null), serialCompare(0, 0x80000000));
}
