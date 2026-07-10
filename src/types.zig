const std = @import("std");

/// DNS 资源记录类型
pub const Type = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41, // EDNS
    SVCB = 64, // 服务绑定 (RFC 9460)
    HTTPS = 65, // HTTPS 服务绑定 (RFC 9460)
    CAA = 257, // 证书颁发机构授权 (RFC 8659)
    // DNSSEC（字段声明顺序须与 RData union 一致，与数值无关）
    DS = 43, // 委派签名者 (RFC 4034)
    RRSIG = 46, // 资源记录签名 (RFC 4034)
    NSEC = 47, // 下一安全记录 (RFC 4034)
    DNSKEY = 48, // DNS 公钥 (RFC 4034)
    NSEC3 = 50, // 哈希化 NSEC (RFC 5155)
    NSEC3PARAM = 51, // NSEC3 参数 (RFC 5155)
    _,
};

pub const OptionCode = enum(u16) {
    ECS = 8, // Client Subnet (RFC 7871)
    COOKIE = 10, // DNS Cookie (RFC 7873)
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
    NOTIFY = 4, // 区域变更通知
    UPDATE = 5, // 动态更新
    _, // 保留/未知值 —— 不可信输入不得触发非法行为
};

/// DNS 响应码
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
    _, // 保留/未知值 —— 不可信输入不得触发非法行为
};

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
    const oc: Opcode = @enumFromInt(3);
    const rc: Rcode = @enumFromInt(15);
    try std.testing.expectEqual(@as(u4, 3), @intFromEnum(oc));
    try std.testing.expectEqual(@as(u4, 15), @intFromEnum(rc));
}
