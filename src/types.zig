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
    _,
};

pub const OptionCode = enum(u16) {
    ECS = 8, // Client Subnet (RFC 7871)
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

test "Opcode/Rcode tolerate reserved/unknown values" {
    // 非穷举枚举：不可信输入里的保留值不得触发非法行为/panic
    const oc: Opcode = @enumFromInt(3);
    const rc: Rcode = @enumFromInt(15);
    try std.testing.expectEqual(@as(u4, 3), @intFromEnum(oc));
    try std.testing.expectEqual(@as(u4, 15), @intFromEnum(rc));
}
