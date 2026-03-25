/// DNS 协议实现库
/// 零拷贝、高性能的 DNS 报文解析和构造

pub const Header = @import("header.zig").Header;
pub const NameIterator = @import("name.zig").NameIterator;
pub const formatDnsName = @import("name.zig").formatDnsName;
pub const Type = @import("types.zig").Type;
pub const Class = @import("types.zig").Class;
pub const Opcode = @import("types.zig").Opcode;
pub const Rcode = @import("types.zig").Rcode;
pub const OptionCode = @import("types.zig").OptionCode;
pub const ECSData = @import("types.zig").ECSData;

pub const Message = @import("message.zig").Message;
pub const MessageParser = @import("parser.zig").MessageParser;
pub const ResourceData = @import("rdata.zig").RData;

pub const Error = @import("errors.zig").Error;

// 导出 Question 和 ResourceRecord 结构供外部使用
pub const Question = @import("parser.zig").Question;
pub const ResourceRecord = @import("parser.zig").ResourceRecord;

// 导出 ECS 解析函数
pub const parseECS = @import("rdata.zig").parseECS;
