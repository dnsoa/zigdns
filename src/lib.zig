/// DNS 协议实现库
/// 零拷贝、高性能的 DNS 报文解析和构造
pub const Header = @import("header.zig").Header;
pub const NameIterator = @import("name.zig").NameIterator;
pub const Name = @import("name.zig").Name;
pub const formatDnsName = @import("name.zig").formatDnsName;
pub const Type = @import("types.zig").Type;
pub const Class = @import("types.zig").Class;
pub const Opcode = @import("types.zig").Opcode;
pub const Rcode = @import("types.zig").Rcode;
pub const OptionCode = @import("types.zig").OptionCode;
pub const ECSData = @import("types.zig").ECSData;
pub const CookieData = @import("types.zig").CookieData;

pub const Message = @import("message.zig").Message;
pub const Section = @import("message.zig").Section;
pub const Edns = @import("message.zig").Edns;
pub const MessageParser = @import("parser.zig").MessageParser;
pub const ResourceData = @import("rdata.zig").RData;
pub const TxtData = @import("rdata.zig").TxtData;
pub const CaaData = @import("rdata.zig").CaaData;
pub const SvcbData = @import("rdata.zig").SvcbData;

// DNSSEC（RFC 4034 / 5155）
pub const TypeBitmap = @import("rdata.zig").TypeBitmap;
pub const DnskeyData = @import("rdata.zig").DnskeyData;
pub const DsData = @import("rdata.zig").DsData;
pub const RrsigData = @import("rdata.zig").RrsigData;
pub const NsecData = @import("rdata.zig").NsecData;
pub const Nsec3Data = @import("rdata.zig").Nsec3Data;
pub const Nsec3ParamData = @import("rdata.zig").Nsec3ParamData;
pub const keyTag = @import("rdata.zig").keyTag;
pub const canonicalCompare = @import("name.zig").canonicalCompare;

pub const Error = @import("errors.zig").Error;

// 导出 Question 和 ResourceRecord 结构供外部使用
pub const Question = @import("parser.zig").Question;
pub const ResourceRecord = @import("parser.zig").ResourceRecord;

// 导出 ECS / Cookie 解析函数
pub const parseECS = @import("rdata.zig").parseECS;
pub const parseCookie = @import("rdata.zig").parseCookie;
