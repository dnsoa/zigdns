/// DNS 协议实现库
/// 零拷贝、高性能的 DNS 报文解析和构造
pub const Header = @import("header.zig").Header;
pub const NameCursor = @import("name.zig").NameCursor;
pub const NameIterator = @import("name.zig").NameIterator;
pub const Name = @import("name.zig").Name;
pub const skipName = @import("name.zig").skipName;
pub const formatDnsName = @import("name.zig").formatDnsName;
pub const formatDnsNameInMessage = @import("name.zig").formatDnsNameInMessage;
pub const decodePresentationName = @import("name.zig").decodePresentationName;
pub const validateMessageOffset = @import("name.zig").validateMessageOffset;
pub const canonicalCompareWire = @import("name.zig").canonicalCompareWire;
pub const MESSAGE_POINTER_FLOOR = @import("name.zig").MESSAGE_POINTER_FLOOR;
pub const Type = @import("types.zig").Type;
pub const Class = @import("types.zig").Class;
pub const Opcode = @import("types.zig").Opcode;
pub const Rcode = @import("types.zig").Rcode;
pub const ExtendedRcode = @import("types.zig").ExtendedRcode;
pub const OptionCode = @import("types.zig").OptionCode;
pub const SvcParamKey = @import("types.zig").SvcParamKey;
pub const ECSData = @import("types.zig").ECSData;
pub const CookieData = @import("types.zig").CookieData;
pub const serialCompare = @import("types.zig").serialCompare;

pub const Message = @import("message.zig").Message;
pub const Section = @import("message.zig").Section;
pub const SectionParser = @import("message.zig").SectionParser;
pub const Edns = @import("message.zig").Edns;
pub const MessageParser = @import("parser.zig").MessageParser;
pub const ResourceData = @import("rdata.zig").RData;
pub const RData = @import("rdata.zig").RData;
pub const HinfoData = @import("rdata.zig").HinfoData;
pub const TxtData = @import("rdata.zig").TxtData;
pub const CaaData = @import("rdata.zig").CaaData;
pub const SvcbData = @import("rdata.zig").SvcbData;
pub const SshfpData = @import("rdata.zig").SshfpData;
pub const TlsaData = @import("rdata.zig").TlsaData;
pub const validateSvcParams = @import("rdata.zig").validateSvcParams;

// DNSSEC（RFC 4034 / 5155）
pub const TypeBitmap = @import("rdata.zig").TypeBitmap;
pub const validateTypeBitmap = @import("rdata.zig").validateTypeBitmap;
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

// 导出 EDNS 选项解析：parseOptOptions 单趟取出全部已识别选项，
// OptOptionIterator 零拷贝遍历全部原始 TLV，parseECS / parseCookie 是单项薄封装。
pub const parseOptOptions = @import("rdata.zig").parseOptOptions;
pub const validateOptOptionsForEncode = @import("rdata.zig").validateOptOptionsForEncode;
pub const OptEncodeValidation = @import("rdata.zig").OptEncodeValidation;
pub const OptOptions = @import("rdata.zig").OptOptions;
pub const OptOption = @import("rdata.zig").OptOption;
pub const OptOptionIterator = @import("rdata.zig").OptOptionIterator;
pub const parseECS = @import("rdata.zig").parseECS;
pub const parseCookie = @import("rdata.zig").parseCookie;

test {
    @import("std").testing.refAllDecls(@This());
}
