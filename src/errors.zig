/// DNS 解析和编码错误
pub const Error = error{
    PacketTooShort,
    MalformedHeader, // TCP 帧声明长度 <12 字节，无法构成合法 DNS Header
    MalformedName,
    MalformedECS,
    LabelTooLong,
    NameTooLong,
    InvalidRData,
    InvalidType,
    InvalidClass,
    BufferTooSmall,
    UnknownType,
    UnknownClass,
    InvalidOffset,
    MessageTooLong,
    MultipleOptRecords, // RFC 6891 §6.1.1: 报文含多个 OPT 记录 → FORMERR
    InvalidRecordOrder, // 调用顺序错误：Builder 分区回退/问题晚于资源记录，或 SectionParser 跳区/未读完声明记录即调 expectEnd
    MalformedCookie, // RFC 7873: DNS Cookie 长度非法（须 8 或 16..40 字节）
    UseEdns, // 对 OPT(41) 调用了通用 RDATA 解析：改用 findEdns / Edns.fromOpt
    MisplacedOptRecord, // RFC 6891 §6.1.1: OPT 记录出现在 Answer/Authority 等非附加区 → FORMERR
    TrailingBytes, // 声明的四个分区记录全部消费后，报文末尾仍有未声明的残留字节 → FORMERR
};
