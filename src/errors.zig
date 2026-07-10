/// DNS 解析和编码错误
pub const Error = error{
    PacketTooShort,
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
    InvalidRecordOrder, // Builder 误用：分区回退，或问题记录晚于资源记录
    MalformedCookie, // RFC 7873: DNS Cookie 长度非法（须 8 或 16..40 字节）
};
