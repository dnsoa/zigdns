/// DNS 解析和编码错误
pub const Error = error{
    PacketTooShort,
    MalformedName,
    LabelTooLong,
    NameTooLong,
    InvalidRData,
    InvalidType,
    InvalidClass,
    BufferTooSmall,
    UnknownType,
    UnknownClass,
    InvalidOffset,
};
