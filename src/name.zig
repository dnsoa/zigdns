const std = @import("std");
const mem = std.mem;
const Error = @import("errors.zig").Error;

// RFC 1035 2.3.4: 单标签 ≤63 字节，完整域名 ≤255 字节。
const MAX_LABEL = 63;
const MAX_NAME = 255;
// 单个域名跟随压缩指针的总次数上限（含带标签后缀链，最多 127 层标签）。
const MAX_POINTER_JUMPS = 128;

/// 完整 DNS 报文中压缩指针目标的最小合法偏移：域名不可能起始于 12 字节 header 内，
/// 指向 header 的指针是畸形输入。裸缓冲区（不是整个报文）用 0 表示不约束。
pub const MESSAGE_POINTER_FLOOR = 12;

/// 域名遍历游标：所有「读出标签」的压缩指针逻辑的唯一实现。
/// 逐标签推进，跟随 0xC0 压缩指针，统一强制 RFC 上限（label≤63 / name≤255 含根）、
/// 严格向前（更早偏移）跳转（RFC 1035 §4.1.4 prior occurrence）与指针跳转限次。
/// 零拷贝——返回指向原缓冲区的标签切片。
/// 只需跳过名字（不要标签）时用同规则但不返回切片的 `skipName`。
///
/// 语义：一个游标实例遍历「一个」完整域名——`total`（累计长度，用于 255 上限）、
/// `origin`（当前名段起点，保证指针严格单调递减防前向跳转与成环）跨多次 `next()` 累积。
pub const NameCursor = struct {
    buffer: []const u8,
    pos: usize,
    total: usize = 0,
    jumps: usize = 0,
    /// 当前正在展开的名字/后缀起始偏移；压缩指针必须满足 `target < origin`（RFC 1035 §4.1.4）。
    origin: ?usize = null,
    /// 压缩指针目标的最小合法偏移，见 `MESSAGE_POINTER_FLOOR`。
    pointer_floor: usize = 0,

    /// 裸缓冲区：不约束最小指针目标（缓冲区不是一整个 DNS 报文时用），仍要求指向更早偏移。
    pub fn init(buffer: []const u8, offset: usize) NameCursor {
        return .{ .buffer = buffer, .pos = offset, .origin = offset };
    }

    /// 完整 DNS 报文：指针不得指向 12 字节 header，且须指向更早偏移。
    pub fn initInMessage(msg: []const u8, offset: usize) NameCursor {
        return .{ .buffer = msg, .pos = offset, .origin = offset, .pointer_floor = MESSAGE_POINTER_FLOOR };
    }

    /// 推进到下一个标签，返回其字节切片；遇结束符返回 null。
    /// 跟随压缩指针；对非法/越界/前向跳转/超长/成环输入返回相应错误（绝不 panic）。
    pub fn next(self: *NameCursor) !?[]const u8 {
        if (self.origin == null) self.origin = self.pos;
        while (true) {
            if (self.pos >= self.buffer.len) return error.PacketTooShort;

            const len = self.buffer[self.pos];
            if (len == 0) {
                self.pos += 1;
                return null; // 结束符
            }

            // 压缩指针 (0xC0)：RFC 1035 §4.1.4 要求指向更早出现的位置（offset < origin）。
            if (len & 0xC0 == 0xC0) {
                if (self.pos + 1 >= self.buffer.len) return error.PacketTooShort;
                const offset = (@as(usize, len & 0x3F) << 8) | self.buffer[self.pos + 1];
                if (offset < self.pointer_floor or offset >= self.buffer.len) return error.InvalidOffset;
                if (offset >= self.origin.? or self.jumps >= MAX_POINTER_JUMPS) {
                    return error.MalformedName;
                }
                self.jumps += 1;
                self.origin = offset;
                self.pos = offset;
                continue;
            }

            if (len > MAX_LABEL) return error.LabelTooLong;
            const start = self.pos + 1;
            if (start + len > self.buffer.len) return error.PacketTooShort;

            self.total += 1 + len;
            // RFC 1035 §2.3.4 的 255 上限「含根结束符」：已累计的标签字节再加 1 字节
            // 根终止符即为线格式总长，故边界是 total+1（否则 256 字节的名字会被放行，
            // 而 Builder.validateName 以同一规则拒绝，形成解析/构造不一致）。
            if (self.total + 1 > MAX_NAME) return error.NameTooLong;

            self.pos = start + len;
            return self.buffer[start .. start + len];
        }
    }
};

/// 跳过 `buffer` 中起始于 `start` 的域名，返回其**线格式**结束偏移：
/// 未压缩名为根结束符之后；压缩名为首个压缩指针的 2 字节之后（**不是**指针目标之后）——
/// 也就是下一个字段（type/class 等）的起点。
///
/// 全程按 `NameCursor` 的规则校验展开结果：标签 ≤63、整名 ≤255（含根）、
/// 指针越界、禁止前向跳转与成环。跳过名字的快路径（`MessageParser.skipName` / RDATA 内推进）
/// 必须走这里，否则「只跳过不展开」的服务端会放行 NameCursor 本会拒绝的名字。
///
/// `pointer_floor`：压缩指针目标的最小合法偏移，完整报文传 `MESSAGE_POINTER_FLOOR`，
/// 裸缓冲区传 0；与 `NameCursor.pointer_floor` 同义。
pub fn skipName(buffer: []const u8, start: usize, pointer_floor: usize) !usize {
    var pos = start;
    var origin = start;
    var total: usize = 1; // 根结束符计入 255（RFC 1035 §2.3.4）
    var jumps: usize = 0;
    var wire_end: ?usize = null; // 线格式止于首个指针；在此之前即整名末尾
    while (true) {
        if (pos >= buffer.len) return error.PacketTooShort;
        const len = buffer[pos];
        if (len == 0) return wire_end orelse pos + 1;

        if (len & 0xC0 == 0xC0) { // 压缩指针：跟随以校验展开结果
            if (pos + 2 > buffer.len) return error.PacketTooShort;
            const target = (@as(usize, len & 0x3F) << 8) | buffer[pos + 1];
            if (target < pointer_floor or target >= buffer.len) return error.InvalidOffset;
            // RFC 1035 §4.1.4: 指针只能指向更早偏移（target < origin），天然消除成环与前向越区引用。
            if (target >= origin or jumps >= MAX_POINTER_JUMPS) {
                return error.MalformedName;
            }
            jumps += 1;
            if (wire_end == null) wire_end = pos + 2;
            origin = target;
            pos = target;
            continue;
        }

        if (len > MAX_LABEL) return error.LabelTooLong;
        if (pos + 1 + len > buffer.len) return error.PacketTooShort;
        total += 1 + len;
        if (total > MAX_NAME) return error.NameTooLong;
        pos += 1 + len;
    }
}

pub const DecodedPresentationName = struct {
    wire_len: usize,
    n_labels: usize,
};

/// 将点分表示格式域名（RFC 1035 §5.1 / RFC 4343 §2.1）单趟解码并校验为线格式（含末尾 0 根字节）。
/// 支持 `\.`、`\\` 等单字符转义与 `\DDD`（000..255）十进制字节转义；无反斜杠时走快路径。
/// `offsets[0..n_labels]` 给出每个标签长度字节在 `wire` 中的偏移。
pub fn decodePresentationName(
    name: []const u8,
    wire: *[MAX_NAME]u8,
    offsets: *[128]u8,
) Error!DecodedPresentationName {
    if (name.len == 0 or mem.eql(u8, name, ".")) {
        wire[0] = 0;
        return .{ .wire_len = 1, .n_labels = 0 };
    }

    // 快路径：无反斜杠转义（占绝大多数真实域名）
    if (mem.indexOfScalar(u8, name, '\\') == null) {
        const s = if (name.len > 1 and name[name.len - 1] == '.') name[0 .. name.len - 1] else name;
        var wpos: usize = 0;
        var n_labels: usize = 0;
        var label_start: usize = 0;

        for (s, 0..) |b, idx| {
            if (b == '.') {
                const llen = idx - label_start;
                if (llen == 0) return Error.MalformedName;
                if (llen > MAX_LABEL) return Error.LabelTooLong;
                if (wpos + 1 + llen + 1 > MAX_NAME) return Error.NameTooLong;
                offsets[n_labels] = @intCast(wpos);
                n_labels += 1;
                wire[wpos] = @intCast(llen);
                @memcpy(wire[wpos + 1 ..][0..llen], s[label_start..idx]);
                wpos += 1 + llen;
                label_start = idx + 1;
            }
        }

        const llen = s.len - label_start;
        if (llen == 0) return Error.MalformedName;
        if (llen > MAX_LABEL) return Error.LabelTooLong;
        if (wpos + 1 + llen + 1 > MAX_NAME) return Error.NameTooLong;
        offsets[n_labels] = @intCast(wpos);
        n_labels += 1;
        wire[wpos] = @intCast(llen);
        @memcpy(wire[wpos + 1 ..][0..llen], s[label_start..]);
        wpos += 1 + llen;
        wire[wpos] = 0;
        return .{ .wire_len = wpos + 1, .n_labels = n_labels };
    }

    // 转义路径（RFC 1035 §5.1）：逐字符解析 `\.`、`\\`、`\DDD`
    var wpos: usize = 0;
    var n_labels: usize = 0;
    var i: usize = 0;
    while (i < name.len) {
        const len_pos = wpos;
        if (wpos + 2 > MAX_NAME) return Error.NameTooLong;
        wpos += 1; // 预留标签长度字节
        var llen: usize = 0;

        while (i < name.len) {
            const c = name[i];
            if (c == '.') {
                if (llen == 0) return Error.MalformedName;
                i += 1;
                break;
            }
            const decoded: u8 = blk: {
                if (c == '\\') {
                    i += 1;
                    if (i >= name.len) return Error.MalformedName;
                    if (std.ascii.isDigit(name[i])) {
                        if (i + 3 > name.len or !std.ascii.isDigit(name[i + 1]) or !std.ascii.isDigit(name[i + 2])) {
                            return Error.MalformedName;
                        }
                        const val: u16 = (@as(u16, name[i] - '0') * 100) +
                            (@as(u16, name[i + 1] - '0') * 10) +
                            (name[i + 2] - '0');
                        if (val > 255) return Error.MalformedName;
                        i += 3;
                        break :blk @intCast(val);
                    } else {
                        const esc = name[i];
                        i += 1;
                        break :blk esc;
                    }
                } else {
                    i += 1;
                    break :blk c;
                }
            };
            if (llen >= MAX_LABEL) return Error.LabelTooLong;
            if (wpos >= MAX_NAME - 1) return Error.NameTooLong; // 至少留 1 字节给根 0
            wire[wpos] = decoded;
            wpos += 1;
            llen += 1;
        }

        if (llen == 0) return Error.MalformedName;
        offsets[n_labels] = @intCast(len_pos);
        n_labels += 1;
        wire[len_pos] = @intCast(llen);
    }

    wire[wpos] = 0;
    return .{ .wire_len = wpos + 1, .n_labels = n_labels };
}

fn compareLabelCI(x: []const u8, y: []const u8) std.math.Order {
    const n = @min(x.len, y.len);
    var k: usize = 0;
    while (k < n) : (k += 1) {
        const cx = std.ascii.toLower(x[k]);
        const cy = std.ascii.toLower(y[k]);
        if (cx != cy) return std.math.order(cx, cy);
    }
    return std.math.order(x.len, y.len);
}

const BackwardLabels = struct {
    s: []const u8,
    rem: ?usize,

    fn init(raw: []const u8) BackwardLabels {
        if (raw.len == 0 or mem.eql(u8, raw, ".")) return .{ .s = raw, .rem = null };
        const trimmed = if (raw.len > 1 and raw[raw.len - 1] == '.') raw[0 .. raw.len - 1] else raw;
        return .{ .s = trimmed, .rem = trimmed.len };
    }

    fn next(self: *BackwardLabels) ?[]const u8 {
        const end = self.rem orelse return null;
        if (mem.lastIndexOfScalar(u8, self.s[0..end], '.')) |dot| {
            self.rem = dot;
            return self.s[dot + 1 .. end];
        } else {
            self.rem = null;
            return self.s[0..end];
        }
    }
};

fn canonicalComparePlain(a: []const u8, b: []const u8) std.math.Order {
    var ia = BackwardLabels.init(a);
    var ib = BackwardLabels.init(b);
    while (true) {
        const la = ia.next();
        const lb = ib.next();
        if (la != null and lb != null) {
            const ord = compareLabelCI(la.?, lb.?);
            if (ord != .eq) return ord;
        } else if (la == null and lb == null) {
            return .eq;
        } else {
            // 共有后缀相同时标签更少者在前
            return if (la == null) .lt else .gt;
        }
    }
}

const PresentationRevIter = struct {
    mode: union(enum) {
        plain: BackwardLabels,
        decoded: struct {
            wire: [MAX_NAME]u8,
            off: [128]u8,
            rem: usize,
        },
    },

    fn init(raw: []const u8) PresentationRevIter {
        if (mem.indexOfScalar(u8, raw, '\\') == null) {
            return .{ .mode = .{ .plain = BackwardLabels.init(raw) } };
        }
        var res: PresentationRevIter = .{ .mode = .{ .decoded = .{
            .wire = undefined,
            .off = undefined,
            .rem = 0,
        } } };
        if (decodePresentationName(raw, &res.mode.decoded.wire, &res.mode.decoded.off)) |d| {
            res.mode.decoded.rem = d.n_labels;
            return res;
        } else |_| {
            // 仅当前操作数自身转义非法时退回按字面点切分，不影响另一操作数的合法转义解码，
            // 保证比较函数是单参数映射上的字典序（严格弱序：反对称且传递）。
            return .{ .mode = .{ .plain = BackwardLabels.init(raw) } };
        }
    }

    fn next(self: *PresentationRevIter) ?[]const u8 {
        switch (self.mode) {
            .plain => |*p| return p.next(),
            .decoded => |*d| {
                if (d.rem == 0) return null;
                d.rem -= 1;
                const o = d.off[d.rem];
                return d.wire[o + 1 ..][0..d.wire[o]];
            },
        }
    }
};

/// DNSSEC canonical 名序（RFC 4034 §6.1）：从最右（TLD）标签起逐个比较，
/// 每个标签按 US-ASCII 大小写折叠后的八位组序比较；共有后缀相同时标签更少者在前。
/// 输入为表示格式域名（支持 RFC 1035 §5.1 转义 `\.` / `\\` / `\DDD`，大小写不敏感），根用 "." 或 ""。
/// 无转义快路径原地逆向扫描，零栈数组分配。
pub fn canonicalCompare(a: []const u8, b: []const u8) std.math.Order {
    if (mem.indexOfScalar(u8, a, '\\') == null and mem.indexOfScalar(u8, b, '\\') == null) {
        return canonicalComparePlain(a, b);
    }

    var ia = PresentationRevIter.init(a);
    var ib = PresentationRevIter.init(b);
    while (true) {
        const la = ia.next();
        const lb = ib.next();
        if (la != null and lb != null) {
            const ord = compareLabelCI(la.?, lb.?);
            if (ord != .eq) return ord;
        } else if (la == null and lb == null) {
            return .eq;
        } else {
            return if (la == null) .lt else .gt;
        }
    }
}

const PackedLabels = struct {
    // 合法线格式域名总长 ≤255（含根与至少 1 个长度字节），故纯标签内容总长恒 ≤253、标签数 ≤127。
    // 注意：不能用 u8 直接索引原报文缓冲区（报文中名字起始偏移常 ≥256），紧凑拷入 253B 局部缓冲后
    // 结束偏移恒 ≤253，既把双侧总栈占用从 2KB 压到 ~762B，又支持任意大小报文偏移。
    chars: [253]u8 = undefined,
    ends: [128]u8 = undefined,
    count: u8 = 0,

    fn unpack(buf: []const u8, off: usize, pointer_floor: usize) Error!PackedLabels {
        var out = PackedLabels{};
        var cur = NameCursor{ .buffer = buf, .pos = off, .pointer_floor = pointer_floor };
        var cpos: usize = 0;
        var n: usize = 0;
        while (try cur.next()) |lbl| {
            @memcpy(out.chars[cpos..][0..lbl.len], lbl);
            cpos += lbl.len;
            out.ends[n] = @intCast(cpos);
            n += 1;
        }
        out.count = @intCast(n);
        return out;
    }

    fn label(self: *const PackedLabels, idx: usize) []const u8 {
        const start: usize = if (idx == 0) 0 else self.ends[idx - 1];
        return self.chars[start..self.ends[idx]];
    }
};

/// 比较两个线格式域名的 DNSSEC canonical 顺序（RFC 4034 §6.1）。
/// 跟随压缩指针，无需先格式化为转义字符串，精确处理含 '.' 或任意二进制字节的标签。
pub fn canonicalCompareWire(
    a_buf: []const u8,
    a_off: usize,
    b_buf: []const u8,
    b_off: usize,
    pointer_floor: usize,
) Error!std.math.Order {
    const pa = try PackedLabels.unpack(a_buf, a_off, pointer_floor);
    const pb = try PackedLabels.unpack(b_buf, b_off, pointer_floor);
    const na: usize = pa.count;
    const nb: usize = pb.count;

    var i: usize = 0;
    while (i < na and i < nb) : (i += 1) {
        const ord = compareLabelCI(pa.label(na - 1 - i), pb.label(nb - 1 - i));
        if (ord != .eq) return ord;
    }
    return std.math.order(na, nb);
}

/// 零拷贝域名解析器：只负责「逐标签遍历一个域名」，不是报文游标。
/// 不分配内存，仅返回指向原始数据包的切片迭代器。
/// 内部持有一个贯穿整次遍历的 `NameCursor`，使 jumps/total 跨 next() 累积——
/// 这是防指针环与 255 上限的前提（每次新建游标会重置计数，导致死循环 DoS）。
///
/// 走整个报文（跳到 type/class、下一条记录）请用 `MessageParser`；
/// 本迭代器只保证 `pos` 停在**线格式**结束处（见下）。
pub const NameIterator = struct {
    buffer: []const u8,
    /// 入参为域名起始偏移；迭代中被更新为目前已知的**线格式**结束偏移。
    /// 跟随压缩指针后，它是首个指针之后 2 字节的位置（而非指针目标之后），
    /// 与 `skipName` 一致，因此可安全用于续读其后的 type/class。
    pos: usize,
    /// 压缩指针目标的最小合法偏移。`buffer` 是完整报文时置为
    /// `MESSAGE_POINTER_FLOOR`，可一并拒绝指向 header 的指针；默认 0（不约束）。
    pointer_floor: usize = 0,
    cursor: ?NameCursor = null,
    /// 线格式已在首个压缩指针处结束，`pos` 不再随游标推进。
    wire_done: bool = false,

    pub fn next(self: *NameIterator) !?[]const u8 {
        if (self.cursor == null) self.cursor = .{
            .buffer = self.buffer,
            .pos = self.pos,
            .pointer_floor = self.pointer_floor,
        };
        const cur = &self.cursor.?;
        const before = cur.pos;
        const jumps_before = cur.jumps;
        const label = try cur.next();
        if (!self.wire_done) {
            if (cur.jumps > jumps_before) {
                // 首次跳转发生在进入本次 next 时的游标位置：该处是 2 字节指针。
                self.pos = before + 2;
                self.wire_done = true;
            } else {
                self.pos = cur.pos;
            }
        }
        return label;
    }
};

test "canonicalCompare orders names per RFC 4034 6.1" {
    const O = std.math.Order;
    // 后缀名（标签更少）排在前：example.com < a.example.com
    try std.testing.expectEqual(O.lt, canonicalCompare("example.com", "a.example.com"));
    try std.testing.expectEqual(O.gt, canonicalCompare("a.example.com", "example.com"));
    // 同层按标签比较：a.example.com < b.example.com
    try std.testing.expectEqual(O.lt, canonicalCompare("a.example.com", "b.example.com"));
    // 大小写不敏感
    try std.testing.expectEqual(O.eq, canonicalCompare("A.Example.COM", "a.example.com"));
    // 从最右标签开始比较占主导：z.a.com < a.z.com（com==com，再比 a<z）
    try std.testing.expectEqual(O.lt, canonicalCompare("z.a.com", "a.z.com"));
    // 根最小
    try std.testing.expectEqual(O.lt, canonicalCompare(".", "com"));
}

test "NameIterator terminates on pointer-cycle with intervening label" {
    // {label 'a', pointer->0}: 每次 next() 必须共享同一游标状态（jumps/total 累积），
    // 否则指针环无法被检测，形成死循环 DoS。
    const buf = [_]u8{ 0x01, 'a', 0xC0, 0x00 };
    var it = NameIterator{ .buffer = &buf, .pos = 0 };
    var count: usize = 0;
    while (true) {
        const label = it.next() catch break; // 必须最终报错（MalformedName）而非死循环
        if (label == null) break;
        count += 1;
        try std.testing.expect(count < 500); // 若到 500 说明死循环
    }
}

test "NameIterator simple domain" {
    // "example.com" 的编码: 7 e x a m p l e 3 c o m 0
    const domain = "\x07example\x03com\x00";
    var iter = NameIterator{ .buffer = domain, .pos = 0 };

    try std.testing.expectEqualStrings("example", (try iter.next()).?);
    try std.testing.expectEqualStrings("com", (try iter.next()).?);
    try std.testing.expect((try iter.next()) == null);
}

test "NameIterator with compression" {
    // 测试指针压缩: 指针指向更早出现的单个标签（RFC 1035 §4.1.4）
    var buffer: [24]u8 = @splat(0);
    // 在偏移 0 处放置更早出现的后缀 "com\x00"
    buffer[0] = 3;
    @memcpy(buffer[1..4], "com");
    buffer[4] = 0;

    // 在偏移 8 处放置 "example" + 指向偏移 0 ("com") 的压缩指针
    buffer[8] = 7;
    @memcpy(buffer[9..16], "example");
    buffer[16] = 0xC0;
    buffer[17] = 0x00;

    var iter = NameIterator{ .buffer = &buffer, .pos = 8 };

    try std.testing.expectEqualStrings("example", (try iter.next()).?);
    // 指针解引用返回 "com"
    try std.testing.expectEqualStrings("com", (try iter.next()).?);
    // 结束符
    try std.testing.expect((try iter.next()) == null);
}

test "NameIterator empty domain" {
    // 仅有结束符的空域名
    const empty = "\x00";
    var iter = NameIterator{ .buffer = empty, .pos = 0 };

    try std.testing.expect((try iter.next()) == null);
}

/// 将 DNS 线路格式域名转换为 RFC 1035 §5.1 表示格式（裸缓冲区语义：不约束压缩指针目标）。
/// 普通可打印 ASCII 直接写出；标签内的 '.' 与 '\\' 转义为 `\.` / `\\`，控制字符与非 ASCII 转义为 `\DDD`。
/// buffer: 包含 DNS 数据包的缓冲区
/// pos: 域名起始位置
/// out_buf: 输出缓冲区（普通 ASCII 域名最多 253 字节；含全转义极端情况至多 1003 字节）
/// 返回: 写入 out_buf 的字符串切片
///
/// buffer 是一整个 DNS 报文时请用 `formatDnsNameInMessage`，它会一并拒绝指向
/// header 的压缩指针。
pub fn formatDnsName(buffer: []const u8, pos: usize, out_buf: []u8) Error![]const u8 {
    return formatName(NameCursor.init(buffer, pos), out_buf);
}

/// 同 `formatDnsName`，但按完整报文语义校验（指针不得指向 12 字节 header）。
pub fn formatDnsNameInMessage(msg: []const u8, pos: usize, out_buf: []u8) Error![]const u8 {
    return formatName(NameCursor.initInMessage(msg, pos), out_buf);
}

fn formatName(cursor: NameCursor, out_buf: []u8) Error![]const u8 {
    var cur = cursor;
    var write_pos: usize = 0;
    var first_label = true;
    var has_any_label = false;

    while (try cur.next()) |label| {
        has_any_label = true;
        // 添加点分隔符（第一个标签前不加）
        if (!first_label) {
            if (write_pos >= out_buf.len) return error.BufferTooSmall;
            out_buf[write_pos] = '.';
            write_pos += 1;
        }
        first_label = false;

        // 快路径：无特殊字节的普通 ASCII 标签整段拷贝
        var needs_escape = false;
        for (label) |b| {
            if (b <= 0x20 or b >= 0x7F or b == '.' or b == '\\') {
                needs_escape = true;
                break;
            }
        }
        if (!needs_escape) {
            if (write_pos + label.len > out_buf.len) return error.BufferTooSmall;
            @memcpy(out_buf[write_pos .. write_pos + label.len], label);
            write_pos += label.len;
        } else {
            for (label) |b| {
                if (b == '.' or b == '\\') {
                    if (write_pos + 2 > out_buf.len) return error.BufferTooSmall;
                    out_buf[write_pos] = '\\';
                    out_buf[write_pos + 1] = b;
                    write_pos += 2;
                } else if (b <= 0x20 or b >= 0x7F) {
                    if (write_pos + 4 > out_buf.len) return error.BufferTooSmall;
                    out_buf[write_pos] = '\\';
                    out_buf[write_pos + 1] = '0' + (b / 100);
                    out_buf[write_pos + 2] = '0' + ((b / 10) % 10);
                    out_buf[write_pos + 3] = '0' + (b % 10);
                    write_pos += 4;
                } else {
                    if (write_pos + 1 > out_buf.len) return error.BufferTooSmall;
                    out_buf[write_pos] = b;
                    write_pos += 1;
                }
            }
        }
    }

    // 根域名（无标签）返回 "."
    if (!has_any_label) {
        if (out_buf.len == 0) return error.BufferTooSmall;
        out_buf[0] = '.';
        return out_buf[0..1];
    }
    return out_buf[0..write_pos];
}

/// 自包含的域名引用：{完整报文缓冲区, 域名起始偏移}。
/// 携带完整报文，因此可独立跟随压缩指针解析，无需指针算术或调用方隐式不变量。
/// RData 中的域名字段即为此类型。
pub const Name = struct {
    /// 完整 DNS 报文缓冲区（压缩指针可指向其中任意更早位置）
    buffer: []const u8,
    /// 域名在报文中的起始偏移
    offset: usize,

    /// 解析为 RFC 1035 §5.1 表示格式写入 out_buf（跟随压缩指针，带循环检测）。
    /// 返回指向 out_buf 的切片。
    /// `buffer` 按定义是完整报文，故指向 header 的压缩指针会被拒绝。
    pub fn str(self: Name, out_buf: []u8) Error![]const u8 {
        return formatDnsNameInMessage(self.buffer, self.offset, out_buf);
    }

    /// 按完整报文语义零拷贝比较两个 Name 的 DNSSEC canonical 顺序（RFC 4034 §6.1）。
    pub fn canonicalCompare(self: Name, other: Name) Error!std.math.Order {
        return canonicalCompareWire(self.buffer, self.offset, other.buffer, other.offset, MESSAGE_POINTER_FLOOR);
    }
};

test "Name.str resolves uncompressed name" {
    const domain = "\x03www\x07example\x03com\x00";
    const name = Name{ .buffer = domain, .offset = 0 };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com", try name.str(&buf));
}

test "Name.str follows compression pointer" {
    var msg: [64]u8 = undefined;
    @memset(&msg, 0);
    // "example.com\0" 位于偏移 12（header 之后——真实报文里名字不会更靠前）
    msg[12] = 7;
    @memcpy(msg[13..20], "example");
    msg[20] = 3;
    @memcpy(msg[21..24], "com");
    msg[24] = 0;
    // 偏移 28: "www" + 指向偏移 12 的压缩指针
    msg[28] = 3;
    @memcpy(msg[29..32], "www");
    msg[32] = 0xC0;
    msg[33] = 12;

    const name = Name{ .buffer = &msg, .offset = 28 };
    var buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("www.example.com", try name.str(&buf));
}

test "Name.str rejects a pointer into the header" {
    // Name.buffer 按定义是完整报文，指向 header 的指针是畸形 RDATA，
    // 不得因为「只是解析 RDATA 内的名字」就绕过 owner name 那条路径的判定。
    var msg: [32]u8 = undefined;
    @memset(&msg, 0);
    msg[12] = 0xC0;
    msg[13] = 0x02;

    const name = Name{ .buffer = &msg, .offset = 12 };
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidOffset, name.str(&buf));
}

test "formatDnsName simple domain" {
    const domain = "\x07example\x03com\x00";
    var buf: [256]u8 = undefined;

    const result = try formatDnsName(domain, 0, &buf);
    try std.testing.expectEqualStrings("example.com", result);
}

test "formatDnsName root domain" {
    const root = "\x00";
    var buf: [256]u8 = undefined;

    const result = try formatDnsName(root, 0, &buf);
    try std.testing.expectEqualStrings(".", result);
}

test "formatDnsName subdomain" {
    const subdomain = "\x03www\x07example\x03com\x00";
    var buf: [256]u8 = undefined;

    const result = try formatDnsName(subdomain, 0, &buf);
    try std.testing.expectEqualStrings("www.example.com", result);
}

test "formatDnsName with compression pointer" {
    var buffer: [32]u8 = @splat(0);
    // 在偏移 0 处放置更早出现的 "example.com\x00"
    buffer[0] = 7;
    @memcpy(buffer[1..8], "example");
    buffer[8] = 3;
    @memcpy(buffer[9..12], "com");
    buffer[12] = 0;

    // 偏移 16: "www" + 指向偏移 0 ("example.com") 的压缩指针
    buffer[16] = 3;
    @memcpy(buffer[17..20], "www");
    buffer[20] = 0xC0;
    buffer[21] = 0x00;

    var buf: [256]u8 = undefined;
    const result = try formatDnsName(&buffer, 16, &buf);
    // 压缩指针会被正确跟随
    try std.testing.expectEqualStrings("www.example.com", result);
}

test "NameIterator detects invalid pointer offset" {
    const buffer = [_]u8{ 0xC0, 0x10 };
    var iter = NameIterator{ .buffer = &buffer, .pos = 0 };

    try std.testing.expectError(error.InvalidOffset, iter.next());
}

test "formatDnsName rejects name exceeding 255 bytes" {
    // 5 个 63 字节标签 = 320 字节 name，远超 RFC 1035 的 255 上限。
    // out_buf 给足 512，确保「不是因缓冲区太小而失败，而是因超长而失败」。
    var buf: [512]u8 = undefined;
    @memset(&buf, 0);
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        buf[pos] = 63;
        @memset(buf[pos + 1 ..][0..63], 'a');
        pos += 64;
    }
    buf[pos] = 0;

    var out: [512]u8 = undefined;
    try std.testing.expectError(error.NameTooLong, formatDnsName(&buf, 0, &out));
}

test "NameIterator.pos is the wire end after a compression pointer" {
    // 偏移 8 处 "example" + 指向偏移 0 的指针；线格式在指针后结束（偏移 18），
    // 而非指针目标 "com" 之后（偏移 5）。调用方按 pos 续读才能拿到正确字节。
    var buffer: [24]u8 = @splat(0);
    buffer[0] = 3;
    @memcpy(buffer[1..4], "com");
    buffer[4] = 0;
    buffer[8] = 7;
    @memcpy(buffer[9..16], "example");
    buffer[16] = 0xC0;
    buffer[17] = 0x00;

    var iter = NameIterator{ .buffer = &buffer, .pos = 8 };
    try std.testing.expectEqualStrings("example", (try iter.next()).?);
    try std.testing.expectEqualStrings("com", (try iter.next()).?);
    try std.testing.expect((try iter.next()) == null);
    try std.testing.expectEqual(@as(usize, 18), iter.pos);
    // 与 skipName 给出的线格式结束点一致。
    try std.testing.expectEqual(@as(usize, 18), try skipName(&buffer, 8, 0));
}

test "NameIterator.pos ends after terminator for uncompressed name" {
    const domain = "\x07example\x03com\x00";
    var iter = NameIterator{ .buffer = domain, .pos = 0 };
    while (try iter.next()) |_| {}
    try std.testing.expectEqual(@as(usize, 13), iter.pos);
}

test "skipName enforces 255 including the root octet (RFC 1035 2.3.4)" {
    // 3×63 + 1×61 标签：线格式 = 64*3 + 62 + 1 = 255 -> 合法。
    // 同构造改成 62 字节末标签：= 256 -> NameTooLong。
    const S = struct {
        fn build(buf: []u8, last: u8) []const u8 {
            var pos: usize = 0;
            for (0..3) |_| {
                buf[pos] = 63;
                @memset(buf[pos + 1 ..][0..63], 'a');
                pos += 64;
            }
            buf[pos] = last;
            @memset(buf[pos + 1 ..][0..last], 'b');
            pos += 1 + last;
            buf[pos] = 0;
            return buf[0 .. pos + 1];
        }
    };
    var buf: [512]u8 = undefined;

    const ok = S.build(&buf, 61);
    try std.testing.expectEqual(@as(usize, 255), ok.len);
    try std.testing.expectEqual(@as(usize, 255), try skipName(ok, 0, 0));

    var buf2: [512]u8 = undefined;
    const too_long = S.build(&buf2, 62);
    try std.testing.expectEqual(@as(usize, 256), too_long.len);
    try std.testing.expectError(error.NameTooLong, skipName(too_long, 0, 0));
}

test "skipName agrees with NameCursor" {
    // skipName 是 NameCursor.next 的无切片副本；两者对「接受/拒绝」的判定必须一致，
    // 否则「只跳过」与「展开」两条路径又会重新分叉（issue #2 的根因）。
    // floor=0（裸缓冲区）与 floor=12（完整报文）两种语义都要对齐——parser 用的是后者。
    const cases = [_][]const u8{
        "\x00", // 根
        "\x07example\x03com\x00", // 普通名
        "\x03www\xC0\x01", // 指针（目标在缓冲区内，但 <12）
        "\x40aaaa\x00", // 标签 >63
        "\x03www", // 缺结束符
        "\xC0", // 悬挂指针
        "\xC0\x00", // 自指成环
        "\xC0\x02\xC0\x00", // 互指成环
        "\x01a\xC0\x00", // 带标签的环
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03com\x00\xC0\x0c", // 指针 -> 12（合法）
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03com\x00\xC0\x0b", // 指针 -> 11（<floor）
    };
    for (cases) |buf| {
        for ([_]usize{ 0, MESSAGE_POINTER_FLOOR }) |floor| {
            const starts = [_]usize{ 0, @min(12, buf.len -| 1), @min(17, buf.len -| 1) };
            for (starts) |start| {
                const skip_err: ?anyerror = if (skipName(buf, start, floor)) |_| null else |e| e;
                var cur = NameCursor{ .buffer = buf, .pos = start, .pointer_floor = floor };
                const cursor_err: ?anyerror = while (true) {
                    if (cur.next()) |label| {
                        if (label == null) break null;
                    } else |e| break e;
                };
                try std.testing.expectEqual(cursor_err, skip_err);
            }
        }
    }
}

test "formatDnsName escapes dots, backslashes and control bytes (RFC 1035 5.1)" {
    var out: [256]u8 = undefined;
    // 单字节标签 '.' 必须转义为 "\."，不得与根域名 "." 冲突
    try std.testing.expectEqualStrings("\\.", try formatDnsName("\x01.\x00", 0, &out));
    // 单标签内含点："example.com"（1 标签）-> "example\.com"
    try std.testing.expectEqualStrings("example\\.com", try formatDnsName("\x0bexample.com\x00", 0, &out));
    // 标签含反斜杠与控制字符/高位字节
    try std.testing.expectEqualStrings("a\\\\b\\000\\255.com", try formatDnsName("\x05a\\b\x00\xff\x03com\x00", 0, &out));
}

test "Name.canonicalCompare and canonicalCompare preserve RFC 4034 6.1 order on labels with dots" {
    const O = std.math.Order;
    // Wire A: \x03b.a\x03com\x00（2 标签：b\.a, com）
    // Wire B: \x01a\x01b\x03com\x00（3 标签：a, b, com）
    // RFC 4034 §6.1 自右向左比较：com == com，次右标签 "b.a" > "b" -> .gt
    var msg_a: [32]u8 = @splat(0);
    @memcpy(msg_a[12..21], "\x03b.a\x03com\x00");
    var msg_b: [32]u8 = @splat(0);
    @memcpy(msg_b[12..21], "\x01a\x01b\x03com\x00");

    const na = Name{ .buffer = msg_a[0..21], .offset = 12 };
    const nb = Name{ .buffer = msg_b[0..21], .offset = 12 };
    try std.testing.expectEqual(O.gt, try na.canonicalCompare(nb));
    try std.testing.expectEqual(O.lt, try nb.canonicalCompare(na));

    // 经 Name.str 转义后再调表示格式 canonicalCompare 也必须给出相同顺序
    var ba: [256]u8 = undefined;
    var bb: [256]u8 = undefined;
    try std.testing.expectEqual(O.gt, canonicalCompare(try na.str(&ba), try nb.str(&bb)));

    // 内部空标签不得与正常名字静默判等
    try std.testing.expect(canonicalCompare("a..example.com", "a.example.com") != .eq);
    try std.testing.expect(canonicalCompare(".example.com", "example.com") != .eq);
}

test "canonicalCompare maintains strict weak ordering when one operand has invalid escape" {
    const O = std.math.Order;
    // 评审复现向量：a 含合法转义而 b 含非法转义 \256 时，绝不得退化为 b 与自身比较返回 .eq
    try std.testing.expectEqual(O.lt, canonicalCompare("a\\.x.example", "b\\256.example"));
    try std.testing.expectEqual(O.gt, canonicalCompare("b\\256.example", "a\\.x.example"));

    // 混合合法无转义、合法含转义、非法转义的样本集：全对验证反对称性与传递性，并跑通 std.mem.sort
    var items = [_][]const u8{
        "z.example",
        "b\\256.example",
        "a\\.z.example",
        "b.b.example",
        "a\\256.d.example",
        "a.example",
        "bad\\",
    };
    for (items) |x| {
        try std.testing.expectEqual(O.eq, canonicalCompare(x, x));
        for (items) |y| {
            const xy = canonicalCompare(x, y);
            const yx = canonicalCompare(y, x);
            try std.testing.expectEqual(xy.invert(), yx);
            for (items) |z| {
                const yz = canonicalCompare(y, z);
                const xz = canonicalCompare(x, z);
                if (xy == .lt and yz == .lt) try std.testing.expectEqual(O.lt, xz);
                if (xy == .eq and yz == .eq) try std.testing.expectEqual(O.eq, xz);
            }
        }
    }
    mem.sort([]const u8, &items, {}, struct {
        fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
            return canonicalCompare(lhs, rhs) == .lt;
        }
    }.lessThan);
    for (items[0 .. items.len - 1], items[1..]) |prev, next| {
        try std.testing.expect(canonicalCompare(prev, next) != .gt);
    }
}

test "Name.canonicalCompare works at packet offsets >= 256 and max escaped length is 1003" {
    var pkt: [512]u8 = @splat(0);
    // 偏移 12 放后缀 "example\0"
    @memcpy(pkt[12..21], "\x07example\x00");
    // 偏移 300 (>255) 放 "b" + 指向 12 的指针；偏移 340 (>255) 放 "a" + 指向 12 的指针
    @memcpy(pkt[300..304], "\x01b\xC0\x0C");
    @memcpy(pkt[340..344], "\x01a\xC0\x0C");
    const nb = Name{ .buffer = &pkt, .offset = 300 };
    const na = Name{ .buffer = &pkt, .offset = 340 };
    try std.testing.expectEqual(std.math.Order.gt, try nb.canonicalCompare(na));
    try std.testing.expectEqual(std.math.Order.lt, try na.canonicalCompare(nb));

    // 极限全转义线格式名字（3×63 + 1×61 个 0x00 字节 = 255 字节线格式）：输出恰为 1003 字节
    var max_wire: [255]u8 = @splat(0);
    max_wire[0] = 63;
    max_wire[64] = 63;
    max_wire[128] = 63;
    max_wire[192] = 61;
    max_wire[254] = 0;
    var out_exact: [1003]u8 = undefined;
    const formatted = try formatDnsName(&max_wire, 0, &out_exact);
    try std.testing.expectEqual(@as(usize, 1003), formatted.len);
    var out_short: [1002]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, formatDnsName(&max_wire, 0, &out_short));
}

test "NameCursor.initInMessage rejects pointers into the header" {
    // formatNameAt / nameEqualsAt / Name.str 都走 Cursor；它们必须和 skipName
    // 一样拒绝指向 header 的指针，否则同一个报文在两条路径上判定不同。
    var msg: [32]u8 = undefined;
    @memset(&msg, 0);
    msg[12] = 0xC0;
    msg[13] = 0x02; // 指向偏移 2（header 内）

    var cur = NameCursor.initInMessage(&msg, 12);
    try std.testing.expectError(error.InvalidOffset, cur.next());
    try std.testing.expectEqual(@as(usize, MESSAGE_POINTER_FLOOR), cur.pointer_floor);

    var out: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidOffset, formatDnsNameInMessage(&msg, 12, &out));
    // 裸缓冲区语义下同一输入只按普通名字校验（此处目标是 0 字节 -> 根）。
    try std.testing.expectEqualStrings(".", try formatDnsName(&msg, 12, &out));
}

test "skipName rejects pointer below the floor" {
    // 报文上下文中，域名不可能起始于 12 字节 header 内；指向 header 的指针是畸形输入。
    var msg: [32]u8 = undefined;
    @memset(&msg, 0);
    msg[12] = 0xC0;
    msg[13] = 0x02; // 指向偏移 2（header 内）
    try std.testing.expectError(error.InvalidOffset, skipName(&msg, 12, 12));
    // 裸缓冲区语义（floor=0）下同一输入仅按普通名字校验。
    _ = try skipName(&msg, 12, 0);
}

test "skipName validates the expansion behind a pointer" {
    // 指针目标处（更早偏移 12）是超长标签：只跳过不展开的实现会放行，skipName 必须报错。
    var msg: [96]u8 = @splat(0);
    msg[12] = 64; // 非法标签长度
    msg[80] = 0xC0;
    msg[81] = 12;
    try std.testing.expectError(error.LabelTooLong, skipName(&msg, 80, 12));

    // 指针成环同样必须在跳过阶段被拒。
    var loop: [32]u8 = undefined;
    @memset(&loop, 0);
    loop[12] = 0xC0;
    loop[13] = 14;
    loop[14] = 0xC0;
    loop[15] = 12;
    try std.testing.expectError(error.MalformedName, skipName(&loop, 12, 12));
}

test "NameCursor terminates on pointer loop" {
    // 两个互指的压缩指针形成环：offset0 -> 2, offset2 -> 0。
    // 前向指针拒绝与跳转限次必须立即让它报 MalformedName 而非死循环。
    const buf = [_]u8{ 0xC0, 0x02, 0xC0, 0x00 };
    var out: [256]u8 = undefined;
    try std.testing.expectError(error.MalformedName, formatDnsName(&buf, 0, &out));
}

test "NameCursor and skipName reject forward compression pointers and >128 pointer chains (RFC 1035 4.1.4)" {
    // 前向指针：偏移 12 处的名字跳向偏移 20（即使偏移 20 处是合法 "com\0" 也须拒绝）
    var fwd: [32]u8 = @splat(0);
    @memcpy(fwd[12..18], "\x03www\xC0\x14");
    @memcpy(fwd[20..25], "\x03com\x00");
    var out: [256]u8 = undefined;
    try std.testing.expectError(error.MalformedName, formatDnsNameInMessage(&fwd, 12, &out));
    try std.testing.expectError(error.MalformedName, skipName(&fwd, 12, MESSAGE_POINTER_FLOOR));

    // 向后指针链超过 MAX_POINTER_JUMPS(128) 跳时须拒绝
    var chain: [300]u8 = @splat(0);
    @memcpy(chain[12..17], "\x03com\x00");
    var prev: usize = 12;
    var off: usize = 18;
    for (0..MAX_POINTER_JUMPS + 1) |_| {
        chain[off] = 0xC0 | @as(u8, @intCast(prev >> 8));
        chain[off + 1] = @intCast(prev & 0xFF);
        prev = off;
        off += 2;
    }
    try std.testing.expectError(error.MalformedName, formatDnsNameInMessage(chain[0..off], prev, &out));
    try std.testing.expectError(error.MalformedName, skipName(chain[0..off], prev, MESSAGE_POINTER_FLOOR));
}
