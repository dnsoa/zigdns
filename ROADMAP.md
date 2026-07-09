# zigdns ROADMAP

本文件记录 code review 发现的架构、BUG、性能与工程化问题，作为向"高性能 DNS server（eBPF / DPDK）与 client"演进的待办清单。

审查基准：`main` @ 6eec2dd，Zig 0.16.0，`zig build test` 全绿（**注意：全绿掩盖了下方 P0 缺陷**）。

优先级：**P0** 阻塞正确性 / **P1** 架构关键 / **P2** 性能 / **P3** 工程化。

---

## P0 — 正确性阻塞（必须先修）

### 1. Header 线格式字节序完全错误 — ✅ 已修复（原为已实测确认）

> **状态：已修复** `src/header.zig` 的 `decode`/`encode` 改为显式按线格式字节映射（不再依赖 packed struct 隐式位序）。新增 4 个固定字节向量测试（真实 query/response、opcode/rcode 位、精确 encode 字节）+ 1 个与 `MessageParser` count 读取一致性的互操作测试，取代原来会掩盖 bug 的往返测试。`zig build test` 全绿。下方保留原始分析供参考。

`src/header.zig` 的 `Header` 是 `packed struct(u96)`。Zig 的 packed struct 字段是 **从最低有效位（LSB）开始排列**，而 `decode`/`encode` 用 `mem.readInt(u96, data, .big)` / `writeInt(..., .big)` 处理。大端读入后，`data[0]`（ID 高字节）落到 u96 的**最高位**，而结构体第一个字段 `id` 却在**最低位** —— 整个 12 字节头部的位布局与协议**镜像颠倒**。

实测（对真实查询报文 `12 34 01 00 00 01 00 00 00 00 00 00`）：

```
id       = 0x0   （应为 0x1234）
rd       = 0     （应为 1）
qdcount  = 0     （应为 1）
ancount  = 1     （应为 0，实际吃到了 qdcount 的值）
```

**影响**：所有从真实报文读取的 header 字段（id/qr/opcode/rcode/各 count）全部错误；`Builder.finish` 写出的 header 也不符合线格式。DNS server/client 的一切都建立在 header 之上，这是最高优先级。

**为什么测试没发现**：`header.zig` 唯一的测试是 `encode → decode` 往返。`readInt`/`writeInt` 与 `bitCast` 各自互逆，往返恒等，永远通过，**完全不验证线格式**。

**修复方向**：不要依赖 packed struct 的隐式位序。显式按字节解码，标志位手动移位：

```zig
// byte2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
// byte3: RA(1) Z(1) AD(1) CD(1) RCODE(4)
id      = readInt(u16, data[0..2], .big);
qr      = data[2] >> 7;
opcode  = (data[2] >> 3) & 0x0F;
aa      = (data[2] >> 2) & 1;
tc      = (data[2] >> 1) & 1;
rd      =  data[2] & 1;
ra      =  data[3] >> 7;
// z/ad/cd 见 P1-8
rcode   =  data[3] & 0x0F;
qdcount = readInt(u16, data[4..6], .big); // ancount/nscount/arcount 同理
```

并补充 **真实抓包字节向量测试**（见 P3-15），断言解码结果等于已知值，而非往返。

---

## P1 — 架构关键（server/client 落地前必须解决）

### 2. RDATA 中的域名不是可用值（原描述为"无法解析压缩"，已更正）— ✅ 已修复

> **状态：已修复（并更正定性）** 实测表明：压缩指针**本来就能解析**（由调用方经 `formatNameFromSlice → formatNameAt` 完成，二者持有完整报文）——所以这**不是**解析正确性 bug。真实问题是 API 安全性/易用性：RDATA 域名字段是**裸线格式字节**（直接用会打印乱码）、解析依赖脆弱的 `@intFromPtr`（见 #12）、且 `RData.parse(rtype, rr.rdata)` 只在"切片必须别名原报文"这一隐式不变量下才正确。
>
> **修复方案（自包含 Name 类型）**：
> - 新增 `Name{ buffer, offset }`（`src/name.zig`），`str(out_buf)` 经 `formatDnsName` 跟随压缩指针解析，无指针算术、无别名假设。
> - `RData` 的 NS/CNAME/PTR/MX.exchange/SOA.mname/rname/SRV.target 字段改为 `Name`。
> - `RData.parse` 签名改为 `(rtype, msg, rdata_offset, rdlength)`；新增便捷方法 `MessageParser.parseRData(rr)`。`ResourceRecord` 增加 `rdata_offset` 字段。
> - 连带关闭 **#12**：删除 `formatNameFromSlice` 及其 `@intFromPtr` 隐患。
> - 更新 `examples/records.zig`、`examples/response.zig`；新增 Name 解析 + 压缩指针解析单测。
> - 验证：`zig build test`（16 rdata + 10 name 等全绿）、`zig build examples` 均 exit 0；`example-records` 端到端打印出正确的 `mail.example.org` / SOA / SRV 等域名。
>
> 下方保留原始（部分不准确的）分析供对照。

`src/rdata.zig` 的 `RData.parse` 只接收 `rdata: []const u8`（rdata 切片），而 `NS/CNAME/PTR/MX/SOA/SRV` 里的域名：
- 通过 `parseName` 返回 `data[start..pos]`，即**原始线格式字节（带长度前缀）**，不是 `www.example.com`；调用方拿到基本不可用。
- 若域名含压缩指针，指针偏移是相对**整个报文**的，而 `parse` 手里只有 rdata 切片，**根本无法解引用**。测试 `RData parseName preserves compression pointer bytes` 恰恰证明它把指针字节原样返回了。

**影响**：无法正确读取任何带压缩的 CNAME/NS/MX/SOA/SRV —— 而真实响应几乎总是压缩的。

**修复方向**：RDATA 解析必须携带完整报文上下文（buffer + record 在报文中的绝对偏移），复用 `MessageParser.formatNameAt` 解析内嵌域名；或将 rdata 内域名以"绝对偏移"形式返回，交给上层用 `formatNameAt` 展开。

**同根症状**：`src/bench.zig:312` 只能靠 `formatNameAt(rr.name_end_pos - 2, …)` 这种 `-2` 技巧倒推域名——而 `-2` 仅在该名字恰好以压缩指针结尾时成立，正是"解析出的名字不是可用值"这一根因的体现。

### 3. 缺少 TCP 组帧（2 字节长度前缀）— ✅ 已修复

> **状态：已修复** 解析侧新增 `Message.parseTcp(raw)`（校验并剥离 2 字节大端长度前缀，零拷贝引用其后报文）。构造侧新增 `Builder.initTcp(dest)`（预留 2 字节，DNS 报文写入 `dest[2..]`，压缩偏移相对 DNS 报文起始因而正确）+ `finishTcp(header)`（回填长度前缀、超 0xFFFF 返回 `MessageTooLong`，返回完整帧）。新增 round-trip 与截断帧拒绝测试。AXFR/IXFR 的多报文语义仍待后续。

### 4. Builder 不设置 TC，缓冲区不足时直接报错 — ✅ 已修复（原子回滚，使截断可安全恢复）

> **状态：已修复** 每个 `add*` 方法现为**原子**：入口 `snapshot()` + `errdefer restore()`，失败（`BufferTooSmall`）时把 `pos`/`compression_count` 回滚到调用前，已写记录完好无损。分区计数在全部写入成功后才递增，失败不误计。由此 server 可实现标准截断：
> ```zig
> builder.addARecord(...) catch |e| switch (e) {
>     error.BufferTooSmall => break, // 放不下就停止追加
>     else => return e,
> };
> // 置 TC=1 后正常 finish，得到有效的截断报文
> ```
> 新增测试验证：失败 add 后 `pos`/计数不变，随后可置 TC=1 正常收尾并解析。（此前失败会留下部分写入、状态损坏。）未来可再加一个自动置 TC 的便捷包装。

### 5. `Builder.finish` 盲信调用方给的 count — ✅ 已修复（自动计数）

> **状态：已修复** Builder 内部按分区计数（`qd/an/ns/ar`）：`addQuestion` 计入 question，RR 计入当前分区（默认 answer，经 `setSection(.authority/.additional)` 推进，debug 下断言只能向后推进且 question 必须先于所有 RR）。`finish(header)` 自动用真实计数回填 header 四个 count 字段——不再可能 desync。保留 `finishRaw(header)`（原样使用调用方计数，供高级/测试用途）。新增测试验证多分区自动计数并可被 parser 完整遍历。

### 6. Opcode / Rcode 为穷举 enum（潜在，非当前可触发）— ✅ 已修复

> **状态：已修复** `Opcode`、`Rcode` 均已加 `_`（非穷举），`@enumFromInt` 保留/未知值不再 UB。新增测试。

`src/types.zig` 中 `Opcode`（缺 3/6/7…）与 `Rcode`（缺 11–15）是**无 `_` 的穷举枚举**。`Type`、`Class` 已正确带 `_`。

**已核实的严重度修正**：当前不可信解析路径**并不会** `@enumFromInt` 这两个枚举——header 把 opcode/rcode 存为裸 `u4`，parser 只对 `Type`（有 `_`）做 `@enumFromInt`。因此这是**潜在（latent）**风险，一旦将来在 API 里对 header 标志做 `@enumFromInt` 就会 UB/panic，**并非今天可被远端触发的崩溃**。修复廉价（加 `_`），建议顺手做，但不属 P1-panic 级。

### 7. Builder 压缩仅比对 64 位 hash，从不核对字节 — ✅ 已修复

> **状态：已修复** `writeName` 在 hash 命中后新增 `nameMatchesAt(pos, canonical)` 字节级确认才发压缩指针；碰撞时回退为写完整域名（正确但不压缩）。新增测试：篡改压缩表制造 hash 碰撞，验证第二个域名仍被展开写入且解析回来正确（而非跟随坏指针）。

### 8. `z: u3` 把 Z/AD/CD 合并，无法表达 DNSSEC 标志

RFC 2535 起 byte3 为 `RA(1) Z(1) AD(1) CD(1) RCODE(4)`。当前 `z: u3` 吞掉了 AD、CD。DNSSEC-aware 解析需要独立的 AD/CD 位。**待办**：随 P0-1 重做 header 时拆分。

### 9. EDNS 只能读不能写 — ✅ 已修复

> **状态：已修复** 新增 `Builder.addOptRecord(Edns)`：自动置于附加区并计数，写入 OPT 记录（root name / CLASS=UDP 载荷大小 / TTL 编码 extended-rcode+version+DO 标志），`Edns.ecs` 非空时附带 ECS 选项（按 RFC 7871 校验 family/prefix/地址长度）。另有低级 `addOptRecordRaw(udp_size, ttl, options)` 供自定义选项。`Edns` 已导出。原子回滚同其他 add*。新增 round-trip（含 DO 标志与 ECS 解析回验）、裸 EDNS、非法 ECS 拒绝三个测试。Cookie/其他 EDNS 选项待后续。

### 10. ECS 地址长度未按 family/prefix 校验 — ✅ 已修复

> **状态：已修复** `parseECSOption` 按 RFC 7871 校验：family 仅接受 1/2（否则 `MalformedECS`），`source_prefix` 不得超过族上限（IPv4=32 / IPv6=128），地址字节数必须恰为 `ceil(source_prefix/8)`。新增拒绝（长度不符/超限 prefix/未知 family）与接受（合法 IPv6）测试。

---

### 19. Builder RDATA `@memcpy` 无 `ensureCapacity` 守卫——真实缓冲区溢出 — ✅ 已修复（原为已实测确认）

> **状态：已修复** `addARecord`/`addAAAARecord` 在最后的 RDATA `@memcpy` 前分别加了 `try self.ensureCapacity(4)` / `ensureCapacity(16)`。新增两个边界回归测试（36/48 字节缓冲区，令守卫写入恰好通过、仅 RDATA 拷贝越界），在 Debug 与 **ReleaseFast** 下均返回 `BufferTooSmall` 而非静默越界。下方保留原始分析。

`src/message.zig:90`（`addARecord`）与 `:101`（`addAAAARecord`）在写入定长 RDATA 时：

```zig
@memcpy(self.buf[self.pos..][0..4], &ip);   // addARecord，之前无 ensureCapacity(4)
```

该记录的**所有其他写入都有守卫**（`writeName`/`writeU16`/`writeU32` 各自 `ensureCapacity`），唯独最后这次 RDATA 拷贝没有。`addTXTRecord`（`:166`）却正确地做了 `ensureCapacity(txt.len + 1)`——**同一文件内不一致**。

实测（`addARecord("example.com", …)` 写入 36 字节缓冲区，前序守卫写入到 `pos=35`，最后拷贝 4 字节 rdata）：
- **Debug**：`panic: index out of bounds: index 39, len 36`（`message.zig:90`）
- **ReleaseFast**：**静默越界写**，无任何报错（`pos=39, buflen=36`，越过缓冲区 3 字节）

**影响**：这是构造路径上的**内存安全漏洞**，直接违背库自我宣称的 "safety" 定位；在 server 高压路径上（ReleaseFast）会静默破坏相邻内存。现有 `BufferTooSmall` 测试只覆盖 `addQuestion`，未触及此路径。**修复**：在两处 `@memcpy` 前加 `try self.ensureCapacity(4)` / `ensureCapacity(16)`。严重度等同 P1-4/5，应置于修复队列前列。

---

## P2 — 性能（eBPF / DPDK 高吞吐相关）

### 11. Header 解码用非原生 u96 bitcast

修好 P0-1 后，建议直接按字节 / 原生整型读取标志字节，避免 12 字节非 2 幂宽整型的 bitcast，在每包必经的热路径上更可控。

### 12. `formatNameFromSlice` 用 `@intFromPtr` 做偏移，脆弱且潜在 UB — ✅ 已修复（随 #2）

> **状态：已修复** 随 #2 一并移除 `formatNameFromSlice`，改由自包含的 `Name{ buffer, offset }` 承载偏移，`Name.str` 直接经 `formatDnsName` 解析——不再有任何 `@intFromPtr` 指针算术。下方保留原始分析。

`src/parser.zig:337` 用 `@intFromPtr(slice.ptr) - @intFromPtr(buffer.ptr)` 反推偏移。

**已核实的修正**：此函数**是活代码**——`examples/records.zig` 里 MX/CNAME/NS/PTR/SOA(mname/rname)/SRV 共 **8 处**调用，`zig build` 会构建到。且"下溢被 `>= len` 拦截"的说法不准确：若切片不在 buffer 内，**安全构建下 `ptr - ptr` 的下溢会先 panic**，轮不到 `>= len` 检查。**建议**：改为显式传偏移（配合 P1-2 让 RDATA 内域名以绝对偏移返回），移除指针算术。

### 13. EDNS/OPT 多次扫描重复解析

`findOptRecord` 与 `findECS` 各自从 `parser` 状态克隆后**从头线性扫描** additional section。server 若既要 OPT 又要 ECS，会扫两遍。**建议**：单趟扫描返回 OPT 记录 + 其中的 ECS。

### 14. 面向 DPDK 的批量 / 分散缓冲区 API 缺失

现有 API 假设单一连续 `[]const u8`。DPDK 的 mbuf 可能分段（scatter-gather），且高吞吐场景需要批处理接口。**待办（长期）**：评估 vectored/批量解析接口；name 比较 / label 扫描可引入 SIMD。

---

## P3 — 工程化与测试

### 15. 缺少不可信输入的 fuzz 测试 — ✅ 已修复（harness 就绪）

> **状态：已修复** 新增 `src/fuzz.zig`，用 Zig 0.16 `std.testing.fuzz`(`*Smith`) 覆盖 5 个入口：`Message.parse`+完整遍历（question/RR/rdata/内嵌域名）、`Message.parseTcp`+走帧、`formatNameAt`/`nameEqualsAt`（任意偏移）、`NameIterator`、`parseECS`。不变量：任意字节不 panic/不 UB/不死循环。已接入 `build.zig`：`zig build test` 编译并冒烟运行一次（CI 保活），`zig build fuzz --fuzz` 做真正模糊。
>
> **已知外部阻碍**：本机 Zig 0.16.0（homebrew `0.16.0_1`）自带的 `compiler/test_runner.zig` 在 fuzz 插桩构建下有类型错误（`writeStackTrace` 期望 `*const debug.StackTrace`），导致 `--fuzz` 引擎本身编译失败——**非本库代码问题**（`zig build test` 全绿，harness 自身零编译错误）。换用修复该 bug 的 Zig 版本即可实跑。

### 16. 测试存在结构性盲区

`Header` 往返测试掩盖了 P0-1 这样的线格式错误。**待办**：改用**真实抓包字节向量**做断言（对已知报文断言具体字段值），覆盖 parse↔build 的互操作往返。

### 17. 无 CI — ✅ 已修复

> **状态：已修复** 新增 `.github/workflows/ci.yml`（push main + PR 触发）：`mlugg/setup-zig@v2`(pin 0.16.0) → `zig fmt --check .` → `zig build test`（含 fuzz 冒烟）→ `zig build examples`。代码已 `zig fmt` 全库格式化通过。

### 18. 文档漂移 / 未验证的性能声明

- `README.md` 的 `Error` 集合缺 `InvalidOffset`、`MalformedECS`（与 `src/errors.zig` 不一致）。
- README "Parse ~50ns / Encode ~100ns" 无可复现依据；且在 P0-1 修复前，header 相关基准衡量的是错误代码。
- **已核实的修正**：examples **已**由默认 `zig build` 构建（`build.zig:67` 无条件 `installArtifact`）；问题仅是它们**未纳入 `test` step**，所以其中的 bug（如 P1-19 的 RDATA 域名路径）不会被 `zig build test` 捕获。

---

## 建议修复顺序

1. **P0-1**（header）+ **#19**（Builder `@memcpy` 越界）——地基正确性 + 内存安全，二者最先修；各补最小复现测试。
2. **P1-2**（RDATA 域名/压缩，连带 #12、`bench.zig:312`）——影响正确解析真实响应。
3. **P1-3/4/5/9**（TCP、TC、count、EDNS 构造）——server/client 骨架能力。
4. **P3-15/16/17**（fuzz + 向量测试 + CI）——防回归，锁死正确性后再谈性能。**顺手**：P1-6 加枚举 `_`（廉价、潜在）。
5. **P2**（性能）——在正确性与测试就位后，用基准驱动优化。

> 备注：P2 的性能优化应在 P0/P1 正确性修复与 P3 测试护栏就位**之后**进行——否则是在错误的实现上做基准。
