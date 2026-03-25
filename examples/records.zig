const std = @import("std");
const dns = @import("dns");
const Type = dns.Type;
const Builder = dns.Message.Builder;

pub fn main() !void {
    std.debug.print("=== DNS Record Types Example ===\n\n", .{});

    // 创建一个 DNS 响应报文，展示各种记录类型
    var buffer: [2048]u8 = undefined;
    var builder = Builder.init(&buffer);

    // 添加各种类型的资源记录
    const ttl: u32 = 3600;

    // A 记录 (IPv4 地址)
    try builder.addARecord("example.org", ttl, [_]u8{ 93, 184, 216, 34 });
    std.debug.print("Added A record: example.org -> 93.184.216.34\n", .{});

    // AAAA 记录 (IPv6 地址)
    try builder.addAAAARecord("example.org", ttl, [_]u8{
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
    });
    std.debug.print("Added AAAA record: example.org -> 2001:db8:85a3::8a2e:370:7334\n", .{});

    // CNAME 记录
    try builder.addCNAMERecord("www.example.org", ttl, "example.org");
    std.debug.print("Added CNAME record: www.example.org -> example.org\n", .{});

    // MX 记录 (邮件交换)
    try builder.addMXRecord("example.org", ttl, 10, "mail.example.org");
    std.debug.print("Added MX record: example.org -> mail.example.org (priority 10)\n", .{});

    // NS 记录 (域名服务器)
    try builder.addNSRecord("example.org", ttl, "ns1.example.org");
    try builder.addNSRecord("example.org", ttl, "ns2.example.org");
    std.debug.print("Added NS records: ns1.example.org, ns2.example.org\n", .{});

    // TXT 记录
    try builder.addTXTRecord("example.org", ttl, "v=spf1 include:_spf.example.org ~all");
    std.debug.print("Added TXT record: SPF record\n", .{});

    // PTR 记录 (反向 DNS)
    try builder.addPTRRecord("34.216.184.93.in-addr.arpa", ttl, "example.org");
    std.debug.print("Added PTR record: 34.216.184.93.in-addr.arpa -> example.org\n", .{});

    // SRV 记录 (服务)
    try builder.addSRVRecord("_http._tcp.example.org", ttl, 10, 60, 8080, "web.example.org");
    std.debug.print("Added SRV record: _http._tcp.example.org -> web.example.org:8080\n", .{});

    // SOA 记录 (起始授权机构)
    try builder.addSOARecord(
        "example.org",
        ttl,
        "ns1.example.org",
        "hostmaster.example.org",
        2024010101,
        3600,
        600,
        86400,
        3600,
    );
    std.debug.print("Added SOA record for example.org\n", .{});

    // 构造头部
    const header = dns.Header{
        .id = 1234,
        .rd = 1,
        .tc = 0,
        .aa = 1,
        .opcode = 0,
        .qr = 1, // 响应
        .rcode = 0,
        .z = 0,
        .ra = 1,
        .qdcount = 0,
        .ancount = 10, // 10 条记录
        .nscount = 0,
        .arcount = 0,
    };

    const packet = builder.finish(header);

    std.debug.print("\n=== Packet Summary ===\n", .{});
    std.debug.print("Total packet size: {d} bytes\n", .{packet.len});
    std.debug.print("Record count: {d}\n", .{header.ancount});

    // 输出十六进制转储
    std.debug.print("\nHex dump (first 128 bytes):\n", .{});
    const dump_len = @min(packet.len, 128);
    for (packet[0..dump_len], 0..) |byte, i| {
        if (i % 16 == 0) std.debug.print("\n{X:0>4}: ", .{i});
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n", .{});

    // 解析并验证记录
    std.debug.print("\n=== Parsing Records Back ===\n", .{});
    var parser = dns.MessageParser.init(packet);

    var i: u32 = 1;
    while (try parser.nextRR()) |rr| {
        std.debug.print("{d}: Type={s} ", .{ i, @tagName(rr.rtype) });

        // 使用 RData.parse 解析 RDATA 字节
        const rdata = dns.ResourceData.parse(rr.rtype, rr.rdata) catch |err| {
            std.debug.print("(parse error: {})\n", .{err});
            i += 1;
            continue;
        };

        switch (rdata) {
            .A => |ip| {
                std.debug.print("A={d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] });
            },
            .AAAA => |ip| {
                std.debug.print("AAAA=", .{});
                for (ip, 0..) |b, j| {
                    if (j > 0 and j % 2 == 0) std.debug.print(":", .{});
                    std.debug.print("{X:0>2}", .{b});
                }
                std.debug.print("\n", .{});
            },
            .MX => |mx| {
                var name_buf: [256]u8 = undefined;
                const exchange_str = parser.formatNameFromSlice(mx.exchange, &name_buf) catch "[error]";
                std.debug.print("MX(pref={d}, exchange={s})\n", .{ mx.preference, exchange_str });
            },
            .CNAME => |cname| {
                var name_buf: [256]u8 = undefined;
                const cname_str = parser.formatNameFromSlice(cname, &name_buf) catch "[error]";
                std.debug.print("CNAME={s}\n", .{cname_str});
            },
            .NS => |ns| {
                var name_buf: [256]u8 = undefined;
                const ns_str = parser.formatNameFromSlice(ns, &name_buf) catch "[error]";
                std.debug.print("NS={s}\n", .{ns_str});
            },
            .PTR => |ptr| {
                var name_buf: [256]u8 = undefined;
                const ptr_str = parser.formatNameFromSlice(ptr, &name_buf) catch "[error]";
                std.debug.print("PTR={s}\n", .{ptr_str});
            },
            .TXT => |txt| {
                std.debug.print("TXT=\"{s}\"\n", .{txt});
            },
            .SOA => |soa| {
                var mname_buf: [256]u8 = undefined;
                var rname_buf: [256]u8 = undefined;
                const mname_str = parser.formatNameFromSlice(soa.mname, &mname_buf) catch "[error]";
                const rname_str = parser.formatNameFromSlice(soa.rname, &rname_buf) catch "[error]";
                std.debug.print("SOA(mname={s}, rname={s}, serial={d})\n", .{
                    mname_str, rname_str, soa.serial,
                });
            },
            .SRV => |srv| {
                var name_buf: [256]u8 = undefined;
                const target_str = parser.formatNameFromSlice(srv.target, &name_buf) catch "[error]";
                std.debug.print("SRV(prio={d}, weight={d}, port={d}, target={s})\n", .{
                    srv.priority, srv.weight, srv.port, target_str,
                });
            },
            else => {
                std.debug.print("\n", .{});
            },
        }
        i += 1;
    }
}
