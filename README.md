# zigdns

A high-performance DNS protocol library for Zig, featuring zero-copy packet parsing and construction.

## Features

- **Zero-copy parsing**: All parsed data references the original buffer - no allocations
- **Compression support**: Automatic compression pointer following on parse; shared-suffix compression on encode
- **Comprehensive record types**: A, AAAA, CNAME, NS, MX, TXT, PTR, SOA, SRV, CAA, SVCB, HTTPS
- **EDNS0 support**: OPT records with ECS (Client Subnet, RFC 7871) and DNS Cookies (RFC 7873)
- **DNSSEC**: DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM parsing and construction, key tag computation, type bitmaps, canonical ordering (RFC 4034 / 5155)
- **Type-safe**: Zig's type system ensures correctness at compile time
- **RFC compliant**: Follows RFC 1035, RFC 1034, and related standards

## Design Philosophy

This library prioritizes **performance** and **safety** for server-side DNS implementations:
- **No dynamic allocation** during parsing or encoding
- **Zero-copy** - data slices point directly into the packet buffer
- **Modular** - each component in a separate file for easy maintenance

## Installation

Add zigdns to your project:

```bash
zig fetch --save="dns" https://github.com/dnsoa/zigdns/archive/refs/tags/main.tar.gz
```

Then in your `build.zig`:

```zig
const dns = b.dependency("dns", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("dns", dns.module("dns"));
```

## Usage

### Creating a DNS Query

```zig
const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    // Buffer for the DNS packet
    var buffer: [512]u8 = undefined;
    var builder = dns.Message.Builder.init(&buffer);

    // Add a question for example.com A record
    try builder.addQuestion("example.com", .A, 1); // type=A, class=IN

    // Create the header
    const header = dns.Header{
        .id = 1234,
        .rd = 1,  // Recursion desired
        .tc = 0,
        .aa = 0,
        .opcode = 0,
        .qr = 0,   // Query
        .rcode = 0,
        .z = 0,
        .ra = 0,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    // Finalize the packet
    const packet = builder.finish(header);

    // Now send packet to a DNS server...
}
```

### Creating a DNS Response

```zig
const std = @import("std");
const dns = @import("dns");

pub fn createResponse() ![]const u8 {
    var buffer: [512]u8 = undefined;
    var builder = dns.Message.Builder.init(&buffer);

    // Add the question (mirrored from query)
    try builder.addQuestion("example.com", .A, 1);

    // Add answers
    try builder.addARecord("example.com", 3600, [_]u8{ 93, 184, 216, 34 });
    try builder.addAAAARecord("example.com", 3600, [_]u8{
        0x20, 0x01, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    });

    // Response header
    const header = dns.Header{
        .id = 1234,
        .rd = 1,
        .tc = 0,
        .aa = 1,   // Authoritative
        .opcode = 0,
        .qr = 1,   // Response
        .rcode = 0,
        .z = 0,
        .ra = 1,   // Recursion available
        .qdcount = 1,
        .ancount = 2,
        .nscount = 0,
        .arcount = 0,
    };

    return builder.finish(header);
}
```

### Parsing DNS Packets

```zig
const std = @import("std");
const dns = @import("dns");

pub fn parseDnsPacket(buffer: []const u8) !void {
    // Parse the header
    const message = try dns.Message.parse(buffer);

    std.debug.print("DNS ID: {d}\n", .{message.header.id});
    std.debug.print("Is Response: {d}\n", .{message.header.qr});
    std.debug.print("Questions: {d}\n", .{message.header.qdcount});
    std.debug.print("Answers: {d}\n", .{message.header.ancount});

    // Parse questions and records
    var parser = dns.MessageParser.init(buffer);

    // Read exactly qdcount questions
    var questions = parser.questions(message.header.qdcount);
    while (try questions.next()) |q| {
        std.debug.print("Question: Type={d}, Class={d}\n", .{
            @intFromEnum(q.qtype),
            q.qclass,
        });
    }

    // Then read the answer section explicitly
    var answers = parser.resourceRecords(message.header.ancount);
    while (try answers.next()) |rr| {
        // Parse RDATA based on type. Domain names inside RDATA come back as
        // self-contained `Name` values that resolve compression pointers.
        const rdata = try parser.parseRData(rr);

        switch (rdata) {
            .A => |ip| {
                std.debug.print("A: {d}.{d}.{d}.{d}\n", .{
                    ip[0], ip[1], ip[2], ip[3]
                });
            },
            .AAAA => |ip| {
                std.debug.print("AAAA: {x:0>2}:{x:0>2}:...\n", .{ip[0], ip[1]});
            },
            .MX => |mx| {
                var name_buf: [255]u8 = undefined;
                std.debug.print("MX: pref={d}, exchange={s}\n", .{
                    mx.preference, try mx.exchange.str(&name_buf),
                });
            },
            else => {},
        }
    }
}
```

For server paths that only need a later section, you can skip the parts you already know how to account for:

```zig
var parser = dns.MessageParser.init(buffer);

// Skip the question section and jump directly to answers
try parser.skipQuestions(message.header.qdcount);

var answers = parser.resourceRecords(message.header.ancount);
while (try answers.next()) |rr| {
    _ = rr;
}
```

To inspect EDNS without consuming the parser cursor, scan the additional section directly.
`findEdns` is the **strict** entry point: one pass, full RFC 6891 §6.1.1 checking, and it
returns the OPT record together with its ECS and Cookie options:

```zig
var parser = dns.MessageParser.init(buffer);
try parser.skipQuestions(message.header.qdcount);
try parser.skipResourceRecords(message.header.ancount + message.header.nscount);

if (try parser.findEdns(message.header.arcount)) |edns| {
    std.debug.print("EDNS UDP size: {d}\n", .{edns.opt.class});
    if (edns.ecs) |ecs| std.debug.print("ECS family={d} prefix={d}\n", .{ ecs.family, ecs.source_prefix });
    if (edns.cookie) |c| std.debug.print("cookie server bytes: {d}\n", .{c.server.len});

    // Header fields (version / extended RCODE / DO) decode from the OPT record itself:
    const params = try dns.Edns.fromOpt(edns.opt);
    std.debug.print("DO={}\n", .{params.dnssec_ok});
}
```

`findEdns` returns an error when the message violates RFC 6891:

| Condition | Error |
|-----------|-------|
| More than one OPT record (§6.1.1) | `error.MultipleOptRecords` |
| OPT owner name is not the root | `error.MalformedName` |
| OPT RDATA options do not exactly tile the RDATA | `error.InvalidRData` |

`findOptRecord`, `findECS` and `findCookie` are **fast paths**: they stop at the first OPT
and skip those checks. Use them only on input you have already validated; for untrusted
packets prefer `findEdns`. The builder enforces the same rule from the other side — a
second `addOptRecord` / `addOptRecordRaw` returns `error.MultipleOptRecords`, so a
Builder-only server cannot emit a packet its own strict parse path would FORMERR.

OPT is not an ordinary record: `parseRData` on type 41 returns `error.UseEdns`, so a
generic "walk every additional RR" loop gets an unambiguous signal to branch to the
EDNS helpers instead of a vague `InvalidRData`.

### Server-side building: TCP framing, truncation, auto-counting

`finish()` fills the header's section counts automatically from what you added, so
they can never desync:

```zig
var builder = dns.Message.Builder.init(&buffer);
try builder.addQuestion("example.com", .A, 1);      // -> qdcount
try builder.addARecord("example.com", 60, .{1,2,3,4}); // -> ancount
builder.setSection(.authority);
try builder.addNSRecord("example.com", 60, "ns1.example.com"); // -> nscount

// header counts are overwritten with the real values (pass 0s)
const packet = builder.finish(header);
// (use finishRaw(header) if you want to set the counts yourself)
```

Every `add*` call is atomic: if it returns `error.BufferTooSmall` the builder is
rolled back to before the call, so you can stop and send a truncated response:

```zig
var truncated = false;
for (answers) |a| {
    builder.addARecord(a.name, a.ttl, a.ip) catch |e| switch (e) {
        error.BufferTooSmall => { truncated = true; break; },
        else => return e,
    };
}
header.tc = if (truncated) 1 else 0;
const packet = builder.finish(header);
```

Attach EDNS(0) — an OPT record goes in the additional section, and `addOptRecord`
places it there and counts it automatically:

```zig
try builder.addQuestion("example.com", .A, 1);
try builder.addOptRecord(.{
    .udp_payload_size = 1232,
    .dnssec_ok = true,
    .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0,
              .address = &[_]u8{ 192, 0, 2 } }, // 192.0.2.0/24
});
// use addOptRecordRaw(udp_size, ttl, options) to supply your own option bytes
```

For DNS-over-TCP, use the 2-byte length-prefix framing helpers:

```zig
var builder = try dns.Message.Builder.initTcp(&buffer);
try builder.addQuestion("example.com", .A, 1);
const frame = try builder.finishTcp(header); // 2-byte length prefix + message

// parsing side strips the prefix:
const message = try dns.Message.parseTcp(frame);
```

### Handling DNS Names

```zig
const dns = @import("dns");

// Parse domain name using iterator
var iter = dns.NameIterator{ .buffer = packet, .pos = 12 };

while (try iter.next()) |label| {
    std.debug.print("Label: {s}\n", .{label});
}
```

`NameIterator` walks the labels of **one** name — it is not a packet cursor. To walk a
whole message (names, then type/class, then the next record), use `MessageParser`, which
validates every name as it goes.

`iter.pos` tracks the name's **wire-form** end: for a compressed name that is the two
bytes of the first pointer, not the end of whatever the pointer targets. It therefore
matches where `MessageParser` leaves off, but reaching for it means doing by hand what
`MessageParser` already does for you.

All name reading enforces RFC 1035 §2.3.4 identically across the library — labels ≤ 63
bytes, and ≤ 255 bytes for the whole name *including* the root octet. A name the parser
accepts can always be re-encoded by the builder.

### Supported Record Types

| Type | Description | Builder Method |
|------|-------------|----------------|
| A | IPv4 address | `addARecord()` |
| AAAA | IPv6 address | `addAAAARecord()` |
| CNAME | Canonical name | `addCNAMERecord()` |
| MX | Mail exchange | `addMXRecord()` |
| NS | Name server | `addNSRecord()` |
| PTR | Pointer record | `addPTRRecord()` |
| TXT | Text record | `addTXTRecord()` |
| SOA | Start of authority | `addSOARecord()` |
| SRV | Service record | `addSRVRecord()` |
| CAA | Certification authority authorization (RFC 8659) | `addCAARecord()` |
| SVCB | Service binding (RFC 9460) | `addSVCBRecord()` |
| HTTPS | HTTPS service binding (RFC 9460) | `addHTTPSRecord()` |
| DNSKEY | DNS public key (RFC 4034) | `addDNSKEYRecord()` |
| DS | Delegation signer (RFC 4034) | `addDSRecord()` |
| RRSIG | Resource record signature (RFC 4034) | `addRRSIGRecord()` |
| NSEC | Next secure record (RFC 4034) | `addNSECRecord()` |
| NSEC3 | Hashed NSEC (RFC 5155) | `addNSEC3Record()` |
| NSEC3PARAM | NSEC3 parameters (RFC 5155) | `addNSEC3PARAMRecord()` |
| OPT | EDNS(0) | `addOptRecord()` |

Unknown or non-IN-class records can be served verbatim via `addRecordRaw()` (RFC 3597).

### Error Handling

The library provides detailed error types:

```zig
pub const Error = error{
    PacketTooShort,
    MalformedName,
    MalformedECS,
    MalformedCookie,
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
    MultipleOptRecords, // RFC 6891 §6.1.1: more than one OPT record → FORMERR
    InvalidRecordOrder, // Builder misuse: section regression, or question after an RR
};
```

## Examples

The library includes several examples:

```bash
# Build all examples
zig build examples

# Run individual examples
zig build example-packet    # Basic packet construction
zig build example-name      # Domain name handling
zig build example-response  # DNS response creation
zig build example-records   # All record types
```

## Building and Testing

```bash
# Run tests
zig build test

# Run specific test file
zig test src/header.zig
zig test src/parser.zig
zig test src/rdata.zig
```

## API Reference

### Core Types

- `Header` - DNS message header (12 bytes, packed struct)
- `Message` - Message parsing wrapper
- `Message.Builder` - Zero-allocation packet builder
- `MessageParser` - Incremental packet parser
- `NameIterator` - Zero-copy label iterator for a single name (not a packet cursor)
- `ResourceData` - Union type for all RDATA formats

### Enums

- `Type` - DNS resource record types (A, AAAA, NS, etc.)
- `Class` - DNS classes (IN, CH, etc.)
- `Opcode` - DNS operation codes
- `Rcode` - DNS response codes
- `OptionCode` - EDNS option codes (ECS, etc.)

## Performance

Zero-copy design means:
- **No heap allocation** during parsing or encoding
- **Minimal memory overhead** - only stores positions and lengths
- **Cache-friendly** - sequential access to packet buffer

Indicative figures from `zig build bench` (ReleaseFast, single dev machine — run it
on your own hardware, these are not authoritative):

| Operation | ~ns/op |
|-----------|-------:|
| Decode header | 0.9 |
| Parse one question (uncompressed name) | 2 |
| Skip question + parse one answer (compressed owner) | 10 |
| Iterate a qname (labels) | 4 |
| Compare a compressed name | 18 |
| Format a compressed name (dotted) | 16 |
| Find OPT / `findEdns` (OPT+ECS+Cookie, one scan) | 17–19 |
| Encode a query | 33 |
| Encode a response with compression | 72 |

Skipping a name now **follows and validates** its compression pointers instead of
accepting "+2 bytes and done", so a fast-path server that only skips rejects the same
malformed names that `formatNameAt` does. That costs roughly 7 ns per compressed name
compared to the old unchecked skip; names without pointers are unaffected.

On server fast paths prefer comparing names (`nameEqualsAt`) or scanning EDNS with the
single-pass `findEdns` over formatting names to strings.

### DPDK / eBPF integration

The library never allocates and operates entirely over a caller-provided `[]const u8`,
so it drops straight into packet-processing fast paths:

```zig
// DNS payload lives at some offset inside an mbuf / packet buffer — pass the slice, no copy:
const message = try dns.Message.parse(pkt[udp_payload_off..]);
// or for DNS-over-TCP framing: dns.Message.parseTcp(pkt[tcp_payload_off..]);

// Burst model: just loop over the RX burst; each parse is independent and allocation-free.
for (burst[0..n]) |pkt| { handle(try dns.Message.parse(dnsPayload(pkt))); }
```

Note: parsing assumes a single **contiguous** buffer. For multi-segment (scatter-gather)
mbuf chains, linearize the DNS payload first (nearly all DNS messages fit one segment).
Native segmented-buffer parsing is a possible future direction.

## Limitations

- DNSSEC **validation** is not implemented: the library parses and builds DNSSEC records (DNSKEY, DS, RRSIG, NSEC(3)) and computes key tags, but does not verify signatures or chains of trust
- EDNS0 signing not implemented (RFC 4035)
- TSIG not supported

## Contributing

Contributions are welcome! The codebase follows Zig style guidelines.

## License

[MIT License](LICENSE)
