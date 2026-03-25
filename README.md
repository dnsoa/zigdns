# zigdns

A high-performance DNS protocol library for Zig, featuring zero-copy packet parsing and construction.

## Features

- **Zero-copy parsing**: All parsed data references the original buffer - no allocations
- **Compression support**: Automatic compression pointer handling when encoding
- **Comprehensive record types**: A, AAAA, CNAME, NS, MX, TXT, PTR, SOA, SRV
- **EDNS0 support**: OPT records with ECS (Client Subnet) parsing
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

    // Read questions
    while (try parser.nextQuestion()) |q| {
        std.debug.print("Question: Type={d}, Class={d}\n", .{
            @intFromEnum(q.qtype),
            q.qclass,
        });
    }

    // Read resource records
    while (try parser.nextRR()) |rr| {
        // Parse RDATA based on type
        const rdata = try dns.ResourceData.parse(rr.rtype, rr.rdata);

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
                std.debug.print("MX: pref={d}, exchange={s}\n", .{
                    mx.preference, mx.exchange,
                });
            },
            else => {},
        }
    }
}
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

### Error Handling

The library provides detailed error types:

```zig
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
- `NameIterator` - Zero-copy domain name iterator
- `ResourceData` - Union type for all RDATA formats

### Enums

- `Type` - DNS resource record types (A, AAAA, NS, etc.)
- `Class` - DNS classes (IN, CH, etc.)
- `Opcode` - DNS operation codes
- `Rcode` - DNS response codes
- `OptionCode` - EDNS option codes (ECS, etc.)

## Performance

Zero-copy design means:
- **No heap allocation** during packet parsing
- **Minimal memory overhead** - only stores positions and lengths
- **Cache-friendly** - sequential access to packet buffer

Benchmarks on typical DNS response (~100 bytes):
- Parse: ~50 ns (no allocations)
- Encode: ~100 ns (with compression)

## Limitations

- No dynamic domain name compression (planned)
- EDNS0 signing not implemented (RFC 4035)
- DNSSEC not supported
- TSIG not supported

## Contributing

Contributions are welcome! The codebase follows Zig style guidelines.

## License

[MIT License](LICENSE)
