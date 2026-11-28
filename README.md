# zigdns

A high-performance DNS protocol library for Zig, featuring zero-copy packet parsing and construction.

## Features

- **Zero-copy parsing**: All parsed data references the original buffer - no allocations
- **Compression support**: Automatic compression pointer following on parse; shared-suffix compression on encode
- **Comprehensive record types**: A, AAAA, CNAME, DNAME, NS, MX, TXT, PTR, HINFO, SOA, SRV, SSHFP, TLSA, CAA, SVCB, HTTPS
- **EDNS0 support**: OPT records with ECS (Client Subnet, RFC 7871), DNS Cookies (RFC 7873), 12-bit Extended RCODEs, and generic TLV iteration
- **DNSSEC**: DNSKEY, CDNSKEY, DS, CDS, RRSIG, NSEC, NSEC3, NSEC3PARAM parsing and construction, key tag computation, type bitmaps, canonical ordering (RFC 4034 / 5155 / 7344)
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
zig fetch --save="dns" https://github.com/dnsoa/zigdns/archive/refs/heads/main.tar.gz
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
    var builder = try dns.Message.Builder.init(&buffer);

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
    _ = packet;

    // Now send packet to a DNS server...
}
```

### Creating a DNS Response

```zig
const std = @import("std");
const dns = @import("dns");

pub fn createResponse(buffer: []u8) ![]const u8 {
    var builder = try dns.Message.Builder.init(buffer);

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
            @backingInt(q.qtype),
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
                // Plain ASCII names fit in 253 bytes; worst-case \DDD-escaped wire names need up to 1003 bytes.
                var name_buf: [1004]u8 = undefined;
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

To inspect EDNS and validate section boundaries across the entire message in one call, use `message.findEdns()` (which rejects `OPT` records misplaced in Answer/Authority via `error.MisplacedOptRecord` and trailing bytes past `ARCOUNT` via `error.TrailingBytes`):

```zig
if (try message.findEdns()) |edns| {
    std.debug.print("EDNS effective UDP size: {d}\n", .{edns.effectiveUdpPayloadSize()});
    std.debug.print("Full 12-bit RCODE: {}\n", .{edns.fullRcode(message.header)});
    if (edns.ecs) |ecs| std.debug.print("ECS family={d} prefix={d}\n", .{ ecs.family, ecs.source_prefix });
    if (edns.cookie) |c| std.debug.print("cookie server bytes: {d}\n", .{c.server.len});

    // Iterate all raw EDNS options (including EDE, NSID, Padding, etc.)
    var opt_it = edns.optionsIterator();
    while (try opt_it.next()) |opt| {
        std.debug.print("Option code={d} len={d}\n", .{ @backingInt(opt.code), opt.data.len });
    }
}
```

Or scan and consume the additional section in a single pass with `MessageParser.consumeEdns` (which decodes `edns.params` without a second `Edns.fromOpt` pass and advances `parser.pos` to the end of the additional section; use read-only `parser.findEdns` if you do not want to advance `parser.pos`):

```zig
var parser = dns.MessageParser.init(buffer);
try parser.skipQuestions(message.header.qdcount);
try parser.skipNonAdditionalRecords(@as(usize, message.header.ancount) + message.header.nscount);

if (try parser.consumeEdns(message.header.arcount)) |edns| {
    std.debug.print("DO={}\n", .{edns.params.dnssec_ok});
}
try parser.expectEnd();
```

When walking all four sections with `message.sections()`, `SectionParser` caches the decoded `Edns` during Additional-section traversal (`secs.edns()`) and provides `skipQuestions()` / `skipAnswers()` / `skipAuthorities()` / `skipAdditionals()` so you never need a second pass over the packet.

`findEdns` returns an error when the message violates RFC 6891 or option validation:

| Condition | Error |
|-----------|-------|
| More than one OPT record (§6.1.1) | `error.MultipleOptRecords` |
| A name points into the header | `error.InvalidOffset` |
| OPT owner name is not the root | `error.MalformedName` |
| OPT RDATA options do not exactly tile the RDATA | `error.InvalidRData` |
| Malformed ECS payload, non-zero tail bits beyond `source_prefix` (RFC 7871 §6), or duplicate ECS option (strict library policy) | `error.MalformedECS` |
| Invalid COOKIE length (RFC 7873 §5.2.2; multiple COOKIE options keep the first and ignore the rest per §5.2/§5.3) | `error.MalformedCookie` |

`findOptRecord`, `findECS` and `findCookie` are **fast paths**: they stop at the first OPT
and skip those checks. Use them only on input you have already validated; for untrusted
packets prefer `findEdns`. The builder enforces the same rule from the other side — a
second OPT via `addOptRecord`, `addOptRecordRaw`, or `addRecordRaw(..., 41, ...)` returns
`error.MultipleOptRecords`, so a Builder-only server cannot emit a packet its own strict
parse path would FORMERR.

OPT is not an ordinary record: `parseRData` on type 41 returns `error.UseEdns`, so a
generic "walk every additional RR" loop gets an unambiguous signal to branch to the
EDNS helpers instead of a vague `InvalidRData`.

### Server-side building: TCP framing, truncation, auto-counting

`finish()` fills the header's section counts automatically from what you added, so
they can never desync:

```zig
var builder = try dns.Message.Builder.init(&buffer);
try builder.addQuestion("example.com", .A, 1);      // -> qdcount
try builder.addARecord("example.com", 60, .{1,2,3,4}); // -> ancount
try builder.setSection(.authority);
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

Attach EDNS(0) safely with `setEdns` — it reserves exact trailing space for the `OPT` record without changing the active section, so `OPT` is still emitted in the Additional section even when Answer records hit `error.BufferTooSmall` (`TC=1` truncation per RFC 6891 §7):

```zig
try builder.addQuestion("example.com", .A, 1);
try builder.setEdns(.{
    .udp_payload_size = 1232,
    .dnssec_ok = true,
    .ecs = .{ .family = 1, .source_prefix = 24, .scope_prefix = 0,
              .address = &[_]u8{ 192, 0, 2 } }, // 192.0.2.0/24
});
// Answer / Authority records can still be added normally; finish() appends OPT at the end.
```

`addOptRecord` and `addOptRecordRaw` remain available for writing an `OPT` record into the Additional section immediately. Note that if you have **not** called `try builder.setSection(.additional)` beforehand, `addOptRecord` / `addOptRecordRaw` lock the builder against accidental subsequent `add*Record` calls (returning `error.InvalidRecordOrder` so Answer records are never silently emitted into Additional as `ANCOUNT=0` NODATA); call `try builder.setSection(.additional)` explicitly to unlock when intentionally appending trailing Additional records such as TSIG after `OPT`. When using `setEdns`, call `builder.flushEdns()` before computing a TSIG digest (or write `Type.TSIG` via `addRecordRaw` in `.additional`, which flushes the reserved `OPT` before `TSIG` automatically per RFC 8945 §5.1). You can also echo a parsed query `Question` directly with `try builder.addQuestionFrom(query_msg.buffer, q)`, forward non-ECS/COOKIE EDNS options zero-copy with `edns.preservingOptions()` (or materialize them into a separate buffer via `try edns.withPreservedOptions(&opt_buf)`), and reuse a builder across packets with `try builder.reset(&buffer)`.

For DNS-over-TCP, use the 2-byte length-prefix framing helpers:

```zig
var builder = try dns.Message.Builder.initTcp(&buffer);
try builder.addQuestion("example.com", .A, 1);
const frame = try builder.finishTcp(header); // 2-byte length prefix + message

// parsing side strips the prefix (returns error.MalformedHeader if the 2-byte length is < 12,
// reserving error.PacketTooShort strictly for incomplete TCP stream bytes):
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
accepts can always be re-encoded by the builder:

- **Presentation escaping (RFC 1035 §5.1 / RFC 4343 §2.1)**: `formatDnsName`, `formatDnsNameInMessage`, `Name.str`, and `MessageParser.formatNameAt` escape `.` and `\` inside labels as `\.` / `\\` and control or non-ASCII bytes (`<= 0x20` or `>= 0x7F`) as `\DDD`. Ordinary printable ASCII names remain ≤ 253 bytes, while a worst-case all-escaped 255-octet wire name expands to **1003 bytes** (pass a `[1004]u8` / `[1024]u8` buffer if untrusted binary labels must be formatted without `error.BufferTooSmall`).
- **Backslash escape parsing & compression**: `Message.Builder`, `MessageParser.nameEqualsAt`, and `canonicalCompare` interpret `\` escapes per RFC 1035 §5.1 (`\.`, `\\`, `\DDD` for `000`–`255`). A literal backslash inside a presentation string must therefore be escaped as `\\` (e.g. `"a\\\\b.example.com"`). Because `Builder`'s compression table keys on decoded wire-format label suffixes, names containing `\` escapes (such as RFC 6763 DNS-SD instance names with `\032` or `\.`) participate in both full-name and shared-suffix compression identically to unescaped names; for DNSSEC ordering on parsed records, prefer zero-escape `Name.canonicalCompare`.
- **RDATA name boundaries**: Embedded domain names inside RDATA whose wire encoding overruns `rdlength` fail with `error.InvalidRData` without reading into subsequent records.

Every message-level entry point enforces full DNS message bounds (`12 <= msg.len <= 65535` and `12 <= offset < msg.len`) and rejects compression pointers aimed at the 12-byte header, since no name can start there. That applies uniformly to `MessageParser` (`skipName` / `formatNameAt` / `nameEqualsAt`), `formatDnsNameInMessage`, `NameCursor.initInMessage`, `Name.str()`, `Name.canonicalCompare()`, and names inside RDATA (`parseRData` on CNAME/NS/MX/SOA/SRV). Both `NameCursor` and `NameIterator` are fused: calling `next()` again after `null` returns `null` without advancing `pos`. The generic helpers that take an arbitrary buffer rather than a whole message (`formatDnsName`, `NameIterator`, `NameCursor.init`) default to `pointer_floor = 0`; use `formatDnsNameInMessage`, `NameCursor.initInMessage`, or set `pointer_floor = dns.MESSAGE_POINTER_FLOOR` to opt into full-message bounds.

### Supported Record Types

| Type | Description | Builder Method |
|------|-------------|----------------|
| A | IPv4 address | `addARecord()` |
| AAAA | IPv6 address | `addAAAARecord()` |
| CNAME | Canonical name | `addCNAMERecord()` |
| DNAME | Subtree redirection (RFC 6672) | `addDNAMERecord()` |
| MX | Mail exchange | `addMXRecord()` |
| NS | Name server | `addNSRecord()` |
| PTR | Pointer record | `addPTRRecord()` |
| HINFO | Host information (RFC 1035 / RFC 8482) | `addHINFORecord()` |
| TXT | Text record | `addTXTRecord()` / `addTXTRecordStrings()` |
| SOA | Start of authority | `addSOARecord()` |
| SRV | Service record | `addSRVRecord()` |
| SSHFP | SSH public key fingerprint (RFC 4255) | `addSSHFPRecord()` |
| TLSA | DANE TLS authentication (RFC 6698) | `addTLSARecord()` |
| CAA | Certification authority authorization (RFC 8659) | `addCAARecord()` |
| SVCB | Service binding (RFC 9460) | `addSVCBRecord()` |
| HTTPS | HTTPS service binding (RFC 9460) | `addHTTPSRecord()` |
| DNSKEY | DNS public key (RFC 4034) | `addDNSKEYRecord()` |
| CDNSKEY | Child DNSKEY (RFC 7344) | `addCDNSKEYRecord()` |
| DS | Delegation signer (RFC 4034) | `addDSRecord()` |
| CDS | Child DS (RFC 7344) | `addCDSRecord()` |
| RRSIG | Resource record signature (RFC 4034) | `addRRSIGRecord()` |
| NSEC | Next secure record (RFC 4034) | `addNSECRecord()` |
| NSEC3 | Hashed NSEC (RFC 5155) | `addNSEC3Record()` |
| NSEC3PARAM | NSEC3 parameters (RFC 5155) | `addNSEC3PARAMRecord()` |
| OPT | EDNS(0) | `setEdns()` / `addOptRecord()` |

Unknown or non-IN-class records can be served verbatim via `addRecordRaw()` (RFC 3597).

### Error Handling

The library provides detailed error types:

```zig
pub const Error = error{
    PacketTooShort,
    MalformedHeader,    // TCP frame declares < 12 bytes (cannot form a valid DNS header)
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
    InvalidRecordOrder, // Section order violation: Builder regression/question after RR/implicit OPT lock, or SectionParser out-of-order/unconsumed section
    UseEdns,            // parseRData called on OPT(41): use findEdns / Edns.fromOpt instead
    MisplacedOptRecord, // RFC 6891 §6.1.1: OPT record in Answer or Authority section → FORMERR
    TrailingBytes,      // Unaccounted trailing bytes past the declared section counts → FORMERR
};
```

### Breaking Behavior Notes

- **Forward compression pointers rejected (RFC 1035 §4.1.4)**: Name compression pointers must target a strictly earlier offset (`target < origin`); forward jumps return `error.MalformedName`.
- **`Builder` initial section is `.question`**: Calling `setSection(.answer)` (or `.authority` / `.additional`) before `addQuestion()` now returns `error.InvalidRecordOrder` (writing a non-OPT RR directly on a fresh builder still auto-advances `.question` → `.answer`).
- **Implicit section lock after `addOptRecord` / `addOptRecordRaw`**: When called without a prior `setSection(.additional)`, appending further records afterward (e.g., TSIG via `addRecordRaw`) requires calling `try builder.setSection(.additional)` first to confirm Additional-section intent (or prefer `setEdns()`, which reserves `OPT` at the end without changing the active section).
- **`RData` decoupled from `Type`**: `RData` is now `union(enum)` rather than `union(Type)` so `Type` can define pure QTYPEs and Meta-TYPEs (`ANY`, `AXFR`, `IXFR`, `TSIG`, `TKEY`); match `RData` tags directly rather than coercing `RData` to `Type`.
- **`OPT` internal TLV overrun error**: When an EDNS option's `OPTION-LENGTH` exceeds `OPT.RDLENGTH`, `parseOptOptions` / `parseECS` / `parseCookie` / `Edns.fromOpt` / `findEdns` now return `error.InvalidRData` instead of `error.PacketTooShort` (reserving `PacketTooShort` for truncated packet or TCP-frame buffers).
- **Fused name iterators & full-message offset bounds**: `NameCursor.next()` and `NameIterator.next()` are now fused after returning `null` (subsequent calls return `null` instead of reading past the root octet or returning `error.PacketTooShort`). Full-message name entry points (`formatDnsNameInMessage`, `NameCursor.initInMessage`, `Name.str`, `Name.canonicalCompare`, `MessageParser.formatNameAt` / `nameEqualsAt`, `skipName(..., MESSAGE_POINTER_FLOOR)`) enforce `12 <= msg.len <= 65535` (`PacketTooShort` / `MessageTooLong`) and `12 <= offset < msg.len` (`InvalidOffset`), rejecting offsets inside the 12-byte DNS header.
- **`MessageParser` 64 KiB cap & `< 12B` `expectEnd`**: `MessageParser` now rejects buffers `> 65535` bytes with `error.MessageTooLong` (matching `Message.parse`), and calling `expectEnd()` on a buffer `< 12` bytes returns `error.PacketTooShort` rather than `error.TrailingBytes`.
- **Non-data RR type/class classification (RFC 6895 / RFC 3597 §3)**: `parseRData` / `RData.parse` now return `error.InvalidType` (rather than `error.UnknownType`) for reserved types (`0`, `65535`) and QTYPE / Meta-TYPE numbers (`128..255`, such as `ANY`, `AXFR`, `IXFR`, `TSIG`, `TKEY`), reserving `error.UnknownType` strictly for unmodeled data RR types; `MessageParser.parseRData` also returns `error.InvalidClass` for reserved classes `0` and `65535` alongside `NONE(254)` and `ANY(255)`. `CDS`, `CDNSKEY`, `DNAME`, `HINFO`, `SSHFP`, and `TLSA` are now parsed into typed `RData` variants rather than returning `error.UnknownType`.
- **Strict sender-side `COOKIE` validation & escaped-name compression in `Builder`**: `Builder` OPT encoding (`setEdns`, `updateEdns`, `addOptRecord`, `addOptRecordRaw`, `addRecordRaw(..., 41, ...)`) rejects duplicate `COOKIE` options and malformed trailing `COOKIE` options with `error.MalformedCookie` (RFC 7873 §4 / §5.1). Names containing `\` escapes are now compressed by `Builder` using wire-format suffix matching.

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

- `Header` - DNS message header (`packed struct(u96)`, host-endian `u16` fields; serialize via `Header.decode` / `Header.encode`)
- `Message` - Zero-copy UDP / TCP (`parseTcp`, `parseTcpFrame`) message wrapper with `sections()` and `findEdns()`
- `SectionParser` - Header-bound strict four-section parser with `skip*()` helpers, cached `edns()`, and `expectEnd()`
- `Message.Builder` - Zero-allocation UDP / TCP packet builder (`init`, `initTcp`, `reset`, `setEdns`, `flushEdns`, `addQuestionFrom`)
- `MessageParser` - Low-level incremental packet cursor (`questions`, `resourceRecords`, `consumeEdns`, `findEdns`, `nameEqualsAt`, `formatNameAt`, `parseRData`)
- `Edns` - Unified EDNS(0) parameters for parsing (`fromOpt`, `optionsIterator`) and building (`setEdns`, `addOptRecord`, `preservingOptions`, `withPreservedOptions`)
- `Name`, `NameCursor`, `NameIterator` - Zero-copy wire name reference, unified pointer-following cursor, and label iterator
- `RData` (`ResourceData`) - Tagged union of typed RDATA payloads (`TxtData`, `HinfoData`, `CaaData`, `SvcbData`, `SshfpData`, `TlsaData`, `DnskeyData`, `DsData`, `RrsigData`, `NsecData`, `Nsec3Data`, `Nsec3ParamData`, `TypeBitmap`)
- `OptOptions`, `OptOption`, `OptOptionIterator`, `ECSData`, `CookieData` - EDNS option types and iterators

### Enums & Helpers

- `Type`, `Class`, `Opcode`, `Rcode`, `ExtendedRcode`, `OptionCode`, `SvcParamKey`, `Section`, `Error`
- `formatDnsName`, `formatDnsNameInMessage`, `decodePresentationName`, `skipName`, `validateMessageOffset`
- `canonicalCompare`, `canonicalCompareWire`, `keyTag`, `serialCompare`, `validateSvcParams`, `validateTypeBitmap`, `parseOptOptions`, `validateOptOptionsForEncode`, `parseECS`, `parseCookie`

## Performance

Zero-copy design means:
- **No heap allocation** during parsing or encoding
- **Minimal memory overhead** - only stores positions and lengths
- **Cache-friendly** - sequential access to packet buffer

Indicative figures from `zig build bench` (ReleaseFast, single dev machine — run it
on your own hardware, these are not authoritative):

| Operation | ~ns/op |
|-----------|-------:|
| Decode header | 0.6 |
| Parse one question (uncompressed name) | 4.7 |
| Skip question + parse one answer (compressed owner) | 11 |
| Iterate a qname (labels) | 7 |
| Compare a compressed name (`nameEqualsAt`) | 11 |
| Format a compressed name (dotted) | 17 |
| Find OPT / `findEdns` (OPT+ECS+Cookie, one scan) | 16–25 |
| Encode a query | 13 |
| Encode a response with compression | 89 |

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
