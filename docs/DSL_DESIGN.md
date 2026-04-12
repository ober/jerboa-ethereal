# DSL Design: Protocol Definition Language

**Version 0.1** — Phase 1-2 specification

This document defines the Jerboa s-expression DSL for declaring network protocols. Instead of imperative C dissectors, protocols are declarative data structures that the dissection engine interprets.

---

## Philosophy

1. **Declarative, not imperative**: Describe *what* the packet structure is, not *how* to parse it
2. **Immutable**: Protocol definitions are read-only; dissection produces new packet records
3. **Composable**: Protocols nest; dissectors chain automatically
4. **Strongly typed**: All fields have types; type checking at definition and runtime
5. **Human-readable**: DSL mirrors RFC specifications; easy to audit against standards

---

## Core Concepts

### Protocol Definition
A protocol is a named structure with a sequence of typed fields:

```scheme
(defprotocol protocol-name
  :description "RFC 792: ICMP"
  :link-type ethernet        ;; (optional) what wraps this protocol
  :next-protocol-field type  ;; (optional) field that determines payload protocol
  :fields [
    (field-name type :key value ...)
    ...
  ])
```

### Field Specification
Each field has:
- **name** (required): kebab-case identifier
- **type** (required): base type (u8, u16be, bytes, etc.)
- **size** (optional): static size or expression (size of field in bytes)
- **mask** (optional): bitfield mask (for extracting bits from a byte)
- **shift** (optional): bit shift (for multi-bit fields)
- **formatter** (optional): function to convert raw value to display string
- **values** (optional): value→name mapping (for enums)
- **conditional** (optional): expression to determine if field is present
- **description** (optional): docstring (appears in packet display)

---

## Types

### Primitive Types

| Type | Size | Description | Example |
|------|------|-------------|---------|
| `u8` | 1 byte | Unsigned 8-bit integer | TTL field in IPv4 |
| `u16be` | 2 bytes | Big-endian 16-bit unsigned | UDP port |
| `u16le` | 2 bytes | Little-endian 16-bit unsigned | Windows NETBIOS |
| `u32be` | 4 bytes | Big-endian 32-bit unsigned | IPv4 address, TCP seqno |
| `u32le` | 4 bytes | Little-endian 32-bit unsigned | Windows registry |
| `u64be` | 8 bytes | Big-endian 64-bit unsigned | Timestamps, counters |
| `u64le` | 8 bytes | Little-endian 64-bit unsigned | Windows FILETIME |
| `bytes` | Variable | Raw byte sequence | Payload, options |
| `string` | Variable | Text string | HTTP headers, DNS names |
| `bitfield` | Partial | Bits extracted from a byte | TCP flags, IPv4 flags |

### Composite Types

| Type | Description | Example |
|------|-------------|---------|
| `(nested protocol-name)` | Another protocol (recursive) | IPv4 options field |
| `(repeat count type)` | Array of fields | IPv4 options array |
| `(choice (pred → type) ...)` | Conditional field types | Variable-length encoding |

---

## Field Examples

### Simple Integer Fields

```scheme
;; IPv4 version (4 bits in upper nibble of first byte)
(version u8 :mask #xF0 :shift 4
  :description "IP version number")

;; IPv4 TTL (simple 8-bit field)
(ttl u8 :description "Time to live")

;; IPv4 source address (32-bit big-endian)
(src-ip u32be :formatter format-ipv4
  :description "Source IP address")

;; UDP length (16-bit big-endian)
(length u16be :description "UDP length")
```

### Enum Fields (Value Mappings)

```scheme
;; IPv4 protocol field with named values
(protocol u8 :values protocol-names
  :description "Protocol number")

;; Define the value mapping elsewhere:
(defval-string protocol-names
  (1 "ICMP")
  (6 "TCP")
  (17 "UDP")
  (41 "IPv6")
  (255 "Unknown"))
```

### Bitfield Fields

```scheme
;; TCP flags: each flag is a single bit
;; Byte layout: [URG ACK PSH RST SYN FIN]
(tcp-flags u8
  :fields [
    (urg :mask 0x20)
    (ack :mask 0x10)
    (psh :mask 0x08)
    (rst :mask 0x04)
    (syn :mask 0x02)
    (fin :mask 0x01)
  ]
  :description "TCP control flags")

;; Or use bitmask helper:
(flags u8
  :mask #xFC :shift 2
  :description "IPv4 flags (DF, MF, Reserved)")
```

### Variable-Length Fields

```scheme
;; Payload: rest of buffer after known headers
(payload bytes :size (- buffer-length offset)
  :description "Packet payload")

;; IPv4 options: size depends on IHL field
(options bytes :size (* (- ihl 5) 4)
  :conditional (> ihl 5)
  :description "IPv4 options (variable length)")

;; DNS name (variable-length, using custom parser)
(query-name string
  :size (dns-name-size buffer offset)  ;; custom function
  :parser parse-dns-name               ;; custom parser
  :description "DNS query name")
```

### Nested Protocols

```scheme
;; Ethernet payload is determined by EtherType
(payload (nested (payload-protocol-at buffer type))
  :description "Encapsulated protocol")

;; TCP options field (contains multiple option structures)
(options (repeat (- data-offset 20) tcp-option)
  :conditional (> data-offset 20)
  :description "TCP options")
```

---

## Complete Example: IPv4 Header

```scheme
(defprotocol ipv4
  :description "RFC 791: Internet Protocol Version 4"
  :link-type ethernet
  :next-protocol-field protocol
  :fields [
    ;; First byte: version and IHL
    (version u8 :mask #xF0 :shift 4
      :description "IP version (4 for IPv4)")
    (ihl u8 :mask #x0F :shift 0
      :description "Internet header length (32-bit words)")

    ;; DSCP and ECN
    (dscp u8 :mask #xFC :shift 2
      :description "Differentiated services code point")
    (ecn u8 :mask #x03 :shift 0
      :description "Explicit congestion notification")

    ;; Packet size and identification
    (total-length u16be
      :description "Total length including header and payload")
    (identification u16be
      :description "Packet identification for reassembly")

    ;; Flags and fragment offset
    (flags u8 :mask #xE0 :shift 5
      :values ipv4-flags
      :description "Flags: DF (don't fragment), MF (more fragments)")
    (fragment-offset u16be :mask #x1FFF
      :description "Fragment offset in 8-byte units")

    ;; Time to live and protocol
    (ttl u8
      :description "Time to live (hop limit)")
    (protocol u8 :values protocol-names
      :description "Protocol number (TCP=6, UDP=17, etc.)")

    ;; Checksum
    (header-checksum u16be
      :description "IPv4 header checksum")

    ;; Addresses
    (src-ip u32be :formatter format-ipv4
      :description "Source IP address")
    (dst-ip u32be :formatter format-ipv4
      :description "Destination IP address")

    ;; Options (variable length, only if IHL > 5)
    (options bytes :size (* (- ihl 5) 4)
      :conditional (> ihl 5)
      :description "Options (variable length)")

    ;; Payload determined by protocol field
    (payload (nested (next-protocol-at buffer protocol))
      :description "Encapsulated protocol")
  ])

;; Value name mappings
(defval-string ipv4-flags
  (0x4 "DF")  ;; Don't Fragment
  (0x2 "MF")) ;; More Fragments

(defval-string protocol-names
  (1 "ICMP")
  (6 "TCP")
  (17 "UDP")
  (41 "IPv6"))
```

---

## Complete Example: TCP Header

```scheme
(defprotocol tcp
  :description "RFC 793: Transmission Control Protocol"
  :link-type ipv4
  :next-protocol-field (nested protocol-from-port dst-port)
  :fields [
    ;; Source and destination ports
    (src-port u16be :formatter format-port
      :description "Source port")
    (dst-port u16be :formatter format-port
      :description "Destination port")

    ;; Sequence and acknowledgment numbers
    (seq-number u32be
      :description "Sequence number")
    (ack-number u32be
      :description "Acknowledgment number")

    ;; Data offset and flags
    (data-offset u8 :mask #xF0 :shift 4
      :description "Data offset (32-bit words)")
    (reserved u8 :mask #x0F
      :description "Reserved (must be 0)")
    (tcp-flags u8 :values tcp-flag-names
      :description "Control flags (SYN, ACK, FIN, etc.)")

    ;; Window and checksums
    (window-size u16be
      :description "Receive window size")
    (checksum u16be
      :description "TCP checksum")
    (urgent-pointer u16be
      :description "Urgent data pointer (if URG flag set)")

    ;; Options (variable length, only if data-offset > 5)
    (options bytes :size (* (- data-offset 5) 4)
      :conditional (> data-offset 5)
      :description "TCP options")

    ;; Payload is application layer
    (payload bytes :size (- buffer-length (* data-offset 4))
      :description "Application data")
  ])

(defval-string tcp-flag-names
  (0x20 "URG")
  (0x10 "ACK")
  (0x08 "PSH")
  (0x04 "RST")
  (0x02 "SYN")
  (0x01 "FIN"))
```

---

## Built-in Formatters

The DSL provides standard formatters for common types:

| Formatter | Input | Output | Example |
|-----------|-------|--------|---------|
| `format-ipv4` | u32be | `a.b.c.d` | `192.168.1.1` |
| `format-ipv6` | u128be | IPv6 notation | `2001:db8::1` |
| `format-mac` | u48be | `xx:xx:xx:xx:xx:xx` | `00:11:22:33:44:55` |
| `format-port` | u16be | service name or number | `ssh` (for 22) or `12345` |
| `format-hex` | bytes | hex string | `0xdeadbeef` |
| `format-boolean` | u8 with mask | `yes`/`no` | `yes` |
| `format-ipv4-mask` | u8 | CIDR notation | `/24` |
| `format-time` | u32be | RFC 3339 | `2026-04-12T10:00:00Z` |

Custom formatters:

```scheme
;; Define a custom formatter
(def (format-port port)
  (let ([service (lookup-port port)])
    (if service
        (str service " (" port ")")
        (str port))))

;; Use it in a field
(src-port u16be :formatter format-port)
```

---

## Conditional Fields

Fields can appear conditionally based on other fields:

```scheme
;; IPv4 options appear only if IHL > 5
(options bytes :size (* (- ihl 5) 4)
  :conditional (> ihl 5))

;; TCP urgent pointer only if URG flag is set
(urgent-pointer u16be
  :conditional (flag-set? tcp-flags 0x20))

;; DNS answer records appear if answer count > 0
(answers (repeat answer-count dns-answer)
  :conditional (> answer-count 0))
```

The `:conditional` expression is evaluated in a context where:
- Previously parsed fields are in scope
- `buffer` is the raw packet buffer
- `offset` is the current byte offset

---

## Nested Protocols

Protocols can encapsulate other protocols:

```scheme
;; Automatic nesting based on protocol field
(defprotocol ethernet
  ...
  :next-protocol-field type  ;; EtherType field determines payload
  :fields [
    (dest-mac u48be)
    (src-mac u48be)
    (type u16be :values ethertype-names)
    ;; Payload protocol determined by type field
    (payload (nested (ethertype-to-protocol type)))
  ])

;; Helper function to determine payload protocol
(def (ethertype-to-protocol type)
  (match type
    (0x0800 'ipv4)
    (0x0806 'arp)
    (0x86DD 'ipv6)
    (_ 'unknown)))
```

---

## Size Expressions

Field sizes can be computed from context:

```scheme
;; Static size
(field u32be)  ;; size is 4

;; Dynamic size from prior field
(options bytes :size (- ihl 5) * 4)  ;; size depends on IHL

;; Size from buffer
(payload bytes :size (- (buffer-length buffer) offset))

;; Complex expressions
(data bytes :size (- total-length 20 (* (- ihl 5) 4)))
```

Size expressions are evaluated with access to:
- All previously parsed fields
- `buffer-length` — total packet size
- `offset` — current byte position

---

## Type Validation & Safety

All field access is bounds-checked. If a size expression or field read goes past the buffer:
- **Raise an error** (don't truncate silently)
- Error message includes offset, size, buffer length
- Packet marked as malformed (included in output for debugging)

```scheme
;; Example error:
;; ERROR: Bounds violation reading ipv4.options at offset 20, size 4, buffer length 21
;;   (IHL=6 implies options size 4, but only 1 byte available)
```

---

## Registration & Discovery

Protocols are registered for automatic detection:

```scheme
;; Register IPv4 as the handler for EtherType 0x0800
(register-dissector-handler 'ipv4 'ethertype 0x0800)

;; Register DNS as the handler for UDP port 53
(register-dissector-handler 'dns 'udp-port 53)

;; Register HTTPS as the handler for TCP port 443
(register-dissector-handler 'tls 'tcp-port 443)
```

The dissection engine uses these registrations to automatically chain protocols:

```
Ethernet → (type=0x0800) → IPv4 → (protocol=6) → TCP → (dst-port=443) → TLS
```

---

## Example: Complete DNS Protocol

```scheme
(defprotocol dns
  :description "RFC 1035: Domain Name System"
  :link-type udp-port
  :fields [
    ;; Header
    (transaction-id u16be
      :description "Transaction ID")
    (flags u16be :values dns-flags
      :description "Flags and codes")
    (questions u16be
      :description "Number of questions")
    (answer-rrs u16be
      :description "Number of answer RRs")
    (authority-rrs u16be
      :description "Number of authority RRs")
    (additional-rrs u16be
      :description "Number of additional RRs")

    ;; Questions section
    (question-records (repeat questions dns-question)
      :conditional (> questions 0)
      :description "Questions")

    ;; Answers section
    (answer-records (repeat answer-rrs dns-answer)
      :conditional (> answer-rrs 0)
      :description "Answer RRs")

    ;; Authority section
    (authority-records (repeat authority-rrs dns-answer)
      :conditional (> authority-rrs 0)
      :description "Authority RRs")

    ;; Additional section
    (additional-records (repeat additional-rrs dns-answer)
      :conditional (> additional-rrs 0)
      :description "Additional RRs")
  ])

;; DNS question record (variable-length name, then type and class)
(defprotocol dns-question
  :fields [
    (name string :parser parse-dns-name
      :description "Domain name (compressed)")
    (type u16be :values dns-type-names
      :description "Query type (A, AAAA, CNAME, etc.)")
    (class u16be :values dns-class-names
      :description "Query class (IN=1)")
  ])

;; DNS resource record
(defprotocol dns-answer
  :fields [
    (name string :parser parse-dns-name
      :description "Domain name (compressed)")
    (type u16be :values dns-type-names
      :description "Answer type")
    (class u16be :values dns-class-names
      :description "Answer class")
    (ttl u32be
      :description "Time to live (seconds)")
    (rdlen u16be
      :description "Resource data length")
    (rdata bytes :size rdlen
      :description "Resource data")
  ])

(defval-string dns-flags ...)
(defval-string dns-type-names ...)
(defval-string dns-class-names ...)
```

---

## Compiler & Runtime Semantics

The DSL compiler produces:
1. **Protocol metadata**: static description of structure
2. **Parser function**: `(parse-protocol buf offset)` → packet-t
3. **Field extractors**: `(get-field packet field-name)` → value

Parser pseudo-code for a protocol:

```scheme
(define (parse-protocol buf offset)
  (let* ([fields-hash (make-hash-table)]
         [offset 0])
    ;; For each field in protocol definition:
    (for-each (lambda (field-spec)
                (when (eval-condition field-spec offset)
                  (let* ([size (eval-size field-spec offset)]
                         [raw-value (read-bytes buf offset size)]
                         [parsed-value (parse-value raw-value field-spec)]
                         [formatted (format-value parsed-value field-spec)])
                    (hash-put! fields-hash (field-name field-spec) formatted)
                    (set! offset (+ offset size)))))
              (protocol-fields protocol-def))
    ;; Build and return packet
    (make-packet protocol-def fields-hash buf offset)))
```

---

## Iteration & Evolution

**v0.1 features** (Phase 1-2):
- Simple fields (u8, u16be, u32be, bytes, string)
- Conditional fields (`:conditional` expression)
- Nested protocols
- Value name mappings
- Built-in formatters

**v0.2 features** (Phase 3, to be designed):
- Bitfield groups (multiple bits in one byte)
- Repeat/array fields
- Custom parsers for complex encodings
- Checksum validation
- Validation expressions (`:validate`)

**v0.3 features** (Future):
- DSL embedding in REPL (define protocols at runtime)
- Plug-in formatter system
- Custom type definitions
- Macro support for protocol families

---

## Next Steps

1. Implement DSL parser (`lib/dsl/parser.ss`)
2. Implement type system (`lib/dsl/types.ss`)
3. Implement built-in formatters (`lib/dsl/formatters.ss`)
4. Define core protocols: Ethernet, IPv4, UDP, TCP
5. Implement dissection engine to use compiled DSL

See `PLAN.md` Phase 2-3 for detailed implementation steps.
