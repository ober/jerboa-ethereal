# Converting Wireshark Dissectors to jerboa-ethereal DSL

## Overview

The Wireshark project contains ~1,700 protocol dissectors in `/epan/dissectors/packet-*.c`. We can systematically extract and convert the most important ones to our Jerboa DSL format.

## Where Wireshark Stores Protocol Definitions

**Main dissector location**: `~/mine/wireshark/epan/dissectors/`

**Key files we can mine**:
- `packet-icmp.c` - ICMP (RFC 792)
- `packet-arp.c` - Address Resolution Protocol (RFC 826)
- `packet-dns.c` - Domain Name System (RFC 1035)
- `packet-ipv6.c` - IPv6 (RFC 2460)
- `packet-http.c` - HTTP/1.1 (RFC 7230-7235)
- `packet-tls.c` - TLS/SSL (RFC 5246, 8446)
- `packet-dhcp.c` - DHCP (RFC 2131)
- `packet-icmpv6.c` - ICMPv6 (RFC 4443)
- `packet-igmp.c` - IGMP (RFC 3376)
- `packet-ntp.c` - NTP (RFC 5905)
- `packet-snmp.c` - SNMP (RFC 3416)
- Plus hundreds more organized by category

## How Wireshark Dissectors Are Structured

### Example: ARP Field Definition from Wireshark

```c
// From packet-arp.c
static hf_register_info hf[] = {
  { &hf_arp_hw_type,
    { "Hardware type", "arp.hw.type", FT_UINT16, BASE_DEC, ...} },
  { &hf_arp_proto_type,
    { "Protocol type", "arp.proto.type", FT_UINT16, BASE_HEX, ...} },
  { &hf_arp_hw_size,
    { "Hardware size", "arp.hw.size", FT_UINT8, BASE_DEC, ...} },
  { &hf_arp_proto_size,
    { "Protocol size", "arp.proto.size", FT_UINT8, BASE_DEC, ...} },
  { &hf_arp_opcode,
    { "Operation", "arp.opcode", FT_UINT16, BASE_DEC, ...} },
};
```

### Conversion Pattern: Wireshark → jerboa-ethereal DSL

**Wireshark Field Definition:**
```c
proto_tree_add_item(tree, hf_field_name, tvb, offset, length, ENC_BIG_ENDIAN);
```

**Converts to jerboa-ethereal DSL:**
```scheme
(field-name u16be
  :formatter format-hex
  :desc "Human readable description")
```

## Field Type Mapping

| Wireshark Type | Size | Byte Order | Jerboa Type | Notes |
|---|---|---|---|---|
| FT_UINT8 | 1 byte | N/A | u8 | Direct |
| FT_UINT16 + ENC_BIG_ENDIAN | 2 bytes | BE | u16be | Network byte order |
| FT_UINT16 + ENC_LITTLE_ENDIAN | 2 bytes | LE | u16le | Host byte order |
| FT_UINT32 + ENC_BIG_ENDIAN | 4 bytes | BE | u32be | Common |
| FT_UINT32 + ENC_LITTLE_ENDIAN | 4 bytes | LE | u32le | Rare |
| FT_UINT64 + ENC_BIG_ENDIAN | 8 bytes | BE | u64be | Very rare |
| FT_IPv4 | 4 bytes | BE | u32be + fmt-ipv4 | Use special formatter |
| FT_IPv6 | 16 bytes | BE | bytes (special) | 128-bit address |
| FT_ETHER (MAC) | 6 bytes | BE | u48be + fmt-mac | MAC address |
| FT_BYTES | Variable | N/A | bytes | Length parameter |
| FT_STRING | Variable | N/A | string | Length parameter |
| FT_BOOLEAN (masked field) | 1 byte with mask | N/A | u8 + :mask | Bitfield |

## Conversion Workflow

### Step 1: Analyze the Wireshark Dissector
```bash
# Find dissector file
grep -l "proto_register_protocol" ~/mine/wireshark/epan/dissectors/packet-PROTOCOL.c

# Extract field definitions
grep -A 3 "hf_register_info" ~/mine/wireshark/epan/dissectors/packet-PROTOCOL.c | head -50

# Find dissection function to understand field order
grep -A 5 "dissect_PROTOCOL" ~/mine/wireshark/epan/dissectors/packet-PROTOCOL.c | head -100
```

### Step 2: Create Protocol Definition in DSL

**Example: Converting ICMP from Wireshark**

Wireshark structure (packet-icmp.c):
```c
proto_tree_add_item(tree, hf_icmp_type, tvb, 0, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(tree, hf_icmp_code, tvb, 1, 1, ENC_BIG_ENDIAN);
proto_tree_add_item(tree, hf_icmp_checksum, tvb, 2, 2, ENC_BIG_ENDIAN);
proto_tree_add_item(tree, hf_icmp_unused, tvb, 4, 4, ENC_BIG_ENDIAN);
```

**Converts to our DSL and generated code:**

```scheme
(defprotocol icmp
  "RFC 792: Internet Control Message Protocol"
  ((type u8
     :formatter format-icmp-type
     :desc "Message type (Echo, Unreachable, etc.)")
   (code u8
     :formatter format-icmp-code
     :desc "Message code (varies by type)")
   (checksum u16be
     :formatter format-hex
     :desc "Internet checksum")
   (rest-of-header u32be
     :desc "Rest of header (varies by message type)")))
```

### Step 3: Create the Jerboa Dissector

```scheme
(import (jerboa prelude)
        (lib dissector protocol))

(def (dissect-icmp buffer)
  "Parse ICMP message from bytevector
   Returns (ok fields) or (err message)"
  
  (try
    (let* ((type-res (read-u8 buffer 0))
           (type-val (unwrap type-res))
           
           (code-res (read-u8 buffer 1))
           (code-val (unwrap code-res))
           
           (checksum-res (read-u16be buffer 2))
           (checksum (unwrap checksum-res))
           
           (rest-res (read-u32be buffer 4))
           (rest (unwrap rest-res)))
      
      (ok `((type . ((raw . ,type-val)
                    (formatted . ,(format-icmp-type type-val))))
            (code . ((raw . ,code-val)
                    (formatted . ,(format-icmp-code type-val code-val))))
            (checksum . ((raw . ,checksum)
                        (formatted . ,(fmt-hex checksum))))
            (rest . ,rest))))
    
    (catch (e)
      (err (str "ICMP parse error: " e)))))

(def (format-icmp-type type)
  (case type
    ((0) "Echo Reply")
    ((3) "Destination Unreachable")
    ((5) "Redirect")
    ((8) "Echo Request")
    ((11) "Time Exceeded")
    ((12) "Parameter Problem")
    (else (str "Unknown (" type ")"))))
```

## Priority Protocol Conversion Queue

### Tier 1: Core Infrastructure (Do First - 1 session)
These are fundamental to the networking stack. Convert these to have a solid foundation.

1. **ICMPv6** (packet-icmpv6.c) - ~300 lines
   - Like ICMP but for IPv6
   - Neighbor discovery, router solicitation
   - Why: Complements IPv6, enables IPv6 testing

2. **IGMP** (packet-igmp.c) - ~200 lines
   - Multicast group membership
   - Version 3 support important
   - Why: Enables multicast testing

### Tier 2: Application Protocols (Do Second - 1-2 sessions)
Higher-layer protocols that are commonly analyzed.

3. **DNS** (packet-dns.c) - ~2000 lines total, but core is ~200
   - Query/Response format
   - Compressed domain names
   - Resource record types
   - Why: Most useful for understanding traffic

4. **DHCP** (packet-dhcp.c) - ~300 lines
   - Dynamic host configuration
   - Bootstrap protocol
   - Why: Common in network traces

5. **NTP** (packet-ntp.c) - ~200 lines
   - Network time protocol
   - Simple fixed structure
   - Why: Often seen in real traffic

### Tier 3: Security Protocols (Do Third - 2-3 sessions)
Important for security analysis.

6. **TLS/SSL** (packet-tls.c) - ~5000 lines total, core handshake ~500
   - Record layer format
   - Handshake messages
   - Alert protocol
   - Why: Essential for HTTPS analysis

7. **HTTP** (packet-http.c) - ~1000 lines
   - Request/response format
   - Header parsing
   - Status codes
   - Why: Very common protocol

### Tier 4: Optional Protocols (Do Later - Ongoing)
Additional protocols as needed.

- SMTP (packet-smtp.c) - Email
- SSH (packet-ssh.c) - Secure shell
- SNMP (packet-snmp.c) - Network management
- FTP (packet-ftp.c) - File transfer
- Syslog (packet-syslog.c) - Logging protocol
- RADIUS (packet-radius.c) - Authentication

## Tools for Analyzing Wireshark Dissectors

### 1. Extract Field Definitions
```bash
# Get all field definitions for a protocol
grep "hf_register_info" ~/mine/wireshark/epan/dissectors/packet-dns.c -A 200 | head -100

# Find just the field names
grep '{ &hf_' ~/mine/wireshark/epan/dissectors/packet-dns.c | awk -F'"' '{print $2}' | sort -u

# Get field offsets and sizes from dissect function
grep "proto_tree_add_item" ~/mine/wireshark/epan/dissectors/packet-dns.c | head -30
```

### 2. Understand Protocol Structure
```bash
# Look at the main dissection function
grep -A 100 "^dissect_dns\|^dissect_icmp" ~/mine/wireshark/epan/dissectors/packet-dns.c | head -50

# Find constants and mappings
grep -E "^#define|static.*val64\|static.*value_string" ~/mine/wireshark/epan/dissectors/packet-dns.c
```

### 3. Automated Parsing (Future)
We could write a script to:
- Parse C files with regex
- Extract proto_tree_add_item() calls
- Generate DSL templates
- Create stub Jerboa dissectors

## Example: Full ICMP Conversion

### Step 1: Analyze Wireshark packet-icmp.c

From Wireshark (simplified):
```c
// Offset 0: Type (1 byte)
proto_tree_add_item(tree, hf_icmp_type, tvb, 0, 1, ENC_BIG_ENDIAN);

// Offset 1: Code (1 byte)
proto_tree_add_item(tree, hf_icmp_code, tvb, 1, 1, ENC_BIG_ENDIAN);

// Offset 2-3: Checksum (2 bytes)
proto_tree_add_item(tree, hf_icmp_checksum, tvb, 2, 2, ENC_BIG_ENDIAN);

// Type-specific fields from offset 4+
if (type == ICMP_ECHO || type == ICMP_ECHOREPLY) {
  proto_tree_add_item(tree, hf_icmp_ident, tvb, 4, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_icmp_seq, tvb, 6, 2, ENC_BIG_ENDIAN);
}
```

### Step 2: Create DSL

```scheme
(defprotocol icmp
  "RFC 792: Internet Control Message Protocol"
  ((type u8
     :formatter format-icmp-type
     :desc "Message type")
   (code u8
     :formatter format-icmp-code
     :desc "Message code")
   (checksum u16be
     :formatter format-hex
     :desc "Internet checksum")
   (identifier u16be
     :conditional (or (= type 8) (= type 0))
     :desc "Identifier (Echo/Echo Reply)")
   (sequence u16be
     :conditional (or (= type 8) (= type 0))
     :desc "Sequence number (Echo/Echo Reply)")
   (rest-of-header u32be
     :conditional (not (or (= type 8) (= type 0)))
     :desc "Rest of header (type-specific)")))
```

### Step 3: Generate Jerboa Dissector

(Already shown above in conversion workflow section)

### Step 4: Test with Real ICMP Packets

```bash
# Ping creates ICMP Echo packets
ping -c 1 192.168.1.1

# Capture with tcpdump
tcpdump -w icmp.pcap icmp

# Later: read with our dissector
./ethereal-musl icmp.pcap | head -20
```

## Commands to Get Started

```bash
# Count protocols
ls ~/mine/wireshark/epan/dissectors/packet-*.c | wc -l

# Find interesting protocols
ls ~/mine/wireshark/epan/dissectors/packet-{icmp,arp,dns,ntp,dhcp,http,tls}.c

# Extract field definitions for DNS
grep "hf_register_info" ~/mine/wireshark/epan/dissectors/packet-dns.c -A 300 | head -200

# Find protocol constants
grep "^#define" ~/mine/wireshark/epan/dissectors/packet-icmp.c | head -20

# Search for a specific field
grep -n "proto_tree_add_item.*hf_icmp_type" ~/mine/wireshark/epan/dissectors/packet-icmp.c
```

## Implementation Strategy

### Week 1 (Tier 1: Core)
- [ ] ICMP dissector (already have)
- [ ] ICMPv6 dissector (~2 hours)
- [ ] IGMP dissector (~2 hours)
- [ ] Register all three in pipeline

### Week 2 (Tier 2: Application)
- [ ] DNS dissector with compressed names (~4 hours)
- [ ] DHCP dissector (~3 hours)
- [ ] NTP dissector (~2 hours)

### Week 3+ (Tier 3+)
- [ ] TLS/SSL record layer (~6 hours, complex)
- [ ] HTTP request/response (~4 hours)
- [ ] Others as needed

## Tools We Can Build

1. **Wireshark → DSL Converter Script** (Jerboa)
   - Parse packet-*.c files
   - Extract hf_register_info structures
   - Generate DSL templates
   - Generate stub dissectors

2. **Protocol Matrix**
   - CSV/table of all 1700 protocols
   - Size, complexity, RFC number
   - Priority ranking for conversion

3. **Automated Dissector Generator**
   - Input: Wireshark field definitions
   - Output: Safe Jerboa dissector
   - Handles: endianness, formatting, validation

## Next Session TODO

1. Pick a Tier 1 protocol from Wireshark (ICMPv6 or IGMP)
2. Extract its field definitions
3. Convert to DSL format
4. Create Jerboa dissector
5. Test with sample packets
6. Register with pipeline

Would you like to start with ICMPv6, IGMP, or move directly to Tier 2 protocols like DNS?
