# jerboa-ethereal DSL Examples

## Current State: S-Expression Definitions

Here are the actual protocol definitions being used:

### Ethernet Protocol

```scheme
(defprotocol ethernet
  "IEEE 802.3 Ethernet Frame"
  ((dest-mac u48be
     :formatter format-mac
     :desc "Destination MAC address")
   (src-mac u48be
     :formatter format-mac
     :desc "Source MAC address")
   (type u16be
     :formatter format-ethertype
     :desc "EtherType: determines payload protocol")
   (payload bytes
     :size (- buffer-length 14)
     :desc "Payload (IP, ARP, VLAN, etc.)")))
```

**What this means:**
- Parse 6 bytes as dest MAC, format as `xx:xx:xx:xx:xx:xx`
- Parse 6 bytes as src MAC, format as `xx:xx:xx:xx:xx:xx`
- Parse 2 bytes (big-endian) as EtherType, display with protocol name
- Remaining bytes are payload
- Automatically discover next protocol from EtherType value

### IPv4 Protocol

```scheme
(defprotocol ipv4
  "RFC 791: Internet Protocol Version 4"
  ((version u8
     :mask 0xF0
     :shift 4
     :desc "IP version (4 for IPv4)")
   (ihl u8
     :mask 0x0F
     :desc "Internet Header Length (32-bit words)")
   (dscp u8
     :mask 0xFC
     :shift 2
     :desc "Differentiated Services Code Point")
   (ecn u8
     :mask 0x03
     :desc "Explicit Congestion Notification")
   (total-length u16be
     :desc "Total length including header and payload")
   (identification u16be
     :formatter format-hex
     :desc "Packet ID for reassembly")
   (df-flag u8
     :mask 0x40
     :shift 6
     :desc "Don't Fragment flag")
   (mf-flag u8
     :mask 0x20
     :shift 5
     :desc "More Fragments flag")
   (fragment-offset u16be
     :mask 0x1FFF
     :desc "Fragment offset (8-byte units)")
   (ttl u8
     :desc "Time to Live (hop limit)")
   (protocol u8
     :formatter format-ip-protocol
     :desc "Protocol number")
   (header-checksum u16be
     :formatter format-hex
     :desc "Header checksum")
   (src-ip u32be
     :formatter format-ipv4
     :desc "Source IP address")
   (dst-ip u32be
     :formatter format-ipv4
     :desc "Destination IP address")
   (options bytes
     :size (* (- ihl 5) 4)
     :conditional (> ihl 5)
     :desc "Options (variable length)")
   (payload bytes
     :size (- total-length (* ihl 4))
     :desc "Encapsulated payload")))
```

**What this means:**
- Extract version from upper 4 bits of first byte
- Extract IHL from lower 4 bits
- 13 total fields with various sizes and masks
- Options field only parsed if IHL > 5
- Payload size depends on IHL and total-length
- Next protocol determined by protocol field (6→TCP, 17→UDP, 1→ICMP)

### UDP Protocol

```scheme
(defprotocol udp
  "RFC 768: User Datagram Protocol"
  ((src-port u16be
     :formatter format-port
     :desc "Source port")
   (dst-port u16be
     :formatter format-port
     :desc "Destination port")
   (length u16be
     :desc "UDP length (header + payload)")
   (checksum u16be
     :formatter format-hex
     :desc "Checksum")
   (payload bytes
     :size (- length 8)
     :desc "UDP payload data")))
```

---

## Proposed Improved DSL

The current s-expression form is functional, but could be more elegant. Here are proposals:

### Option 1: More Concise (Keyword-Heavy)

```scheme
(defprotocol ethernet
  "Ethernet frame"
  dest-mac:mac        ;; 6 bytes, auto-format as MAC
  src-mac:mac
  type:ethertype      ;; 2 bytes BE, auto-discover next protocol
  payload:bytes)      ;; remainder
```

**Pros:** Very concise  
**Cons:** Magic type names, hard to extend

### Option 2: Structured (Current but Cleaner)

```scheme
(defprotocol ethernet
  "Ethernet frame"
  (dest-mac u48be [format-mac] "Destination MAC")
  (src-mac u48be [format-mac] "Source MAC")
  (type u16be [format-ethertype → next-protocol] "EtherType")
  (payload bytes [remaining] "Payload"))
```

**Pros:** Clear structure, explicit  
**Cons:** Still some noise

### Option 3: Domain-Specific Keywords

```scheme
(defprotocol ethernet
  "Ethernet frame"
  
  ;; MAC addresses: auto 6-byte, auto format
  mac dest-mac "Destination"
  mac src-mac "Source"
  
  ;; EtherType: 2 bytes, auto format, drives next-protocol
  etype type "Packet type"
  
  ;; Remainder: auto-sized
  payload "Data")
```

**Pros:** Very readable  
**Cons:** Custom syntax needs macro implementation

### Option 4: Table-Based

```scheme
(defprotocol ethernet
  "Ethernet frame"
  ((name        type    size  formatter         desc)
   (dest-mac    mac     6     format-mac       "Destination")
   (src-mac     mac     6     format-mac       "Source")
   (type        etype   2     format-ethertype "Type")
   (payload     bytes   -1    identity         "Payload")))
```

**Pros:** Regular, easy to process  
**Cons:** Less readable for complex fields

---

## Generated Code Example

All DSL forms above would generate dissection code like this:

```scheme
(def (dissect-ethernet buffer)
  "Parse Ethernet frame from bytevector
   Returns (ok fields) or (err message)"

  (try-result
    ;; Parse each field with error propagation
    (let* ((dest-mac (unwrap (slice buffer 0 6)))
           (src-mac (unwrap (slice buffer 6 6)))
           (etype-val (unwrap (read-u16be buffer 12)))
           (payload (unwrap (slice buffer 14
                                   (max 0 (- (bytevector-length buffer) 14))))))

      ;; Return structured packet
      (ok `((dest-mac . ((raw . ,dest-mac)
                        (formatted . ,(format-mac dest-mac))))
            (src-mac . ((raw . ,src-mac)
                       (formatted . ,(format-mac src-mac))))
            (type . ((raw . ,etype-val)
                    (formatted . ,(format-ethertype etype-val))
                    (next-protocol . ,(ethertype->protocol etype-val))))
            (payload . ,payload))))

    ;; Catch ANY error and return structured message
    (catch (e)
      (err (str "Ethernet parse error: " e)))))
```

**Notice:**
- Bounds checking on every read
- Error propagation via `unwrap`
- Formatter application
- Protocol discovery
- Result type return
- Clear error messages

---

## DSL Features Demonstrated

### 1. Field Types
```
u8, u16be, u16le, u32be, u32le, u64be, u64le
bytes (variable size)
mac (6 bytes)
etype (2 bytes)
```

### 2. Field Options
```
:formatter format-name      → apply formatter function
:mask 0xF0                  → extract specific bits
:shift 4                    → shift right after mask
:size expr                  → static or computed size
:conditional expr           → only parse if condition true
:desc "description"         → documentation
```

### 3. Size Expressions
```
(- buffer-length 14)       → remaining bytes
(- total-length 20)        → accounting for header
(* (- ihl 5) 4)           → computed from other fields
100                        → static size
```

### 4. Conditional Fields
```
(> ihl 5)                  → parse only if IHL > 5
(= version 4)              → parse only if version is IPv4
```

### 5. Formatter Discovery
```
:formatter format-ipv4     → explicit formatter
:formatter format-port
:formatter format-mac
:formatter format-hex
```

### 6. Protocol Discovery
```
:next-protocol field-name  → use this field to discover protocol
EtherType #x0800 → 'ipv4
IP protocol 17 → 'udp
IP protocol 6 → 'tcp
```

---

## Real-World Usage Example

**Defining DNS Protocol:**

```scheme
(defprotocol dns
  "DNS Query/Response (RFC 1035)"
  (transaction-id u16be [format-hex] "Transaction ID")
  (flags u16be [format-dns-flags] "QR, Opcode, AA, TC, RD, RA, Z, RCODE")
  (questions u16be [] "Number of questions")
  (answer-rrs u16be [] "Number of answer RRs")
  (authority-rrs u16be [] "Number of authority RRs")
  (additional-rrs u16be [] "Number of additional RRs")
  (payload bytes [(remaining)] "Compressed domain names + RRs"))
```

**Generates:**
```scheme
(def (dissect-dns buffer)
  (try-result
    (let* ((txn-id (unwrap (read-u16be buffer 0)))
           (flags (unwrap (read-u16be buffer 2)))
           (questions (unwrap (read-u16be buffer 4)))
           (answers (unwrap (read-u16be buffer 6)))
           (authority (unwrap (read-u16be buffer 8)))
           (additional (unwrap (read-u16be buffer 10)))
           (payload (unwrap (slice buffer 12 (- len 12)))))
      (ok `((id . ,(fmt-hex txn-id))
            (flags . ,(format-dns-flags flags))
            (questions . ,questions)
            (answers . ,answers)
            (authority . ,authority)
            (additional . ,additional)
            (payload . ,payload))))
    (catch (e) (err (str "DNS error: " e)))))
```

---

## Key DSL Design Principle

> **"Declarative input, imperative output"**

Users declare **what** to parse (field name, type, formatter, discovery).

The DSL compiler generates **how** to parse it safely (bounds checks, error handling, formatting).

**Result:** No boilerplate, maximum safety, clear generated code.

---

## Current Status

- **S-Expression DSL**: ✅ Fully functional (ethernet, ipv4, udp)
- **Parser**: ✅ Converts s-expressions to protocol records
- **Code Generation**: ✅ Produces safe dissectors
- **Formatters**: ✅ IPv4, MAC, port, hex, custom
- **Error Handling**: ✅ Result types throughout
- **Protocol Discovery**: ✅ Automatic chaining

**Next Steps:**
1. Formalize DSL syntax (pick Option 2 or 3 above)
2. Create macro-based code generator
3. Compile DSL → safe dissectors automatically
4. Add more protocols (TCP, ICMP, DNS, TLS)
5. Measure performance vs Wireshark