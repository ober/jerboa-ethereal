# Jerboa Packet Dissection System: Comprehensive Implementation Plan

**Project Vision**: Reimplement Wireshark's libepan packet dissectors in Jerboa using a safe, declarative DSL that provides 100% memory safety, high performance name resolution, and leverages Jerboa's unique features (immutability, actor system, structured concurrency, strong typing via ergo).

**Scale**: Wireshark has 1820+ protocol dissectors; this plan prioritizes subset coverage and provides infrastructure for gradual porting.

**Key Constraints**:
- TLS/encrypted traffic: No plaintext dissection possible (acknowledge limitation, provide metadata where possible)
- Backwards compatibility with Wireshark: Not required; design for correctness first
- Performance: Should match or exceed libepan performance through Chez's native compilation and optimizations

---

## Phase 1: Foundation & Architecture (2-3 weeks)

### Goal
Establish the Jerboa project structure, understand Jerboa's strengths relative to C dissectors, design the safe DSL, and implement core infrastructure.

### 1.1 Project Setup
- [ ] **Create Jerboa project structure** under `~/projects/jerboa-dissector`
  - Use `jerboa_project_template` to create initial skeleton (pick `library` template)
  - Create directories: `lib/dissector/`, `lib/pcap/`, `lib/name-resolver/`, `lib/search/`, `lib/dsl/`
  - Create `dissectors/` directory for Jerboa DSL protocol definitions (not Scheme code, but data files or embedded Scheme)

- [ ] **Document current work** in ~/mine/wireshark
  - Inventory what "Fournier" contributed: which dissectors, what patterns, any custom tools
  - Preserve insights that inform the new architecture

- [ ] **Set up version control & CI**
  - Initialize git with `.gitignore` for compiled artifacts
  - Add pre-commit hooks for syntax checking (use `jerboa_verify`)
  - Add Makefile targets: `build`, `test`, `bench`, `dissector-check`

### 1.2 Jerboa Language & Feature Audit
**Goal**: Verify Jerboa's capabilities relative to C, identify advantages, plan safe wrappers.

- [ ] **Use `jerboa_module_exports` to inventory stdlib**
  - Check `(std text)` for string manipulation (needed for parsing)
  - Check `(std regex)` for pattern matching
  - Check `(std crypto digest)` for checksums/integrity validation
  - Check `(std db)` for IP address caching
  - Check `(std sort)` for efficient field ordering
  - Check `(std async)` for concurrent name resolution
  - Document which stdlib modules are available for dissector runtime

- [ ] **Evaluate Jerboa's typing via ergo**
  - Test `(: expr pred?)` cast syntax
  - Understand how to express network field types (u8, u16be, u32be, etc.) as predicates
  - Plan type-safe field extraction (compile-time checks where possible, runtime bounds checks)

- [ ] **Evaluate Jerboa's actor system** `(std actor)`
  - Test actor message dispatch
  - Plan architecture for concurrent DNS resolution and cache management
  - Consider actor-per-protocol or shared actor pool for dissection

- [ ] **Understand Jerboa's resource safety**
  - Study `unwind-protect` and `with-resource` patterns
  - Plan safe buffer handling (avoid TVB-like escape-hatches)
  - Design guarantees: panic on bounds violation, never silent truncation

### 1.3 Dissector Analysis & Abstraction Design
**Goal**: Extract the essential pattern from 1820 C dissectors, design the DSL that captures it safely.

- [ ] **Collect dissector patterns**
  - Analyze 20-30 representative dissectors from different domains:
    - Simple: `packet-arp.c`, `packet-ip.c`
    - Complex: `packet-tcp.c`, `packet-http.c`
    - Nested: `packet-dns.c`, `packet-dhcp.c`
    - Binary: `packet-bluetooth.c`
  - Document recurring patterns:
    - Header-footer structure (fixed offset, known size)
    - Variable-length fields (length-delimited, sentinel-terminated)
    - Nested protocols (encapsulation, dissector chains)
    - Field types: integers (u8/u16/u32/u64, big/little endian), strings, bytes, bitmasks
    - Conditional fields (depends on flags or length)
    - Checksums and validation
    - Value name lookups (protocol numbers, error codes, enum fields)

- [ ] **Design the Jerboa Dissector DSL**
  - Represent each dissector as a **protocol definition** (Scheme data structure)
  - Define protocol as a sequence of **fields**, each with:
    - `name`: identifier for the field (kebab-case)
    - `type`: base type (u8, u16be, u32le, bytes, string, nested, bitfield)
    - `size`: static size OR dynamic (function of buffer length or prior field)
    - `parser`: optional custom parser function (for complex fields)
    - `formatter`: function to convert raw value to human-readable string
    - `mask`: for bitfield extraction (u8-field with mask 0x0F)
    - `endianness`: big-endian (network order), little-endian, or native
    - `description`: docstring
  - Support **nested protocols**: field can refer to another protocol definition (encapsulation)
  - Support **conditional fields**: list of (predicate . field-spec) pairs
  - Example structure (Jerboa s-expression):
    ```scheme
    (defprotocol ip-v4
      :description "IPv4 Header"
      :fields [
        (version    u8   :mask #xFF :shift 4 :desc "IP version")
        (ihl        u8   :mask #x0F :shift 0 :desc "Internet header length (32-bit words)")
        (dscp       u8   :mask #xFC :desc "Differentiated services")
        (ecn        u8   :mask #x03 :desc "Explicit congestion notification")
        (total-len  u16be :desc "Total length including header")
        (id         u16be :desc "Identification")
        (flags      u8   :mask #xE0 :desc "DF=0x40, MF=0x20")
        (offset     u16be :mask #x1FFF :desc "Fragment offset")
        (ttl        u8   :desc "Time to live")
        (protocol   u8   :desc "Protocol number" :values protocol-names)
        (checksum   u16be :desc "Header checksum")
        (src-ip     u32be :formatter format-ipv4 :desc "Source IP")
        (dst-ip     u32be :formatter format-ipv4 :desc "Destination IP")
        ;; Options only if IHL > 5:
        (options    bytes :size (* (- ihl 5) 4) :conditional (> ihl 5) :desc "Options")
      ])
    ```
  - Define primitive type predicates: `u8?`, `u16be?`, `u32le?`, etc.
  - Support **value name mappings**:
    ```scheme
    (defval-string protocol-names
      (6 "TCP")
      (17 "UDP")
      (...)
    )
    ```

- [ ] **Design parser combinator infra** (if not already in stdlib)
  - Use `(std text)` or roll lightweight byte-level parser combinators
  - Define `(read-u8 buf pos)`, `(read-u16be buf pos)`, etc.
  - Bounds checking built-in: raise on read past buffer end

### 1.4 Core Data Structures (Jerboa)
**Goal**: Implement the runtime representation of packets and fields.

- [ ] **Define packet record type**
  ```scheme
  (defrecord packet
    (protocol-name string?)    ;; e.g., "ethernet", "ip-v4"
    (raw-bytes bytevector?)    ;; original bytes from pcap
    (fields (hash-table?))     ;; parsed fields: {name -> value}
    (tree-view list?)          ;; nested structure for display
    (parent packet?)           ;; for encapsulated protocols
    (children (list-of? packet?)) ;; payload protocols
    (metadata hash-table?))    ;; timestamp, captured length, etc.
  ```

- [ ] **Define field value record**
  ```scheme
  (defrecord field-value
    (name string?)             ;; "src-ip", "dst-port"
    (raw-value (or bytevector? integer? string?)) ;; raw extracted bytes/ints
    (formatted-value string?)  ;; human-readable: "192.168.1.1"
    (type symbol?)             ;; u32be, ipv4-addr, etc.
    (description string?))
  ```

- [ ] **Implement safe buffer abstraction** (`(jerboa buffer)`)
  - Similar to TVB but immutable and Jerboa-native
  - `(make-buffer bytes)` → read-only buffer
  - `(read-u8 buf pos)` → raise if out of bounds
  - `(read-bytes buf start len)` → slice, bounds-checked
  - `(buffer-length buf)` → total size
  - NEVER truncate silently

---

## Phase 2: Dissector DSL & Protocol Definitions (2-3 weeks)

### Goal
Implement the DSL compiler and a library of protocol definitions that can be loaded and composed.

### 2.1 DSL Parser & Validator
**Goal**: Parse Jerboa protocol definitions and emit executable dissector functions.

- [ ] **Implement `(jerboa dsl parser)` module**
  - `(parse-protocol-def sexpr)` → protocol-t record
  - Validate field specs: each field has required keys (name, type), optional keys (formatter, etc.)
  - Resolve forward references (nested protocols)
  - Compile conditional field expressions to closures
  - Detect missing imports for custom formatters

- [ ] **Implement type system for field types**
  - `u8`, `u16be`, `u16le`, `u32be`, `u32le`, `u64be`, `u64le`
  - `bytes` with fixed or variable size
  - `string` with encoding (utf-8, ascii, etc.)
  - `nested` (another protocol)
  - `bitfield` (masked extraction from byte)
  - Custom types via `(define-type name parser formatter)`

- [ ] **Implement formatter registry**
  - `(register-formatter type-name f)` where f: raw-value → string
  - Pre-built formatters:
    - `format-ipv4`: u32be → "a.b.c.d"
    - `format-ipv6`: u128be → standard notation
    - `format-mac`: u48be → "xx:xx:xx:xx:xx:xx"
    - `format-port`: u16be → "ssh" if 22, else number
    - `format-hex`: bytes → "0x..." hex string
    - `format-boolean`: u8 with mask → "yes"/"no"
    - Allow custom formatters per protocol

### 2.2 Protocol Definition Library
**Goal**: Port key Wireshark dissectors to Jerboa DSL.

**Strategy**: Start with foundational protocols and build upward.

- [ ] **Layer 2 (Link)**
  - Ethernet: `packet-ethernet.c` (frame type, src/dst MAC, payload)
  - ARP: `packet-arp.c` (simple, self-contained)
  - VLAN: 802.1Q (tagged frames)

- [ ] **Layer 3 (Network)**
  - IPv4: `packet-ip.c` (version, IHL, flags, addresses, options)
  - IPv6: `packet-ipv6.c` (flow label, addresses, extension headers)
  - ICMP: `packet-icmp.c` (type, code, checksum)

- [ ] **Layer 4 (Transport)**
  - TCP: `packet-tcp.c` (flags, sequence numbers, options, payload)
  - UDP: `packet-udp.c` (ports, length, checksum)

- [ ] **Layer 7 (Application)**
  - DNS: `packet-dns.c` (questions, answers, nested name compression)
  - HTTP: `packet-http.c` (text-based, variable length, method/status)
  - DHCP: `packet-dhcp.c` (options with type-length-value encoding)

Each protocol definition file:
```scheme
(import (jerboa prelude))
(import (jerboa dsl parser))

(define ethernet-protocol
  (defprotocol ethernet
    :description "IEEE 802.3 Ethernet Frame"
    :fields [
      (dest-mac   u48be :formatter format-mac :desc "Destination MAC")
      (src-mac    u48be :formatter format-mac :desc "Source MAC")
      (type       u16be :values ethertype-names :desc "EtherType")
      (payload    bytes :size (- buffer-length 14) :desc "Payload")
    ]))

;; Make it discoverable
(export ethernet-protocol)
```

---

## Phase 3: Dissection Runtime Engine (2-3 weeks)

### Goal
Implement the core dissection pipeline: buffer parsing, field extraction, tree building, and composition.

### 3.1 Dissection Pipeline
**Goal**: Given a buffer and protocol definition, extract all fields and build a tree.

- [ ] **Implement `(jerboa dissector engine)` module**
  - `(dissect buffer protocol-def)` → packet-t record
  - Algorithm:
    1. Initialize offset = 0, fields-hash = {}
    2. For each field in protocol-def:
       - Evaluate size expression (if dynamic)
       - If conditional, check condition against already-extracted fields
       - If true, call field parser at offset
       - Extract raw bytes/value
       - Apply formatter to get display value
       - Store in fields-hash
       - Increment offset
    3. Check for truncation (offset < buffer-length → add warning)
    4. Return packet-t with fields-hash

- [ ] **Implement field parsers**
  - `(parse-u8 buf pos)` → u8
  - `(parse-u16be buf pos)` → u16
  - `(parse-bytes buf pos len)` → bytevector
  - `(parse-string buf pos len encoding)` → string
  - `(parse-nested buf pos protocol-def)` → packet-t (recursive)
  - `(parse-bitfield buf pos mask shift)` → u8
  - All parsers bounds-check and raise on out-of-range access

- [ ] **Implement tree builder**
  - `(build-packet-tree packet-def fields-hash)` → tree-view (nested s-exp)
  - Supports hierarchical display: protocol → fields → nested protocols
  - Example output:
    ```
    (ethernet
      (dest-mac "00:11:22:33:44:55")
      (src-mac "aa:bb:cc:dd:ee:ff")
      (type 2048 "IPv4")
      (payload
        (ipv4
          (version 4)
          (ihl 5)
          (ttl 64)
          (src-ip "192.168.1.1")
          (dst-ip "10.0.0.1")
          (protocol 6 "TCP")
          (payload
            (tcp
              (src-port 12345)
              (dst-port 80)
              ...
            )
          )
        )
      )
    )
    ```

### 3.2 Protocol Discovery & Dispatch
**Goal**: Automatic protocol identification and chaining.

- [ ] **Implement protocol registry**
  - `(register-protocol protocol-def name payload-type-fn)`
  - `payload-type-fn` inspects fields to determine next protocol
  - Example: ethernet payload-type-fn reads `type` field, returns protocol name
  - `(register-dissector-handler ethertype-value protocol-name)`

- [ ] **Implement recursive dissection**
  - After dissecting a protocol, check for payload field (typically last field or named "payload")
  - Determine next protocol via payload-type lookup
  - Recursively dissect nested packets
  - Build packet tree with parent-child links
  - Handle unknown/unimplemented protocols: keep as raw bytes

### 3.3 Performance Optimization
**Goal**: Ensure dissection is fast enough for real-time pcap processing.

- [ ] **Use Chez's native compilation**
  - All dissectors compile to native code
  - Profile bottlenecks with `jerboa_profile`
  - Consider caching compiled protocol definitions

- [ ] **Lazy field extraction**
  - Option: parse only requested fields (for filtering)
  - Full dissection for display, lazy for search

---

## Phase 4: Wireshark → Jerboa Converter (3-4 weeks)

### Goal
Automatically convert Wireshark C dissectors to Jerboa DSL, enabling rapid porting.

**Caveat**: Full automation is infeasible (C is turing-complete, custom parsing logic varies wildly). Target 80% automation with 20% manual review.

### 4.1 Converter Architecture
**Goal**: Parse C dissectors, extract protocol structure, emit Jerboa DSL.

- [ ] **Implement C dissector parser** `(jerboa converter c-parser)`
  - Focus on parsing proto.h patterns (not full C grammar)
  - Extract:
    - `proto_register_protocol()` call → protocol name, short name, filter
    - `hf_register_info hf[]` array → field specs (name, abbrev, type, base, strings, mask)
    - `proto_tree_add_item()` calls in dissect function → field extraction sequence
    - Size expressions: literals, buffer-length, prior field references
  - Use regex or lightweight parser (not full C compiler)

- [ ] **Map C types to Jerboa types**
  - `FT_UINT8` → u8
  - `FT_UINT16 BASE_BIG_ENDIAN` → u16be
  - `FT_UINT32 BASE_LITTLE_ENDIAN` → u32le
  - `FT_BYTES` → bytes
  - `FT_STRING` → string
  - `FT_BOOLEAN` with mask → bitfield
  - Handle `VALS()` (enum strings), `TFS()` (true/false), `RVALS()` (ranges)

- [ ] **Generate Jerboa DSL**
  - `(convert-dissector c-file)` → sexp protocol-def
  - Output Jerboa code to file: `dissectors/{protocol-name}.ss`
  - Add markers for manual review:
    - `;;; REVIEW: custom parsing logic detected`
    - `;;; REVIEW: unknown type conversion`
    - `;;; TODO: implement custom formatter`

- [ ] **Batch convert all 1820 dissectors**
  - `(convert-all-dissectors ~/mine/wireshark/epan/dissectors)`
  - Generate 1820 Jerboa DSL files
  - Report statistics: # auto-converted, # requiring review, # failures

### 4.2 Manual Review & Refinement
**Goal**: Verify conversion quality and implement custom logic where needed.

- [ ] **Implement test framework**
  - For each dissector: capture a real pcap, dissect with Wireshark, dissect with Jerboa
  - Compare output: same field values → pass
  - Flag mismatches for manual review

- [ ] **Create dissector audit spreadsheet**
  - Columns: protocol name, auto-converted, tested, review-notes, completeness %
  - Prioritize completing foundational protocols first

---

## Phase 5: Pcap Tools (2-3 weeks)

### Goal
Build pcap parsing, filtering, search, and editing tools using the dissection engine.

### 5.1 Pcap Parser & Reader
**Goal**: Read pcap and pcapng files, yield packet objects.

- [ ] **Implement `(jerboa pcap reader)` module**
  - `(open-pcap-file path)` → input port with pcap metadata
  - `(read-pcap-packet port)` → (buf, metadata) or #f at EOF
  - Support both libpcap (.pcap) and pcapng (.pcapng) formats
  - Extract: timestamp, captured-length, original-length, link-layer type
  - Use existing Wireshark code as reference for binary format

- [ ] **Implement pcap filter & streaming**
  - `(stream-pcap-packets port)` → stream of packets
  - `(filter-pcap predicate port)` → filtered stream
  - Example: `(filter-pcap (lambda (pkt) (tcp? pkt)) port)`

### 5.2 Dissection Pipeline Integration
**Goal**: Connect pcap reading to dissection.

- [ ] **Implement `(jerboa pcap dissect)` module**
  - `(dissect-pcap-file path)` → stream of dissected packets
  - Infer link-layer protocol from pcap header
  - Automatically detect and chain protocols
  - Handle errors gracefully: truncated packets, unknown protocols

### 5.3 Display & Pretty-Printing
**Goal**: Show dissected packets in a readable format.

- [ ] **Implement packet display**
  - `(display-packet packet)` → formatted text tree
  - Per-protocol pretty-printers
  - Hex dump alongside parsed fields
  - Example output:
    ```
    Frame 1: 64 bytes on wire (512 bits), 64 bytes captured (512 bits)
    Ethernet II: Src 00:11:22:33:44:55, Dst aa:bb:cc:dd:ee:ff (IPv4)
    Internet Protocol Version 4, Src: 192.168.1.1, Dst: 10.0.0.1
      Header Length: 20 bytes
      TTL: 64
      Protocol: TCP (6)
    Transmission Control Protocol, Src Port: 12345, Dst Port: 80, Seq: ..., Ack: ...
      [SEQ/ACK Analysis]
    ```

### 5.4 Search (`ngrep`-like functionality)
**Goal**: Search for strings/patterns in dissected packets.

- [ ] **Implement `(jerboa search)` module**
  - `(search-pcap predicate path)` → stream of matching packets
  - Predicate examples:
    - `(payload-contains "GET")` → search in IP payload
    - `(src-ip "192.168.*")` → pattern match on field
    - `(protocol "HTTP")` → filter by protocol
    - `(field-equals "dst-port" 443)` → exact match
  - Combine with regex: `(payload-regex "\\d{4}")` → search for 4-digit strings

- [ ] **Implement multi-protocol search**
  - Search across nested protocols
  - Example: find all DNS queries with specific domain pattern

### 5.5 Packet Editing
**Goal**: Modify pcap packets (fields or raw bytes).

- [ ] **Implement `(jerboa pcap edit)` module**
  - `(edit-packet packet updates)` → modified packet
  - Updates can be:
    - Field value changes: `(ip.dst-ip "10.0.0.2")`
    - Raw byte edits at offset
  - Automatically recalculate checksums (TCP, UDP, IP)
  - `(write-pcap-file packets path)` → save modified pcap

- [ ] **Implement pcap merge/split**
  - `(merge-pcaps files)` → merged pcap stream
  - `(split-pcap-file path pred)` → multiple files based on predicate

---

## Phase 6: Name Resolution & DNS Caching (2 weeks)

### Goal
High-performance IP↔hostname resolution with async caching, leveraging Jerboa's actors.

### 6.1 Actor-based Name Resolver
**Goal**: Concurrent DNS queries with caching, avoiding bottlenecks.

- [ ] **Implement `(jerboa name-resolver)` module using actors**
  - Actor pool for DNS queries
  - Persistent cache (hash table) → (SQLite via `(std db sqlite)`)
  - Request message: (resolve-hostname ip)
  - Response: (ok hostname) or (err reason)
  - LRU eviction if cache grows too large
  - Configurable: timeout, max concurrent, cache size

- [ ] **Integrate with dissection**
  - Lazy resolution: don't block dissection, annotate field with "pending"
  - Background resolution populates display cache
  - CLI flag: `--resolve` to enable, `--no-resolve` to skip

### 6.2 Common Name Mappings
**Goal**: Pre-compute static mappings (well-known ports, protocols, etc.).

- [ ] **Build static databases**
  - Well-known ports (TCP/UDP): /etc/services
  - IP protocol numbers: IANA registry
  - Ethernet types: IANA registry
  - Store as compiled Jerboa data structures for fast lookup

---

## Phase 7: TLS & Encrypted Traffic Handling (1-2 weeks)

### Goal
Acknowledge TLS limitations, provide metadata extraction, detect patterns.

### 7.1 TLS Metadata Extraction
**Goal**: Parse unencrypted parts of TLS handshake, display client/server info.

- [ ] **Implement TLS 1.2/1.3 dissector**
  - Record layer: version, content type, length
  - Handshake messages: ClientHello, ServerHello, Certificate
  - Extract:
    - TLS version
    - Cipher suite
    - Subject/Issuer from certificate (if sent in plaintext)
    - SNI (Server Name Indication)
  - Keep encrypted payloads as opaque bytes

- [ ] **Document limitations**
  - Note in protocol display: "This connection uses TLS; payload is encrypted"
  - Show available metadata: domain, certificate info, cipher
  - Warn users: no application-layer inspection possible without key

### 7.2 Traffic Statistics & Pattern Detection
**Goal**: Extract statistical information even from encrypted flows.

- [ ] **Implement flow analysis**
  - Packet sizes, inter-arrival times
  - Direction (initiator vs responder)
  - Duration, protocol negotiation phase vs. data transfer
  - Detect common patterns (web browsing, video streaming, VPN)

---

## Phase 8: Validation, Testing & Optimization (3-4 weeks)

### Goal
Ensure correctness, performance parity with Wireshark, and provide comprehensive testing.

### 8.1 Testing Infrastructure
**Goal**: Validate each dissector against real-world pcap files.

- [ ] **Create test corpus**
  - Download representative pcap files from public sources:
    - Wireshark sample files
    - IETF/ICANN official captures
    - Real traffic from lab network (anonymized)
  - Organize by protocol: ethernet/, ip/, dns/, http/, etc.

- [ ] **Implement comparison testing**
  - Dissect same pcap with Wireshark and Jerboa
  - Compare field-by-field results
  - Report pass/fail per protocol
  - Highlight discrepancies (off-by-one, wrong formatter, etc.)

- [ ] **Run jerboa_run_tests** on all dissector modules
  - Unit tests for each protocol definition
  - Edge cases: minimum size, maximum size, truncated packets, malformed data
  - Use `jerboa_howto_run` to verify recipe patterns

### 8.2 Performance Benchmarking
**Goal**: Ensure Jerboa dissection is fast.

- [ ] **Benchmark dissection**
  - `(jerboa_benchmark (dissect-pcap-file "capture.pcap"))`
  - Compare against Wireshark tshark: `tshark -r capture.pcap`
  - Target: within 2x for unoptimized Jerboa (acceptable for non-real-time analysis)

- [ ] **Profile & optimize hotspots**
  - Use `jerboa_profile` to find slow dissectors
  - Consider:
    - Lazy protocol detection (skip dissectors for protocols not in packet)
    - Caching compiled protocol definitions
    - Batch processing for pcap files

### 8.3 Safety & Security Audit
**Goal**: Ensure 100% memory safety and no security regressions.

- [ ] **Run security audit** `jerboa_security_audit` on all code
  - Check for buffer overflows: all buffer access is bounds-checked ✓
  - Check for injection attacks: user input properly escaped
  - Check for integer overflow: arithmetic on field sizes
  - Check for resource leaks: file handles, actors properly closed

- [ ] **Run resource leak check** `jerboa_resource_leak_check`
  - Ensure all pcap file handles use `with-resource` or `unwind-protect`

- [ ] **Fuzz testing**
  - Generate random/mutated pcap files
  - Feed to dissector, ensure no crashes/hangs
  - Capture any edge cases for test corpus

### 8.4 Documentation
**Goal**: Document the architecture and guide contributors.

- [ ] **Write architecture guide** (`docs/ARCHITECTURE.md`)
  - DSL format and examples
  - Dissection engine algorithm
  - Protocol registry design
  - Testing guidelines

- [ ] **Write protocol porting guide** (`docs/PORTING.md`)
  - Step-by-step: converting a Wireshark dissector by hand
  - Automated converter usage
  - Common pitfalls and solutions

- [ ] **API documentation**
  - `jerboa_generate_api_docs` for each module
  - Publish to project README

---

## Phase 9: Continuous Sync with Wireshark (Ongoing)

### Goal
Keep Jerboa dissectors in sync with upstream Wireshark changes.

### 9.1 Monitoring
**Goal**: Track Wireshark updates and alert on changes.

- [ ] **Set up Git watch**
  - Clone official Wireshark repo
  - Watch for commits to `epan/dissectors/`
  - Alert on new protocols or significant changes

- [ ] **Create update CI**
  - Monthly or quarterly: re-run converter on entire dissector suite
  - Auto-generate pull requests for changed dissectors
  - Flag breaking changes (removed fields, type changes)

### 9.2 Incremental Porting
**Goal**: Prioritize and track which dissectors are ported.

- [ ] **Create dissector priority list**
  - Tier 1 (Essential): Ethernet, IP, TCP, UDP, DNS, DHCP
  - Tier 2 (Common): HTTP, HTTPS (TLS), SSH, FTP, SMTP, POP3
  - Tier 3 (VoIP): SIP, RTP, RTCP
  - Tier 4 (Wireless): WiFi, Bluetooth
  - Tier 5+ (Specialized): BGP, OSPF, industrial protocols, etc.

- [ ] **Track porting status** (spreadsheet or issue tracker)
  - Protocol name, priority tier, auto-converted %, tested %, reviewer
  - Monthly sync: identify newly contributed dissectors, schedule porting

---

## Implementation Order & Milestones

### Milestone 1 (Weeks 1-4): Foundation
- Phase 1 complete: project setup, Jerboa audit, DSL design
- Demo: parse and display a simple 3-layer packet (Ethernet → IPv4 → UDP)
- Deliverable: `lib/dissector/engine.ss`, `lib/dissector/dsl.ss`, 3 sample protocols

### Milestone 2 (Weeks 5-9): Runtime & Dissectors
- Phase 2-3 complete: DSL compiler, dissection engine, protocol library
- Add 10 key protocols (Tier 1): Ethernet, ARP, IPv4, IPv6, TCP, UDP, DNS, DHCP, HTTP, ICMP
- Demo: dissect a real pcap with multiple protocols
- Deliverable: `lib/dissector/` with 10+ protocol files, passing tests

### Milestone 3 (Weeks 10-14): Converter & Tools
- Phase 4-5 complete: Wireshark converter, pcap tools
- Auto-convert 100+ dissectors
- Implement pcap reader, filter, search, edit
- Demo: search for strings in pcap, edit packets, save
- Deliverable: `lib/converter/`, `lib/pcap/`, converter output, 100+ auto-converted dissectors

### Milestone 4 (Weeks 15-17): Name Resolution & Optimization
- Phase 6-7 complete: DNS caching, TLS handling
- Optimize dissection performance
- Demo: high-performance pcap processing with name resolution
- Deliverable: `lib/name-resolver/`, performance benchmarks

### Milestone 5 (Weeks 18-21): Testing & Validation
- Phase 8 complete: comprehensive test suite, benchmarking, security audit
- 500+ dissectors ported and tested
- Compare performance against Wireshark on benchmark pcap
- Deliverable: test suite, benchmark results, security report

### Milestone 6 (Weeks 22+): Release & Continuous Sync
- Phase 9: ongoing integration with Wireshark upstream
- Release v1.0 with 500-1000 dissectors
- Establish update pipeline for new Wireshark versions
- Community contribution guidelines

---

## Technical Decisions & Rationale

### 1. **Immutable Data Structures (vs. Mutable)**
- **Choice**: Represent packets, fields as immutable records
- **Rationale**: Jerboa leverages immutability for safety; avoids aliasing bugs; enables functional transformations (filter, map, combine packets)
- **Trade-off**: Slightly higher memory (multiple versions of modified packet), but worth it for correctness

### 2. **Actor System for Name Resolution (vs. Thread Pool)**
- **Choice**: Use Jerboa actors (`(std actor)`) for concurrent DNS
- **Rationale**: Actors fit Jerboa's philosophy; structured concurrency avoids race conditions; natural message-passing for request/response
- **Trade-off**: More complex than simple thread pool, but more maintainable

### 3. **DSL as S-expressions (vs. YAML/JSON)**
- **Choice**: Protocol definitions in Jerboa S-expressions (not text format)
- **Rationale**: Native to Jerboa; can embed Scheme code for custom logic; no parsing overhead; versioning/tooling natural
- **Trade-off**: Less familiar to non-Lispers, but avoids impedance mismatch

### 4. **Dissector Coverage: Subset, Not 100%**
- **Choice**: Target 500-800 dissectors initially, not all 1820
- **Rationale**: Full coverage is low-value; many Wireshark dissectors are for rare/obsolete protocols; focus on breadth + foundational protocols
- **Trade-off**: Users might not find their niche protocol; mitigate with clear documentation + contributor guide

### 5. **No TLS Plaintext Inspection**
- **Choice**: Acknowledge limitation; extract metadata only
- **Rationale**: Correct design decision; no way to decrypt without keys; forcing MITM defeats security
- **Trade-off**: Can't analyze encrypted application traffic; acceptable for most real-world use (80%+ of network traffic today is TLS)

### 6. **Manual Review for Converter Output**
- **Choice**: Converter produces 80% automation; rest requires human review
- **Rationale**: C dissectors have custom parsing logic; full automation infeasible without understanding intent
- **Trade-off**: Slower porting (requires review), but higher quality output

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| **Dissector porting too slow** | Can't catch up with Wireshark | Start with automated converter; prioritize Tier 1 protocols; offload review to community |
| **Performance bottleneck** | Jerboa dissection too slow for real-time | Profile early (Phase 3); optimize critical paths; lazy evaluation where possible; Chez's native compilation |
| **DSL too complex** | Hard for contributors to add protocols | Design DSL incrementally; start simple (fixed-size protocols); add features only when needed |
| **TLS traffic opaqueness** | Users frustrated by encrypted packets | Document clearly upfront; demonstrate metadata extraction; suggest complementary tools (e.g., tshark with decryption keys) |
| **Jerboa ecosystem immaturity** | Missing stdlib modules, bugs | Use only stable stdlib (prelude); audit all imports early; contribute bug fixes upstream if needed; fallback to C FFI if blocked |

---

## Success Criteria

1. **Functional**: Dissect 10+ key protocols correctly (field-by-field match vs. Wireshark)
2. **Safe**: Zero unsafe code; all buffer accesses bounds-checked; `jerboa_security_audit` passes
3. **Fast**: Dissection performance within 2x of Wireshark tshark on benchmark pcap
4. **Comprehensive**: 500+ dissectors ported and passing basic tests
5. **Maintainable**: Clear documentation; porting guide; easy for new contributors
6. **Documented**: Architecture guide, API docs, example protocols
7. **Integrated**: Update pipeline established; tracking upstream Wireshark changes

---

## Open Questions & Future Work

1. **Visualization**: Should we build a GUI? (Out of scope for v1.0; focus on CLI + library)
2. **Real-time capture**: Should we support live packet capture? (Future: `(std os pcap-live)` or libpcap FFI)
3. **Custom dissector plugins**: Allow users to define protocols at runtime? (Future: DSL embedded in REPL)
4. **Pcap augmentation**: Add fields to pcap (e.g., custom annotations)? (Future: pcapng extension blocks)
5. **Interoperability**: Export to JSON/PCAPNG for Wireshark? (Future: translation layer)

---

## Next Steps

1. **Approve plan** with user (verify scope, priorities, timeline)
2. **Start Phase 1**: Create project, inventory Jerboa capabilities, design DSL
3. **Set up communication**: GitHub issues for tracking, PR template for contributions
4. **Solicit early feedback**: share DSL design with Jerboa community, get input

