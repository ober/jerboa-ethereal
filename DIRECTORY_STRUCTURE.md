# Directory Structure

This document explains the layout of the jerboa-ethereal project.

```
jerboa-ethereal/
├── PLAN.md                    # Comprehensive implementation plan (22+ weeks)
├── README.md                  # Project overview and quick start
├── DIRECTORY_STRUCTURE.md     # This file
├── Makefile                   # Build targets: build, test, check, clean
├── .git/                      # Git repository
│
├── lib/                       # Jerboa source libraries
│   ├── dissector/
│   │   ├── engine.ss          # Phase 1: Core dissection pipeline
│   │   │                        - packet-t record type
│   │   │                        - field-value record type
│   │   │                        - safe buffer abstraction
│   │   │                        - dissection algorithm
│   │   └── (additional modules in Phase 3)
│   │
│   ├── dsl/
│   │   ├── parser.ss          # Phase 2: DSL parser and compiler
│   │   │                        - parse protocol definitions
│   │   │                        - validate field specs
│   │   │                        - type resolution
│   │   │                        - compile to dissector functions
│   │   ├── types.ss           # Field type system (u8, u16be, bytes, etc.)
│   │   ├── formatters.ss      # Built-in formatters (IPv4, MAC, hex, etc.)
│   │   └── (additional in Phase 2)
│   │
│   ├── pcap/
│   │   ├── reader.ss          # Phase 5: PCAP file reader
│   │   │                        - libpcap format (.pcap)
│   │   │                        - pcapng format (.pcapng)
│   │   ├── dissect.ss         # Phase 5: Connect pcap reading to dissection
│   │   ├── display.ss         # Phase 5: Pretty-printing and display
│   │   ├── edit.ss            # Phase 5: Packet editing and merge/split
│   │   └── (additional in Phase 5)
│   │
│   ├── search/
│   │   ├── filter.ss          # Phase 5: Packet filtering and search
│   │   │                        - payload-contains, src-ip, protocol, etc.
│   │   │                        - regex pattern matching (ngrep-like)
│   │   └── (additional in Phase 5)
│   │
│   └── name-resolver/
│       ├── resolver.ss        # Phase 6: Actor-based DNS caching
│       │                        - concurrent DNS resolution
│       │                        - persistent SQLite cache
│       ├── static.ss          # Phase 6: Static name mappings
│       │                        - well-known ports (TCP/UDP)
│       │                        - IP protocol numbers
│       │                        - Ethernet types
│       └── (additional in Phase 6)
│
├── dissectors/                # Protocol definitions in Jerboa DSL
│   ├── ethernet.ss            # Phase 2: Layer 2 - IEEE 802.3 Ethernet
│   ├── arp.ss                 # Phase 2: Address Resolution Protocol
│   ├── vlan.ss                # Phase 2: 802.1Q VLAN tagging
│   ├── ipv4.ss                # Phase 2: Layer 3 - IPv4
│   ├── ipv6.ss                # Phase 2: Layer 3 - IPv6
│   ├── icmp.ss                # Phase 2: ICMP
│   ├── tcp.ss                 # Phase 2: Layer 4 - TCP
│   ├── udp.ss                 # Phase 2: Layer 4 - UDP
│   ├── dns.ss                 # Phase 2: DNS
│   ├── dhcp.ss                # Phase 2: DHCP
│   ├── http.ss                # Phase 2: HTTP
│   ├── tls.ss                 # Phase 7: TLS (metadata only)
│   ├── (and 700+ more via converter in Phase 4)
│   └── README.md              # Guide to protocol definitions
│
├── converter/                 # Phase 4: Wireshark C → Jerboa DSL
│   ├── c-parser.ss            # Parse Wireshark C dissectors
│   ├── type-mapper.ss         # Map C types to Jerboa types
│   ├── codegen.ss             # Generate Jerboa DSL from parsed C
│   └── batch.ss               # Batch convert all 1820 dissectors
│
├── test/                      # Test suite
│   ├── dissector-test.ss      # Phase 8: Unit tests for dissector engine
│   ├── dsl-test.ss            # Phase 8: DSL parser tests
│   ├── pcap-test.ss           # Phase 8: PCAP reader tests
│   ├── integration-test.ss    # Phase 8: End-to-end dissection tests
│   └── corpus/                # Test PCAP files
│       ├── ethernet.pcap
│       ├── ipv4-udp.pcap
│       ├── tcp-http.pcap
│       ├── (etc.)
│       └── README.md          # Where to download public PCAP corpus
│
├── docs/                      # Documentation
│   ├── ARCHITECTURE.md        # Phase 8: Architecture guide
│   ├── PORTING.md             # Phase 8: Protocol porting guide
│   ├── DSL_GUIDE.md           # Phase 3: DSL format and examples
│   ├── API.md                 # Auto-generated via jerboa_generate_api_docs
│   └── (additional docs)
│
├── tools/                     # CLI tools
│   ├── ethereal.ss            # Main CLI entry point
│   │                            - ethereal dissect <pcap>
│   │                            - ethereal search <pattern> <pcap>
│   │                            - ethereal edit <pcap> <updates> -o <out>
│   │                            - ethereal merge <pcap>...
│   │                            - ethereal split <pcap> <predicate>
│   └── (additional tools in Phase 5+)
│
└── build.ss                   # Build script (make build)
└── test-runner.ss             # Test runner (make test)
└── check.ss                   # Static checks (make check)
```

## Module Dependencies

```
tools/ethereal.ss
  ├─ lib/dissector/engine.ss
  ├─ lib/dsl/parser.ss
  ├─ lib/pcap/reader.ss
  ├─ lib/pcap/dissect.ss
  ├─ lib/pcap/display.ss
  ├─ lib/search/filter.ss
  ├─ lib/name-resolver/resolver.ss
  └─ dissectors/*.ss
```

## Build Phases

Each phase introduces new modules and dissectors:

| Phase | Modules | Dissectors | Tests |
|-------|---------|-----------|-------|
| 1 | engine | - | - |
| 2 | dsl, types, formatters | 10 core | basic |
| 3 | engine (expanded) | 10 core | expanded |
| 4 | converter | 100+ auto | validation |
| 5 | pcap, search, display | 100+ | integration |
| 6 | name-resolver, static | 100+ | perf |
| 7 | tls dissector | 100+ | encrypted |
| 8 | tests, docs | 500+ | comprehensive |
| 9 | (maintenance) | 500-1000 | continuous |

## File Naming Conventions

- **Dissectors**: `dissectors/<protocol-name>.ss` (kebab-case)
  - Example: `dissectors/ipv4.ss`, `dissectors/tcp-syn-cookies.ss`

- **Modules**: `lib/<category>/<feature>.ss`
  - Example: `lib/dissector/engine.ss`, `lib/name-resolver/resolver.ss`

- **Tests**: `test/<module>-test.ss` or `test/<integration>.ss`
  - Example: `test/dissector-test.ss`, `test/pcap-reader-test.ss`

- **Tools**: `tools/<tool-name>.ss` (executable)
  - Example: `tools/ethereal.ss`

## Editing Guidelines

When adding new files:
1. Place in appropriate directory (see structure above)
2. Start with phase number in comments: `;;; Phase N: ...`
3. Add TODO comments for unimplemented sections
4. Export at end: `(export ...)`
5. Update this file if adding new directories/categories

## Notes

- All `.ss` files import `(jerboa prelude)` as base
- Use `jerboa_verify` before committing
- Run `make check` to validate all modules
- See `PLAN.md` for detailed phase breakdown
