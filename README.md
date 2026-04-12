# jerboa-ethereal

**Safe, performant packet dissection in Jerboa Scheme**

A complete reimplementation of Wireshark's libepan dissectors using Jerboa's safe abstractions. Instead of 1820 lines of C per dissector, define packet formats declaratively in a Jerboa DSL, with zero unsafe code and 100% memory safety.

## Quick Start

```bash
cd ~/mine/jerboa-ethereal
make help          # Show available targets
make build         # Compile all modules (when ready)
make test          # Run test suite (when ready)
```

## Structure

- **`PLAN.md`** — Comprehensive 9-phase implementation plan (22+ weeks)
- **`DIRECTORY_STRUCTURE.md`** — Detailed explanation of project layout
- **`lib/dissector/`** — Core dissection engine and data structures
- **`lib/dsl/`** — Protocol DSL parser and compiler
- **`lib/pcap/`** — PCAP file reader (libpcap and pcapng formats)
- **`lib/name-resolver/`** — Async DNS resolution with caching
- **`lib/search/`** — Packet filtering and search (ngrep-like)
- **`dissectors/`** — Protocol definitions in Jerboa DSL

## Philosophy

1. **Safe by default**: All buffer access is bounds-checked. No unsafe code, ever.
2. **Declarative**: Define protocols as Scheme s-expressions, not imperative C.
3. **Composable**: Protocols nest naturally; dissectors chain automatically.
4. **Honest about TLS**: No plaintext inspection of encrypted traffic; extract metadata instead.
5. **High performance**: Leverage Chez Scheme's native compilation.

## Current Phase

**Phase 1: Foundation** — Project structure, DSL design, core types

See `PLAN.md` for the full implementation roadmap.

## Contributing

See `PLAN.md` § "Porting Guide" (future) for how to add new protocol dissectors.

## References

- Wireshark source: `~/mine/wireshark/`
- libepan protocol definitions: `~/mine/wireshark/epan/dissectors/`
- Original Fournier work: See git history in `~/mine/wireshark`
