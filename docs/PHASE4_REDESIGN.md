# Phase 4 Redesign: Minimal, Safe, Fast Dissectors

## Problem with Original Approach

The initial Phase 3 engine used **runtime interpretation**:
- Parse field specs at runtime
- Evaluate conditionals at runtime  
- Evaluate size expressions at runtime
- Formatters as registry lookups

**Issues:**
- Complex, error-prone
- Performance overhead
- Hard to reason about safety
- Difficult to handle malformed packets gracefully

## New Direction: Code Generation

**Shift to compile-time code generation:**
- Each protocol definition generates tight, specialized code
- Zero runtime interpretation
- All safety checks INLINE
- Clear error handling via Result types
- Minimal boilerplate

## Core Philosophy

1. **Inline Safety**: Every read checks bounds
2. **Result Types**: (ok value) or (err message) for all I/O
3. **Tight Code**: Generated code is readable and efficient
4. **Graceful Degradation**: Corrupt packets → clear errors, no crashes
5. **No Runtime Complexity**: Protocols don't depend on a heavy engine

## Example: Ethernet Protocol

### Old Way (Interpreted)
```scheme
;; Define as data structure, interpret at runtime
(def ethernet-protocol
  '(defprotocol ethernet
     :field-specs ((dest-mac u48be :formatter format-mac)
                   (src-mac u48be :formatter format-mac)
                   (type u16be :formatter format-ethertype)
                   (payload bytes))))

;; Engine interprets field specs at runtime
(dissect-protocol ethernet-proto buffer)
```

### New Way (Generated Code)
```scheme
;; Tight, readable code with all safety inline
(def (dissect-ethernet buffer)
  "Parse Ethernet frame"
  (try-result
    (let* ((dest-mac (unwrap (slice buffer 0 6)))
           (src-mac (unwrap (slice buffer 6 6)))
           (type-val (unwrap (read-u16be buffer 12)))
           (payload (unwrap (slice buffer 14 
                                   (- (bytevector-length buffer) 14)))))
      (ok `((dest-mac . ,(fmt-mac dest-mac))
            (src-mac . ,(fmt-mac src-mac))
            (type . ((raw . ,type-val)
                    (formatted . ,(format-ethertype type-val))
                    (next-protocol . ,(ethertype->protocol type-val))))
            (payload . ,payload))))
    (catch (e)
      (err (str "Ethernet error: " e)))))
```

**Benefits:**
- ✓ Zero runtime overhead
- ✓ Every bounds check visible
- ✓ Obvious control flow
- ✓ Handles corruption gracefully
- ✓ Easy to verify safety

## Implementation Layers

### 1. Safe Read Primitives (lib/dissector/protocol.ss)
```scheme
(read-u8 buf offset)      → (ok u8) | (err msg)
(read-u16be buf offset)   → (ok u16) | (err msg)
(read-u32be buf offset)   → (ok u32) | (err msg)
(slice buf offset len)    → (ok bytes) | (err msg)

(extract-bits val mask shift)  → u8
(validate pred msg)            → (ok #t) | (err msg)
```

### 2. Formatters (inline in protocol.ss)
```scheme
(fmt-ipv4 addr)     → "192.168.1.1"
(fmt-mac bytes)     → "00:11:22:33:44:55"
(fmt-hex val)       → "0xDEADBEEF"
(fmt-port num)      → "ssh (22)"
```

### 3. Protocol Discovery
```scheme
(ethertype->protocol #x0800)   → 'ipv4
(ip-protocol->protocol 17)     → 'udp
```

### 4. Protocol Functions
Each protocol (ethernet, ipv4, udp, tcp, ...) is a single function:
```scheme
(def (dissect-NAME buffer)
  "Dissect NAME protocol from buffer
   Returns (ok fields) or (err msg)"
  ...)
```

## Field Structure

All fields follow consistent structure:
```
(field-name . raw-value)           ;; simple int/bytes
(field-name . (raw . value))       ;; with metadata
(field-name . ((raw . val)         ;; with formatted + chaining
              (formatted . str)
              (next . proto-name)))
```

## Error Handling Strategy

**All errors are recoverable:**
- Truncated packet → `(err "Buffer overrun")`
- Invalid field value → `(err "Invalid IHL")`
- Malformed option → `(err "IPv4 option truncated")`

Consumers can:
- Partial dissection: take what succeeded before error
- Retry with larger buffer
- Log and skip malformed packet
- Display error message to user

## Next Steps (Remaining Phase 4)

1. **Ethernet**: Rewrite to use new primitives ✓
2. **IPv4**: Rewrite with inline safety
3. **UDP**: Simple, clean dissector
4. **TCP**: More complex options handling
5. **Demo**: End-to-end packet dissection
6. **Integration**: Tests, error handling

## Migration Path

Old code (runtime-interpreted) → New code (code-generated)
- No need to port interpreter
- Each protocol is independent
- Gradual migration possible
- Can mix old and new protocols temporarily

## Philosophy Summary

> "Complexity at compile time, simplicity at runtime"

- Dissectors are fast, safe, obvious
- Boilerplate is minimal
- Adding new protocols is straightforward
- Corrupt packets are handled gracefully
- No mystery crashes—all errors are explicit

This approach scales to thousands of protocols without sacrificing performance or safety.