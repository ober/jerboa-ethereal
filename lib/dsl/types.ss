;; jerboa-ethereal/lib/dsl/types.ss
;; Type system for packet field types
;;
;; Defines predicates for all field types (u8, u16be, bytes, string, etc.)
;; and provides utilities for type checking and conversion.

(import (jerboa prelude))

;; ── Primitive Type Predicates ───────────────────────────────────────────────
;; Each type predicate returns #t if a value is valid for that type.

(def (u8? x)
  "Predicate: unsigned 8-bit integer (0-255)"
  (and (integer? x) (>= x 0) (<= x 255)))

(def (u16be? x)
  "Predicate: big-endian unsigned 16-bit integer"
  (and (integer? x) (>= x 0) (<= x 65535)))

(def (u16le? x)
  "Predicate: little-endian unsigned 16-bit integer"
  (and (integer? x) (>= x 0) (<= x 65535)))

(def (u32be? x)
  "Predicate: big-endian unsigned 32-bit integer"
  (and (integer? x) (>= x 0) (<= x 4294967295)))

(def (u32le? x)
  "Predicate: little-endian unsigned 32-bit integer"
  (and (integer? x) (>= x 0) (<= x 4294967295)))

(def (u64be? x)
  "Predicate: big-endian unsigned 64-bit integer"
  (and (integer? x) (>= x 0) (<= x 18446744073709551615)))

(def (u64le? x)
  "Predicate: little-endian unsigned 64-bit integer"
  (and (integer? x) (>= x 0) (<= x 18446744073709551615)))

(def (bytes? x)
  "Predicate: bytevector (raw bytes)"
  (bytevector? x))

(def (string? x)
  "Predicate: string (text)"
  (string? x))

(def (bitfield? x)
  "Predicate: bitfield (masked bits from byte)"
  (and (integer? x) (>= x 0) (<= x 255)))

;; ── Type Information ────────────────────────────────────────────────────────
;; Maps type names to metadata: size, endianness, predicate

;; Field type structure: represents metadata about a protocol field type
;; Maps: name -> (name size predicate endianness parser doc)
;; Using alists for simplicity (name . (size predicate endianness parser doc))

(def field-types-registry (make-hash-table))

(def (register-field-type! name size predicate endianness parser doc)
  "Register a field type in the global registry
   Args: name (symbol), size (int or #f), predicate (proc),
         endianness (symbol or #f), parser (proc), doc (string)"
  (hash-put! field-types-registry name
    (list size predicate endianness parser doc)))

(def (lookup-field-type name)
  "Look up a field type by name, return (size predicate endianness parser doc) or #f"
  (hash-get field-types-registry name))

(def (field-type-size name)
  "Get size (in bytes) of a field type, or #f if variable"
  (let ([data (lookup-field-type name)])
    (if data (car data) #f)))

(def (field-type-predicate name)
  "Get predicate function for a field type"
  (let ([data (lookup-field-type name)])
    (if data (cadr data) #f)))

(def (field-type-parser name)
  "Get parser function for a field type"
  (let ([data (lookup-field-type name)])
    (if data (cadddr data) #f)))

;; ── Define Standard Types ───────────────────────────────────────────────────

;; Register u8 type
(register-field-type! 'u8 1 u8? #f
  (lambda (buf offset)
    "Read u8 from buffer at offset"
    (if (>= offset (bytevector-length buf))
        (error 'parse-u8 (str "Buffer too short: offset " offset " >= length " (bytevector-length buf)))
        (bytevector-u8-ref buf offset)))
  "Unsigned 8-bit integer")

;; Register u16be type
(register-field-type! 'u16be 2 u16be? 'big
  (lambda (buf offset)
    "Read big-endian u16 from buffer"
    (let ([len (bytevector-length buf)])
      (unless (>= len (+ offset 2))
        (error 'parse-u16be (str "Buffer too short: need " (+ offset 2) ", have " len)))
      (bytevector-u16-ref buf offset (endianness big))))
  "Big-endian unsigned 16-bit integer")

;; Register u16le type
(register-field-type! 'u16le 2 u16le? 'little
  (lambda (buf offset)
    "Read little-endian u16 from buffer"
    (let ([len (bytevector-length buf)])
      (unless (>= len (+ offset 2))
        (error 'parse-u16le (str "Buffer too short: need " (+ offset 2) ", have " len)))
      (bytevector-u16-ref buf offset (endianness little))))
  "Little-endian unsigned 16-bit integer")

;; Register u32be type
(register-field-type! 'u32be 4 u32be? 'big
  (lambda (buf offset)
    "Read big-endian u32 from buffer"
    (let ([len (bytevector-length buf)])
      (unless (>= len (+ offset 4))
        (error 'parse-u32be (str "Buffer too short: need " (+ offset 4) ", have " len)))
      (bytevector-u32-ref buf offset (endianness big))))
  "Big-endian unsigned 32-bit integer")

;; Register u32le type
(register-field-type! 'u32le 4 u32le? 'little
  (lambda (buf offset)
    "Read little-endian u32 from buffer"
    (let ([len (bytevector-length buf)])
      (unless (>= len (+ offset 4))
        (error 'parse-u32le (str "Buffer too short: need " (+ offset 4) ", have " len)))
      (bytevector-u32-ref buf offset (endianness little))))
  "Little-endian unsigned 32-bit integer")

;; Register u64be type
(register-field-type! 'u64be 8 u64be? 'big
  (lambda (buf offset)
    "Read big-endian u64 from buffer"
    (let ([len (bytevector-length buf)])
      (unless (>= len (+ offset 8))
        (error 'parse-u64be (str "Buffer too short: need " (+ offset 8) ", have " len)))
      (bytevector-u64-ref buf offset (endianness big))))
  "Big-endian unsigned 64-bit integer")

;; Register u64le type
(register-field-type! 'u64le 8 u64le? 'little
  (lambda (buf offset)
    "Read little-endian u64 from buffer"
    (let ([len (bytevector-length buf)])
      (unless (>= len (+ offset 8))
        (error 'parse-u64le (str "Buffer too short: need " (+ offset 8) ", have " len)))
      (bytevector-u64-ref buf offset (endianness little))))
  "Little-endian unsigned 64-bit integer")

;; Register bytes type (variable length)
(register-field-type! 'bytes #f bytes? #f
  (lambda (buf offset size)
    "Extract bytevector from buffer (size required)"
    (let ([len (bytevector-length buf)])
      (unless (>= len (+ offset size))
        (error 'parse-bytes (str "Buffer too short: need " (+ offset size) ", have " len)))
      (bytevector-slice buf offset size)))
  "Raw byte sequence (variable length)")

;; All top-level definitions are exported by default in Jerboa.
;; Public API:
;;   - Type predicates: u8?, u16be?, u16le?, u32be?, u32le?, u64be?, u64le?, bytes?, string?, bitfield?
;;   - Type registry: field-types-registry, register-field-type!, lookup-field-type
;;   - Type accessors: field-type-size, field-type-predicate, field-type-parser
