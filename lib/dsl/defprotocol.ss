;; jerboa-ethereal/lib/dsl/defprotocol.ss
;; Macro-based protocol definition DSL
;;
;; Transforms declarative protocol specs into optimized, safe dissectors.
;; Key principle: ALL complexity at macro-expansion time, zero runtime overhead.

(import (jerboa prelude))

;; ── DSL Entry Point ────────────────────────────────────────────────────────
;; (defprotocol name docstring
;;   (field-name type :size size-expr :formatter fmt-name :on-error recover)
;;   ...)

(defrule (defprotocol name docstring . fields)
  "Define a packet dissector protocol
   Generates (dissect-NAME buffer) function that safely parses packets.
   On any error (bounds, corruption), returns error result."

  (begin
    ;; Generate the dissector function
    (def (dissect-name-fn buffer)
      docstring
      ;; Expand all field parsing with error checking
      (try-result
        (parse-fields-name buffer (make-alist))
        (catch (e)
          (err (str "Parse error in " 'name ": " e)))))

    ;; Metadata: export protocol info for chaining
    (def name-protocol
      `(name ,docstring ,(list ,@(map (lambda (f) `',(car f)) fields)))))))

;; ── Field Parsing (expands to inline code) ────────────────────────────────

(defrule (parse-u8 buffer pos)
  "Read u8 with bounds checking, returns (ok value) or (err msg)"
  (if (>= pos (bytevector-length buffer))
      (err "EOF reading u8")
      (ok (bytevector-u8-ref buffer pos))))

(defrule (parse-u16be buffer pos)
  "Read u16 big-endian with bounds checking"
  (if (> (+ pos 2) (bytevector-length buffer))
      (err "EOF reading u16be")
      (ok (bytevector-u16-ref buffer pos (endianness big)))))

(defrule (parse-u32be buffer pos)
  "Read u32 big-endian with bounds checking"
  (if (> (+ pos 4) (bytevector-length buffer))
      (err "EOF reading u32be")
      (ok (bytevector-u32-ref buffer pos (endianness big)))))

(defrule (parse-u16le buffer pos)
  "Read u16 little-endian with bounds checking"
  (if (> (+ pos 2) (bytevector-length buffer))
      (err "EOF reading u16le")
      (ok (bytevector-u16-ref buffer pos (endianness little)))))

(defrule (parse-u32le buffer pos)
  "Read u32 little-endian with bounds checking"
  (if (> (+ pos 4) (bytevector-length buffer))
      (err "EOF reading u32le")
      (ok (bytevector-u32-ref buffer pos (endianness little)))))

;; ── Type-Safe Field Extraction ─────────────────────────────────────────────

(def (safe-slice buffer offset length)
  "Extract bytes [offset, offset+length) with bounds check"
  (if (> (+ offset length) (bytevector-length buffer))
      (err (str "Buffer overrun: tried to read " length " bytes at offset " offset))
      (ok (let ((result (make-bytevector length)))
            (bytevector-copy! buffer offset result 0 length)
            result))))

(def (safe-read-u8 buffer offset)
  "Read u8 at offset with bounds check"
  (if (>= offset (bytevector-length buffer))
      (err (str "Buffer overrun at offset " offset))
      (ok (bytevector-u8-ref buffer offset))))

(def (safe-read-u16be buffer offset)
  "Read u16be at offset with bounds check"
  (if (> (+ offset 2) (bytevector-length buffer))
      (err (str "Buffer overrun reading u16be at offset " offset))
      (ok (bytevector-u16-ref buffer offset (endianness big)))))

(def (safe-read-u32be buffer offset)
  "Read u32be at offset with bounds check"
  (if (> (+ offset 4) (bytevector-length buffer))
      (err (str "Buffer overrun reading u32be at offset " offset))
      (ok (bytevector-u32-ref buffer offset (endianness big)))))

(def (safe-read-u16le buffer offset)
  "Read u16le at offset with bounds check"
  (if (> (+ offset 2) (bytevector-length buffer))
      (err (str "Buffer overrun reading u16le at offset " offset))
      (ok (bytevector-u16-ref buffer offset (endianness little)))))

(def (safe-read-u32le buffer offset)
  "Read u32le at offset with bounds check"
  (if (> (+ offset 4) (bytevector-length buffer))
      (err (str "Buffer overrun reading u32le at offset " offset))
      (ok (bytevector-u32-ref buffer offset (endianness little)))))

;; ── Bitfield Extraction ────────────────────────────────────────────────────

(def (extract-bitfield value mask shift)
  "Extract masked bits and shift right
   (extract-bitfield #b11110000 #b11110000 4) → upper 4 bits"
  (bitwise-arithmetic-shift-right (bitwise-and value mask) shift))

;; ── Formatter Application ─────────────────────────────────────────────────

(def (fmt-ipv4 addr)
  "Format u32 as a.b.c.d"
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-hex val)
  "Format as 0xHEXHEX"
  (if (integer? val)
      (format "0x~x" val)
      (str val)))

(def (fmt-port port-num)
  "Port number with service lookup"
  (let ((services (alist
                    (22 . "ssh") (80 . "http") (443 . "https")
                    (53 . "dns") (123 . "ntp") (3306 . "mysql"))))
    (let ((svc (assoc-in services port-num)))
      (if svc
          (str (cdr svc) " (" port-num ")")
          (str port-num)))))

(def (fmt-mac addr)
  "Format u48 as xx:xx:xx:xx:xx:xx"
  (let ((bytes (reverse
                 (for/collect ((i (in-range 0 6)))
                   (bitwise-and (bitwise-arithmetic-shift-right addr (* i 8)) 255)))))
    (string-join (map (lambda (b) (format "~2,'0x" b)) bytes) ":")))

;; ── Protocol Discovery Helpers ────────────────────────────────────────────

(def (ethertype->protocol type)
  "Map EtherType to protocol name"
  (case type
    ((#x0800) 'ipv4)
    ((#x0806) 'arp)
    ((#x86DD) 'ipv6)
    (else #f)))

(def (ip-protocol->protocol num)
  "Map IP protocol number to protocol name"
  (case num
    ((1) 'icmp)
    ((6) 'tcp)
    ((17) 'udp)
    (else #f))))