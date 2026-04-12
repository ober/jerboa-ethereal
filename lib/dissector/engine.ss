;; jerboa-ethereal/lib/dissector/engine.ss
;; Core dissection pipeline: binary packet parsing and field extraction
;;
;; Parses raw bytevectors using protocol definitions from DSL,
;; extracting fields with formatters, handling conditional fields,
;; and chaining through nested protocols.

(import (jerboa prelude))

;; ── Data Structures ─────────────────────────────────────────────────────────

(defstruct buffer (bytes pos end-offset))

(defstruct field-value (name type raw-value formatted description))

(defstruct dissected-packet (protocol-name fields raw-bytes payload-start payload-bytes next-protocol))

;; ── Buffer Operations ──────────────────────────────────────────────────────

(def (buffer-length buf)
  "Remaining bytes in buffer"
  (- (buffer-end-offset buf) (buffer-pos buf)))

(def (buffer-remaining? buf)
  "Check if buffer has unread data"
  (> (buffer-length buf) 0))

(def (buffer-peek-u8 buf)
  "Read u8 without advancing position"
  (let ([pos (buffer-pos buf)])
    (when (>= pos (buffer-end-offset buf))
      (error 'buffer-peek-u8 "End of buffer"))
    (bytevector-u8-ref (buffer-bytes buf) pos)))

(def (buffer-read-u8 buf)
  "Read and consume u8"
  (let ([val (buffer-peek-u8 buf)])
    (set-buffer-pos! buf (+ (buffer-pos buf) 1))
    val))

(def (buffer-read-u16 buf endian)
  "Read and consume u16 with specified endianness"
  (let ([pos (buffer-pos buf)])
    (when (> (+ pos 2) (buffer-end-offset buf))
      (error 'buffer-read-u16 "Not enough bytes for u16"))
    (let ([val (bytevector-u16-ref (buffer-bytes buf) pos endian)])
      (set-buffer-pos! buf (+ pos 2))
      val)))

(def (buffer-read-u32 buf endian)
  "Read and consume u32 with specified endianness"
  (let ([pos (buffer-pos buf)])
    (when (> (+ pos 4) (buffer-end-offset buf))
      (error 'buffer-read-u32 "Not enough bytes for u32"))
    (let ([val (bytevector-u32-ref (buffer-bytes buf) pos endian)])
      (set-buffer-pos! buf (+ pos 4))
      val)))

(def (buffer-read-u64 buf endian)
  "Read and consume u64 with specified endianness"
  (let ([pos (buffer-pos buf)])
    (when (> (+ pos 8) (buffer-end-offset buf))
      (error 'buffer-read-u64 "Not enough bytes for u64"))
    (let ([val (bytevector-u64-ref (buffer-bytes buf) pos endian)])
      (set-buffer-pos! buf (+ pos 8))
      val)))

(def (buffer-read-bytes buf size)
  "Read and consume N bytes"
  (let ([pos (buffer-pos buf)])
    (when (> (+ pos size) (buffer-end-offset buf))
      (error 'buffer-read-bytes (str "Not enough bytes: need " size)))
    (let ([result (make-bytevector size)])
      (bytevector-copy! (buffer-bytes buf) pos result 0 size)
      (set-buffer-pos! buf (+ pos size))
      result)))

;; ── Type Parsing ───────────────────────────────────────────────────────────

(def (parse-type buf type-name)
  "Parse a field type from buffer"
  (case type-name
    [(u8) (buffer-read-u8 buf)]
    [(u16be) (buffer-read-u16 buf (endianness big))]
    [(u16le) (buffer-read-u16 buf (endianness little))]
    [(u32be) (buffer-read-u32 buf (endianness big))]
    [(u32le) (buffer-read-u32 buf (endianness little))]
    [(u64be) (buffer-read-u64 buf (endianness big))]
    [(u64le) (buffer-read-u64 buf (endianness little))]
    [(bytes) (error 'parse-type "bytes type requires size parameter")]
    [#t (error 'parse-type (str "Unknown type: " type-name))]))

;; ── Formatter Registry ──────────────────────────────────────────────────────

(def formatters (make-hash-table))

(def (register-formatter! type-name formatter-func)
  "Register a formatter function"
  (hash-put! formatters type-name formatter-func))

(def (get-formatter formatter-name)
  "Get formatter by name, returns default if not found"
  (or (hash-get formatters formatter-name) format-default))

;; Built-in formatters

(def (format-ipv4 addr)
  "IPv4 address: u32 → a.b.c.d"
  (let* ([b0 (bitwise-arithmetic-shift-right addr 24)]
         [b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255)]
         [b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255)]
         [b3 (bitwise-and addr 255)])
    (str b0 "." b1 "." b2 "." b3)))

(def (format-hex val)
  "Hexadecimal formatting"
  (cond
    [(bytevector? val)
     (str "0x" (string-join
                 (for/collect ([b (in-bytes val)])
                   (format "~2,'0x" b))
                 ""))]
    [(integer? val) (format "0x~x" val)]
    [#t (str val)]))

(def (format-port port-num)
  "Port number with optional service name"
  (let ([services (alist
                    (22 "ssh") (80 "http") (443 "https")
                    (53 "dns") (123 "ntp") (3306 "mysql"))])
    (let ([svc (assoc-in services port-num)])
      (if svc
          (str (cdr svc) " (" port-num ")")
          (str port-num)))))

(def (format-default val)
  "Default: convert to string"
  (str val))

;; Register standard formatters
(register-formatter! 'format-ipv4 format-ipv4)
(register-formatter! 'format-hex format-hex)
(register-formatter! 'format-port format-port)

;; ── Field Parsing ──────────────────────────────────────────────────────────

(def (parse-field-value buf field-spec proto-context)
  "Parse a single field from buffer
   field-spec: (name type size mask shift formatter description)
   proto-context: alist of (field-name . value) from already-parsed fields"

  (let* ([name (car field-spec)]
         [type (cadr field-spec)]
         [size (caddr field-spec)]
         [mask (cadddr field-spec)]
         [shift (car (cddddr field-spec))]
         [formatter-name (cadr (cddddr field-spec))]
         [description (caddr (cddddr field-spec))])

    ;; Calculate actual size if dynamic
    (let ([actual-size (cond
                         [(integer? size) size]
                         [(symbol? size)
                          (let ([val (assoc-in proto-context size)])
                            (if val (cdr val)
                                (error 'parse-field-value (str "Unknown field: " size))))]
                         [#t (error 'parse-field-value (str "Invalid size: " size))])])

      ;; Parse raw value
      (let ([raw-val (if (eq? type 'bytes)
                         (buffer-read-bytes buf actual-size)
                         (parse-type buf type))])

        ;; Apply mask and shift if present
        (let ([masked-val (if (and mask shift (integer? raw-val))
                              (bitwise-arithmetic-shift-right
                                (bitwise-and raw-val mask) shift)
                              raw-val)])

          ;; Format the value
          (let ([formatter (get-formatter formatter-name)])
            (let ([formatted (formatter masked-val)])
              (make-field-value name type masked-val formatted description))))))))

;; ── Protocol Dissection ─────────────────────────────────────────────────────

(def (dissect-protocol protocol buf)
  "Parse protocol from buffer
   protocol: (name description field-specs link-type next-protocol-field)
   buf: buffer struct
   Returns: dissected-packet struct"

  (let* ([proto-name (car protocol)]
         [field-specs (caddr protocol)]
         [next-field (car (cddddr protocol))])

    ;; Parse all fields
    (let loop ([specs field-specs]
               [fields '()]
               [proto-context '()])

      (if (null? specs)
          ;; All fields parsed - create result
          (let ([payload-remaining (buffer-length buf)])
            (let ([payload-bytes (if (> payload-remaining 0)
                                     (buffer-read-bytes buf payload-remaining)
                                     #f)])
              ;; Look up next protocol if there's a next-field indicator
              (let ([next-proto (if next-field
                                   (find-next-protocol-name (reverse fields) next-field)
                                   #f)])
                (make-dissected-packet
                  proto-name
                  (reverse fields)
                  (buffer-bytes buf)
                  (buffer-pos buf)
                  payload-bytes
                  next-proto))))

          ;; Parse next field
          (let* ([spec (car specs)]
                 [field (parse-field-value buf spec proto-context)])
            (loop (cdr specs)
                  (cons field fields)
                  (cons (cons (field-value-name field) (field-value-raw-value field))
                        proto-context)))))))

;; ── Protocol Discovery ─────────────────────────────────────────────────────

(def (find-next-protocol-name fields field-name)
  "Find protocol name from field value in parsed fields"
  (let loop ([fields fields])
    (if (null? fields)
        #f
        (let ([field (car fields)])
          (if (eq? (field-value-name field) field-name)
              (raw-value-to-protocol (field-value-raw-value field))
              (loop (cdr fields)))))))

(def (raw-value-to-protocol value)
  "Map EtherType or IP protocol number to protocol name"
  (cond
    [(= value #x0800) 'ipv4]      ;; IPv4 EtherType
    [(= value #x0806) 'arp]       ;; ARP EtherType
    [(= value #x86DD) 'ipv6]      ;; IPv6 EtherType
    [(= value 1) 'icmp]           ;; ICMP IP protocol
    [(= value 6) 'tcp]            ;; TCP IP protocol
    [(= value 17) 'udp]           ;; UDP IP protocol
    [#t #f]))

;; ── Packet Tree Display ────────────────────────────────────────────────────

(def (dissected-packet->string pkt (indent 0))
  "Format dissected packet for display"
  (let ([spaces (make-string indent #\space)])
    (string-join
      (cons (str spaces (dissected-packet-protocol-name pkt) ":")
            (map (lambda (f)
                   (str spaces "  " (field-value-name f) " = " (field-value-formatted f)))
                 (dissected-packet-fields pkt)))
      "\n")))

(def (dissect-packet-chain pkt protocols indent)
  "Recursively dissect payload with chained protocols"
  (let ([output (dissected-packet->string pkt indent)])
    (if (and (dissected-packet-payload-bytes pkt)
             (dissected-packet-next-protocol pkt))
        (let* ([next-proto-name (dissected-packet-next-protocol pkt)]
               [next-proto (assoc-in protocols next-proto-name)])
          (if next-proto
              (let ([payload-buf (make-buffer
                                   (dissected-packet-payload-bytes pkt) 0
                                   (bytevector-length (dissected-packet-payload-bytes pkt)))])
                (let ([next-pkt (dissect-protocol next-proto payload-buf)])
                  (str output "\n" (dissect-packet-chain next-pkt protocols (+ indent 2)))))
              output))
        output)))
