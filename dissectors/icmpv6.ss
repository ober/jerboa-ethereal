;; jerboa-ethereal/dissectors/icmpv6.ss
;; RFC 4443: Internet Control Message Protocol (ICMPv6) for IPv6
;;
;; Handles core ICMPv6 message types:
;; - Echo Request/Reply (128/129)
;; - Neighbor Solicitation/Advertisement (135/136)
;; - Router Solicitation/Advertisement (133/134)
;; - Redirect (137)
;; - Time Exceeded (3)
;; - Parameter Problem (4)

(import (jerboa prelude))
;; ── Protocol Helpers (from lib/dissector/protocol.ss) ────────────────────

(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

(def (read-u16le buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness little)))))

(def (read-u32le buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (validate pred msg)
  (if pred (ok #t) (err msg)))

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-mac bytes)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bytes))
    ":"))

(def (fmt-hex val)
  (str "0x" (number->string val 16)))

(def (fmt-port port)
  (number->string port))

(def (ip-protocol->protocol num)
  (case num
    ((1) 'icmp) ((6) 'tcp) ((17) 'udp)
    ((41) 'ipv6) ((58) 'icmpv6) (else #f)))



;; ── ICMPv6 Message Type Formatters ────────────────────────────────────

(def (format-icmpv6-type type-val)
  "Format ICMPv6 message type as readable string"
  (case type-val
    ((1) "Destination Unreachable")
    ((2) "Packet Too Big")
    ((3) "Time Exceeded")
    ((4) "Parameter Problem")
    ((100) "Private Experimentation")
    ((101) "Private Experimentation")
    ((128) "Echo Request")
    ((129) "Echo Reply")
    ((130) "Multicast Listener Query")
    ((131) "Multicast Listener Report")
    ((132) "Multicast Listener Done")
    ((133) "Router Solicitation")
    ((134) "Router Advertisement")
    ((135) "Neighbor Solicitation")
    ((136) "Neighbor Advertisement")
    ((137) "Redirect")
    ((255) "Reserved for expansion")
    (else (str "Type " type-val))))

(def (format-icmpv6-code type-val code-val)
  "Format ICMPv6 code based on message type"
  (case type-val
    ((1) ; Destination Unreachable
     (case code-val
       ((0) "No route to destination")
       ((1) "Communication with destination administratively prohibited")
       ((2) "Beyond scope of source address")
       ((3) "Address unreachable")
       ((4) "Port unreachable")
       ((5) "Source address failed ingress/egress policy")
       ((6) "Reject route to destination")
       ((7) "Error in Source Routing Header")
       (else (str "Code " code-val))))
    ((3) ; Time Exceeded
     (case code-val
       ((0) "Hop limit exceeded in transit")
       ((1) "Fragment reassembly time exceeded")
       (else (str "Code " code-val))))
    ((4) ; Parameter Problem
     (case code-val
       ((0) "Erroneous header field encountered")
       ((1) "Unrecognized Next Header type encountered")
       ((2) "Unrecognized IPv6 option encountered")
       (else (str "Code " code-val))))
    (else (str "Code " code-val))))

;; ── Core ICMPv6 Dissector ─────────────────────────────────────────────

(def (dissect-icmpv6 buffer)
  "Parse ICMPv6 message from bytevector
   Returns (ok fields) or (err message)

   Structure (8-byte minimum):
   [0]     type (message type)
   [1]     code (type-specific code)
   [2:4)   checksum (ICMPv6 checksum)
   [4:)    message-specific data (rest of header + payload)"

  (try
    ;; Validate minimum size
    (unwrap (validate (>= (bytevector-length buffer) 8)
                         "ICMPv6 message too short (< 8 bytes)")))

    (let* ((type-res (read-u8 buffer 0))
           (type-val (unwrap type-res))

           (code-res (read-u8 buffer 1))
           (code-val (unwrap code-res))

           (checksum-res (read-u16be buffer 2))
           (checksum (unwrap checksum-res))

           ;; Rest of message (type-specific)
           (rest-len (max 0 (- (bytevector-length buffer) 4)))
           (rest-data (if (> rest-len 0)
                         (unwrap (slice buffer 4 rest-len))
                         #f)))

      ;; Parse type-specific fields
      (let ((type-fields (parse-icmpv6-specific type-val buffer)))
        (ok `((type . ((raw . ,type-val)
                      (formatted . ,(format-icmpv6-type type-val))))
              (code . ((raw . ,code-val)
                      (formatted . ,(format-icmpv6-code type-val code-val))))
              (checksum . ((raw . ,checksum)
                          (formatted . ,(fmt-hex checksum))))
              ,@type-fields
              (payload . ,rest-data)))))

    ;; Error handling
    (catch (e)
      (err (str "ICMPv6 parse error: " e)))))

;; ── Type-Specific Field Parsing ───────────────────────────────────────

(def (parse-icmpv6-specific type-val buffer)
  "Parse type-specific fields for ICMPv6 messages
   Returns alist of additional fields"

  (case type-val
    ;; Echo Request / Echo Reply (128/129)
    ((128 129)
     (if (>= (bytevector-length buffer) 8)
         (try
           (let* ((id-res (read-u16be buffer 4))
                  (id-val (unwrap id-res))
                  (seq-res (read-u16be buffer 6))
                  (seq-val (unwrap seq-res)))
             `((identifier . ((raw . ,id-val)
                             (formatted . ,(fmt-hex id-val))))
               (sequence . ((raw . ,seq-val)
                           (formatted . ,(fmt-hex seq-val))))))
           (catch (e) '()))
         '()))

    ;; Router Solicitation (133) / Router Advertisement (134)
    ((133)
     (if (>= (bytevector-length buffer) 8)
         (try
           (let* ((reserved-res (read-u32be buffer 4))
                  (reserved (unwrap reserved-res)))
             `((reserved . ,reserved)))
           (catch (e) '()))
         '()))

    ((134)
     (if (>= (bytevector-length buffer) 16)
         (try
           (let* ((hop-limit-res (read-u8 buffer 4))
                  (hop-limit (unwrap hop-limit-res))
                  (flags-res (read-u8 buffer 5))
                  (flags (unwrap flags-res))
                  (managed (extract-bits flags #x80 7))
                  (other-config (extract-bits flags #x40 6))
                  (router-lifetime-res (read-u16be buffer 6))
                  (router-lifetime (unwrap router-lifetime-res))
                  (reachable-time-res (read-u32be buffer 8))
                  (reachable-time (unwrap reachable-time-res))
                  (retrans-time-res (read-u32be buffer 12))
                  (retrans-time (unwrap retrans-time-res)))
             `((hop-limit . ,hop-limit)
               (managed-config-flag . ,managed)
               (other-config-flag . ,other-config)
               (router-lifetime . ,router-lifetime)
               (reachable-time . ,reachable-time)
               (retrans-time . ,retrans-time)))
           (catch (e) '()))
         '()))

    ;; Neighbor Solicitation (135) / Neighbor Advertisement (136)
    ((135 136)
     (if (>= (bytevector-length buffer) 24)
         (try
           (let* ((reserved-or-flags-res (read-u32be buffer 4))
                  (reserved-or-flags (unwrap reserved-or-flags-res))
                  (target-ip (unwrap (slice buffer 8 16))))
             `((target-address . ((raw . ,target-ip)
                                 (formatted . ,(fmt-ipv6 target-ip))))
               (flags . ,reserved-or-flags)))
           (catch (e) '()))
         '()))

    ;; Redirect (137)
    ((137)
     (if (>= (bytevector-length buffer) 40)
         (try
           (let* ((reserved-res (read-u32be buffer 4))
                  (reserved (unwrap reserved-res))
                  (target-ip (unwrap (slice buffer 8 16)))
                  (dest-ip (unwrap (slice buffer 24 16))))
             `((reserved . ,reserved)
               (target-address . ((raw . ,target-ip)
                                 (formatted . ,(fmt-ipv6 target-ip))))
               (destination-address . ((raw . ,dest-ip)
                                      (formatted . ,(fmt-ipv6 dest-ip))))))
           (catch (e) '()))
         '()))

    ;; Default: no type-specific fields
    (else '())))

;; ── IPv6 Address Formatter ────────────────────────────────────────────

(def (fmt-ipv6 ipv6-bytes)
  "Format IPv6 address (16 bytes) as standard notation"
  (if (and (bytevector? ipv6-bytes)
           (= (bytevector-length ipv6-bytes) 16))
      ;; Simple hex representation (full notation)
      ;; Real implementation would use :: compression
      (string-join
        (for/collect ((i (in-range 0 16 2)))
          (string-pad (number->string
                       (bytevector-u16-ref ipv6-bytes i (endianness big))
                       16)
                      4 #\0))
        ":")
      "invalid-ipv6"))

;; ── Exported API ───────────────────────────────────────────────────────

;; dissect-icmpv6: main entry point
;; format-icmpv6-type: type formatter
;; format-icmpv6-code: code formatter
;; fmt-ipv6: IPv6 address formatter
