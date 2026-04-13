;; jerboa-ethereal/dissectors/ipv6.ss
;; RFC 2460: Internet Protocol, Version 6 (IPv6)
;;
;; 40-byte fixed header with extension header chaining

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



;; ── IPv6 Next Header Formatter ────────────────────────────────────────────

(def (format-next-header nh)
  "Format IPv6 next header value"
  (case nh
    ((0) "Hop-by-Hop Option")
    ((1) "ICMP")
    ((2) "IGMP")
    ((6) "TCP")
    ((17) "UDP")
    ((41) "IPv6")
    ((43) "Routing Header")
    ((44) "Fragment Header")
    ((47) "GRE")
    ((50) "Encapsulating Security Payload")
    ((51) "Authentication Header")
    ((58) "ICMPv6")
    ((59) "No Next Header")
    ((60) "Destination Options")
    (else (str "NH " nh))))

(def (format-ipv6-traffic-class tc)
  "Format IPv6 Traffic Class (DSCP + ECN)"
  (let ((dscp (bitwise-arithmetic-shift-right (bitwise-and tc #xFC) 2))
        (ecn (bitwise-and tc #x03)))
    (str "DSCP=" dscp " ECN=" ecn)))

;; ── Format IPv6 Address ───────────────────────────────────────────────────

(def (fmt-ipv6-address addr-bytes)
  "Format 16-byte IPv6 address in standard notation"
  (if (< (bytevector-length addr-bytes) 16)
      "invalid"
      (string-join
        (for/collect ((i (in-range 0 16 2)))
          (let ((high (bytevector-u8-ref addr-bytes i))
                (low (bytevector-u8-ref addr-bytes (+ i 1))))
            (string-pad (number->string (+ (bitwise-arithmetic-shift-left high 8) low) 16)
                       4 #\0)))
        ":")))

;; ── Core IPv6 Dissector ───────────────────────────────────────────────────

(def (dissect-ipv6 buffer)
  "Parse IPv6 message from bytevector
   Returns (ok fields) or (err message)

   Structure (40 bytes minimum):
   [0:4)   Version (4 bits), Traffic Class (8 bits), Flow Label (20 bits)
   [4:6)   Payload Length (16 bits)
   [6]     Next Header (8 bits)
   [7]     Hop Limit (8 bits)
   [8:24)  Source Address (128 bits)
   [24:40) Destination Address (128 bits)
   [40:)   Payload (variable, length from Payload Length field)"

  (try
    ;; Validate minimum size
    (unwrap (validate (>= (bytevector-length buffer) 40)
                         "IPv6 header too short (< 40 bytes)")))

    (let* (;; First 4 bytes contain version, traffic class, flow label
           (bytes0-3-res (read-u32be buffer 0))
           (bytes0-3 (unwrap bytes0-3-res))

           (version (extract-bits bytes0-3 #xF0000000 28))
           (traffic-class (extract-bits bytes0-3 #x0FF00000 20))
           (flow-label (extract-bits bytes0-3 #x000FFFFF 0))

           (payload-len-res (read-u16be buffer 4))
           (payload-len (unwrap payload-len-res))

           (next-hdr-res (read-u8 buffer 6))
           (next-hdr (unwrap next-hdr-res))

           (hop-limit-res (read-u8 buffer 7))
           (hop-limit (unwrap hop-limit-res))

           (src-addr (unwrap (slice buffer 8 16)))
           (dst-addr (unwrap (slice buffer 24 16)))

           (payload (unwrap (slice buffer 40
                                   (min payload-len
                                        (max 0 (- (bytevector-length buffer) 40)))))))

      (ok `((version . ,version)
            (traffic-class . ((raw . ,traffic-class)
                             (formatted . ,(format-ipv6-traffic-class traffic-class))))
            (flow-label . ((raw . ,flow-label)
                          (formatted . ,(fmt-hex flow-label))))
            (payload-length . ,payload-len)
            (next-header . ((raw . ,next-hdr)
                           (formatted . ,(format-next-header next-hdr))
                           (next-protocol . ,(ip-protocol->protocol next-hdr))))
            (hop-limit . ,hop-limit)
            (source-address . ((raw . ,src-addr)
                              (formatted . ,(fmt-ipv6-address src-addr))))
            (destination-address . ((raw . ,dst-addr)
                                   (formatted . ,(fmt-ipv6-address dst-addr))))
            (payload . ,payload))))

    ;; Error handling
    (catch (e)
      (err (str "IPv6 parse error: " e)))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-ipv6: main entry point
;; format-next-header: next header formatter
;; format-ipv6-traffic-class: traffic class formatter
;; fmt-ipv6-address: IPv6 address formatter
