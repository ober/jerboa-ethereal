;; jerboa-ethereal/dissectors/ntp.ss
;; RFC 5905: Network Time Protocol (NTP) Version 4
;;
;; Fixed 48-byte header structure for NTP packets
;; Used for time synchronization over UDP

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



;; ── NTP Mode Formatter ─────────────────────────────────────────────────────

(def (format-ntp-mode mode)
  "Format NTP mode field (0-7)"
  (case mode
    ((0) "Reserved")
    ((1) "Symmetric Active")
    ((2) "Symmetric Passive")
    ((3) "Client")
    ((4) "Server")
    ((5) "Broadcast")
    ((6) "NTP Control Message")
    ((7) "Private Use")
    (else (str "Mode " mode))))

(def (format-ntp-stratum stratum)
  "Format NTP stratum field"
  (case stratum
    ((0) "Kiss-o'-Death")
    ((1) "Primary Reference")
    ((2-15) (str "Secondary (stratum " stratum ")"))
    ((16) "Unsynchronized")
    (else (str "Stratum " stratum))))

(def (format-leap-indicator li)
  "Format leap second indicator"
  (case li
    ((0) "No warning")
    ((1) "Last minute of day has 61 seconds")
    ((2) "Last minute of day has 59 seconds")
    ((3) "Clock is unsynchronized")
    (else (str "LI " li))))

;; ── Core NTP Dissector ────────────────────────────────────────────────────

(def (dissect-ntp buffer)
  "Parse NTP message from bytevector
   Returns (ok fields) or (err message)

   Structure (48 bytes):
   [0]     LI (2), Version (3), Mode (3)
   [1]     Stratum (8)
   [2]     Poll interval (8)
   [3]     Precision (8)
   [4:8)   Root delay (32-bit fixed-point)
   [8:12)  Root dispersion (32-bit fixed-point)
   [12:16) Reference ID (32-bit)
   [16:24) Reference timestamp (64-bit)
   [24:32) Originate timestamp (64-bit)
   [32:40) Receive timestamp (64-bit)
   [40:48) Transmit timestamp (64-bit)"

  (try
    ;; Validate minimum size
    (unwrap (validate (>= (bytevector-length buffer) 48)
                         "NTP packet too short (< 48 bytes)")))

    (let* ((byte0-res (read-u8 buffer 0))
           (byte0 (unwrap byte0-res))
           (li (extract-bits byte0 #xC0 6))
           (version (extract-bits byte0 #x38 3))
           (mode (extract-bits byte0 #x07 0))

           (stratum-res (read-u8 buffer 1))
           (stratum (unwrap stratum-res))

           (poll-res (read-u8 buffer 2))
           (poll (unwrap poll-res))

           (precision-res (read-u8 buffer 3))
           (precision (unwrap precision-res))

           (root-delay-res (read-u32be buffer 4))
           (root-delay (unwrap root-delay-res))

           (root-disp-res (read-u32be buffer 8))
           (root-disp (unwrap root-disp-res))

           (ref-id-res (read-u32be buffer 12))
           (ref-id (unwrap ref-id-res))

           (ref-ts-res (read-u32be buffer 16))
           (ref-ts (unwrap ref-ts-res))

           (orig-ts-res (read-u32be buffer 24))
           (orig-ts (unwrap orig-ts-res))

           (recv-ts-res (read-u32be buffer 32))
           (recv-ts (unwrap recv-ts-res))

           (xmit-ts-res (read-u32be buffer 40))
           (xmit-ts (unwrap xmit-ts-res)))

      (ok `((leap-indicator . ((raw . ,li)
                              (formatted . ,(format-leap-indicator li))))
            (version . ,version)
            (mode . ((raw . ,mode)
                    (formatted . ,(format-ntp-mode mode))))
            (stratum . ((raw . ,stratum)
                       (formatted . ,(format-ntp-stratum stratum))))
            (poll-interval . ,poll)
            (precision . ,precision)
            (root-delay . ((raw . ,root-delay)
                          (formatted . ,(fmt-hex root-delay))))
            (root-dispersion . ((raw . ,root-disp)
                               (formatted . ,(fmt-hex root-disp))))
            (reference-id . ((raw . ,ref-id)
                            (formatted . ,(fmt-hex ref-id))))
            (reference-timestamp . ((raw . ,ref-ts)
                                   (formatted . ,(fmt-hex ref-ts))))
            (originate-timestamp . ((raw . ,orig-ts)
                                   (formatted . ,(fmt-hex orig-ts))))
            (receive-timestamp . ((raw . ,recv-ts)
                                 (formatted . ,(fmt-hex recv-ts))))
            (transmit-timestamp . ((raw . ,xmit-ts)
                                  (formatted . ,(fmt-hex xmit-ts)))))))

    ;; Error handling
    (catch (e)
      (err (str "NTP parse error: " e)))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-ntp: main entry point
;; format-ntp-mode: mode formatter
;; format-ntp-stratum: stratum formatter
;; format-leap-indicator: leap second indicator formatter
