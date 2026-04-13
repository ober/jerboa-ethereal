;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/sv.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sv.c

(import (jerboa prelude))

;; ── Protocol Helpers ─────────────────────────────────────────────────
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u24be buf offset)
  (if (> (+ offset 3) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (+ (* (bytevector-u8-ref buf offset) 65536)
             (* (bytevector-u8-ref buf (+ offset 1)) 256)
             (bytevector-u8-ref buf (+ offset 2))))))

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

(def (read-u64be buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness big)))))

(def (read-u64le buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

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

(def (fmt-oct val)
  (str "0" (number->string val 8)))

(def (fmt-port port)
  (number->string port))

(def (fmt-bytes bv)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bv))
    " "))

(def (fmt-ipv6-address bytes)
  (let loop ((i 0) (parts '()))
    (if (>= i 16)
        (string-join (reverse parts) ":")
        (loop (+ i 2)
              (cons (let ((w (+ (* (bytevector-u8-ref bytes i) 256)
                                (bytevector-u8-ref bytes (+ i 1)))))
                      (number->string w 16))
                    parts)))))

;; ── Dissector ──────────────────────────────────────────────────────
(def (dissect-sv buffer)
  "IEC61850 Sampled Values"
  (try
    (let* (
           (phsmeas-q (unwrap (read-u32be buffer 0)))
           (phsmeas-q-overflow (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-outofrange (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-badreference (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-oscillatory (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-failure (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-olddata (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-inconsistent (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-inaccurate (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-test (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-operatorblocked (extract-bits phsmeas-q 0x0 0))
           (phsmeas-q-derived (extract-bits phsmeas-q 0x0 0))
           (appid (unwrap (read-u16be buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (reserve1 (unwrap (read-u16be buffer 0)))
           (reserve1-s-bit (extract-bits reserve1 0x0 0))
           (reserve2 (unwrap (read-u16be buffer 0)))
           (gmidentity (unwrap (read-u64be buffer 16)))
           (gmidentity-manuf (unwrap (slice buffer 16 3)))
           (phmeas-instmag-i (unwrap (read-u32be buffer 24)))
           )

      (ok (list
        (cons 'phsmeas-q (list (cons 'raw phsmeas-q) (cons 'formatted (fmt-hex phsmeas-q))))
        (cons 'phsmeas-q-overflow (list (cons 'raw phsmeas-q-overflow) (cons 'formatted (if (= phsmeas-q-overflow 0) "Not set" "Set"))))
        (cons 'phsmeas-q-outofrange (list (cons 'raw phsmeas-q-outofrange) (cons 'formatted (if (= phsmeas-q-outofrange 0) "Not set" "Set"))))
        (cons 'phsmeas-q-badreference (list (cons 'raw phsmeas-q-badreference) (cons 'formatted (if (= phsmeas-q-badreference 0) "Not set" "Set"))))
        (cons 'phsmeas-q-oscillatory (list (cons 'raw phsmeas-q-oscillatory) (cons 'formatted (if (= phsmeas-q-oscillatory 0) "Not set" "Set"))))
        (cons 'phsmeas-q-failure (list (cons 'raw phsmeas-q-failure) (cons 'formatted (if (= phsmeas-q-failure 0) "Not set" "Set"))))
        (cons 'phsmeas-q-olddata (list (cons 'raw phsmeas-q-olddata) (cons 'formatted (if (= phsmeas-q-olddata 0) "Not set" "Set"))))
        (cons 'phsmeas-q-inconsistent (list (cons 'raw phsmeas-q-inconsistent) (cons 'formatted (if (= phsmeas-q-inconsistent 0) "Not set" "Set"))))
        (cons 'phsmeas-q-inaccurate (list (cons 'raw phsmeas-q-inaccurate) (cons 'formatted (if (= phsmeas-q-inaccurate 0) "Not set" "Set"))))
        (cons 'phsmeas-q-test (list (cons 'raw phsmeas-q-test) (cons 'formatted (if (= phsmeas-q-test 0) "Not set" "Set"))))
        (cons 'phsmeas-q-operatorblocked (list (cons 'raw phsmeas-q-operatorblocked) (cons 'formatted (if (= phsmeas-q-operatorblocked 0) "Not set" "Set"))))
        (cons 'phsmeas-q-derived (list (cons 'raw phsmeas-q-derived) (cons 'formatted (if (= phsmeas-q-derived 0) "Not set" "Set"))))
        (cons 'appid (list (cons 'raw appid) (cons 'formatted (fmt-hex appid))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'reserve1 (list (cons 'raw reserve1) (cons 'formatted (fmt-hex reserve1))))
        (cons 'reserve1-s-bit (list (cons 'raw reserve1-s-bit) (cons 'formatted (if (= reserve1-s-bit 0) "Not set" "Set"))))
        (cons 'reserve2 (list (cons 'raw reserve2) (cons 'formatted (fmt-hex reserve2))))
        (cons 'gmidentity (list (cons 'raw gmidentity) (cons 'formatted (fmt-hex gmidentity))))
        (cons 'gmidentity-manuf (list (cons 'raw gmidentity-manuf) (cons 'formatted (fmt-bytes gmidentity-manuf))))
        (cons 'phmeas-instmag-i (list (cons 'raw phmeas-instmag-i) (cons 'formatted (number->string phmeas-instmag-i))))
        )))

    (catch (e)
      (err (str "SV parse error: " e)))))

;; dissect-sv: parse SV from bytevector
;; Returns (ok fields-alist) or (err message)