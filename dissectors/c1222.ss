;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/c1222.ss
;; Auto-generated from wireshark/epan/dissectors/packet-c1222.c

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
(def (dissect-c1222 buffer)
  "ANSI C12.22"
  (try
    (let* (
           (epsem-flags (unwrap (read-u8 buffer 0)))
           (epsem-flags-reserved (extract-bits epsem-flags 0x0 0))
           (epsem-flags-recovery (extract-bits epsem-flags 0x0 0))
           (epsem-flags-proxy (extract-bits epsem-flags 0x0 0))
           (epsem-flags-ed-class (extract-bits epsem-flags 0x0 0))
           (epsem-total (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'epsem-flags (list (cons 'raw epsem-flags) (cons 'formatted (fmt-hex epsem-flags))))
        (cons 'epsem-flags-reserved (list (cons 'raw epsem-flags-reserved) (cons 'formatted (if (= epsem-flags-reserved 0) "Not set" "Set"))))
        (cons 'epsem-flags-recovery (list (cons 'raw epsem-flags-recovery) (cons 'formatted (if (= epsem-flags-recovery 0) "Not set" "Set"))))
        (cons 'epsem-flags-proxy (list (cons 'raw epsem-flags-proxy) (cons 'formatted (if (= epsem-flags-proxy 0) "Not set" "Set"))))
        (cons 'epsem-flags-ed-class (list (cons 'raw epsem-flags-ed-class) (cons 'formatted (if (= epsem-flags-ed-class 0) "Not set" "Set"))))
        (cons 'epsem-total (list (cons 'raw epsem-total) (cons 'formatted (fmt-bytes epsem-total))))
        )))

    (catch (e)
      (err (str "C1222 parse error: " e)))))

;; dissect-c1222: parse C1222 from bytevector
;; Returns (ok fields-alist) or (err message)