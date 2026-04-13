;; packet-rk512.c
;; Routines for RK 512 protocol dissection
;; Copyright 2022 Michael Mann
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rk512.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rk512.c

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
(def (dissect-rk512 buffer)
  "SICK RK512"
  (try
    (let* (
           (reply-header (unwrap (read-u32be buffer 0)))
           (size (unwrap (read-u16be buffer 6)))
           (coordination-flag (unwrap (read-u8 buffer 8)))
           (scan-number (unwrap (read-u32be buffer 14)))
           (telegram-number (unwrap (read-u16be buffer 18)))
           (measurement-data-type (unwrap (read-u16be buffer 22)))
           (measurement-data (unwrap (read-u16be buffer 24)))
           (measurement-data-distance (extract-bits measurement-data 0x1FFF 0))
           (measurement-data-flags (extract-bits measurement-data 0xE000 13))
           )

      (ok (list
        (cons 'reply-header (list (cons 'raw reply-header) (cons 'formatted (fmt-hex reply-header))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'coordination-flag (list (cons 'raw coordination-flag) (cons 'formatted (fmt-hex coordination-flag))))
        (cons 'scan-number (list (cons 'raw scan-number) (cons 'formatted (number->string scan-number))))
        (cons 'telegram-number (list (cons 'raw telegram-number) (cons 'formatted (number->string telegram-number))))
        (cons 'measurement-data-type (list (cons 'raw measurement-data-type) (cons 'formatted (fmt-hex measurement-data-type))))
        (cons 'measurement-data (list (cons 'raw measurement-data) (cons 'formatted (fmt-hex measurement-data))))
        (cons 'measurement-data-distance (list (cons 'raw measurement-data-distance) (cons 'formatted (if (= measurement-data-distance 0) "Not set" "Set"))))
        (cons 'measurement-data-flags (list (cons 'raw measurement-data-flags) (cons 'formatted (if (= measurement-data-flags 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "RK512 parse error: " e)))))

;; dissect-rk512: parse RK512 from bytevector
;; Returns (ok fields-alist) or (err message)