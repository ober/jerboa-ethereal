;; packet-maccontrol.c
;; Routines for MAC Control ethernet header disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/maccontrol.ss
;; Auto-generated from wireshark/epan/dissectors/packet-maccontrol.c

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
(def (dissect-maccontrol buffer)
  "MAC Control"
  (try
    (let* (
           (timestamp (unwrap (read-u32be buffer 2)))
           (pause-time (unwrap (read-u16be buffer 6)))
           (req-grants (unwrap (read-u8 buffer 6)))
           (port (unwrap (read-u16be buffer 6)))
           (time (unwrap (read-u16be buffer 8)))
           (grants (unwrap (read-u8 buffer 10)))
           (ack-port (unwrap (read-u16be buffer 10)))
           (ack-time (unwrap (read-u16be buffer 12)))
           (cbfc-enbv (unwrap (read-u16be buffer 12)))
           (cbfc-enbv-c0 (extract-bits cbfc-enbv 0x1 0))
           (cbfc-enbv-c1 (extract-bits cbfc-enbv 0x2 1))
           (cbfc-enbv-c2 (extract-bits cbfc-enbv 0x4 2))
           (cbfc-enbv-c3 (extract-bits cbfc-enbv 0x8 3))
           (cbfc-enbv-c4 (extract-bits cbfc-enbv 0x10 4))
           (cbfc-enbv-c5 (extract-bits cbfc-enbv 0x20 5))
           (cbfc-enbv-c6 (extract-bits cbfc-enbv 0x40 6))
           (cbfc-enbv-c7 (extract-bits cbfc-enbv 0x80 7))
           )

      (ok (list
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'pause-time (list (cons 'raw pause-time) (cons 'formatted (number->string pause-time))))
        (cons 'req-grants (list (cons 'raw req-grants) (cons 'formatted (number->string req-grants))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (number->string time))))
        (cons 'grants (list (cons 'raw grants) (cons 'formatted (number->string grants))))
        (cons 'ack-port (list (cons 'raw ack-port) (cons 'formatted (number->string ack-port))))
        (cons 'ack-time (list (cons 'raw ack-time) (cons 'formatted (number->string ack-time))))
        (cons 'cbfc-enbv (list (cons 'raw cbfc-enbv) (cons 'formatted (fmt-hex cbfc-enbv))))
        (cons 'cbfc-enbv-c0 (list (cons 'raw cbfc-enbv-c0) (cons 'formatted (if (= cbfc-enbv-c0 0) "Not set" "Set"))))
        (cons 'cbfc-enbv-c1 (list (cons 'raw cbfc-enbv-c1) (cons 'formatted (if (= cbfc-enbv-c1 0) "Not set" "Set"))))
        (cons 'cbfc-enbv-c2 (list (cons 'raw cbfc-enbv-c2) (cons 'formatted (if (= cbfc-enbv-c2 0) "Not set" "Set"))))
        (cons 'cbfc-enbv-c3 (list (cons 'raw cbfc-enbv-c3) (cons 'formatted (if (= cbfc-enbv-c3 0) "Not set" "Set"))))
        (cons 'cbfc-enbv-c4 (list (cons 'raw cbfc-enbv-c4) (cons 'formatted (if (= cbfc-enbv-c4 0) "Not set" "Set"))))
        (cons 'cbfc-enbv-c5 (list (cons 'raw cbfc-enbv-c5) (cons 'formatted (if (= cbfc-enbv-c5 0) "Not set" "Set"))))
        (cons 'cbfc-enbv-c6 (list (cons 'raw cbfc-enbv-c6) (cons 'formatted (if (= cbfc-enbv-c6 0) "Not set" "Set"))))
        (cons 'cbfc-enbv-c7 (list (cons 'raw cbfc-enbv-c7) (cons 'formatted (if (= cbfc-enbv-c7 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "MACCONTROL parse error: " e)))))

;; dissect-maccontrol: parse MACCONTROL from bytevector
;; Returns (ok fields-alist) or (err message)