;; packet-xip-serval.c
;; Routines for XIP Serval dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Serval is a service-centric architecture that has been ported to XIA to
;; allow applications to communicate using service names.
;;

;; jerboa-ethereal/dissectors/xip-serval.ss
;; Auto-generated from wireshark/epan/dissectors/packet-xip_serval.c

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
(def (dissect-xip-serval buffer)
  "XIP Serval"
  (try
    (let* (
           (serval-ext-type (unwrap (read-u8 buffer 0)))
           (serval-cext-flags (unwrap (read-u8 buffer 0)))
           (serval-cext-syn (extract-bits serval-cext-flags 0x80 7))
           (serval-cext-rsyn (extract-bits serval-cext-flags 0x40 6))
           (serval-cext-ack (extract-bits serval-cext-flags 0x20 5))
           (serval-cext-nack (extract-bits serval-cext-flags 0x10 4))
           (serval-cext-rst (extract-bits serval-cext-flags 0x8 3))
           (serval-cext-fin (extract-bits serval-cext-flags 0x4 2))
           (serval-cext-verno (unwrap (read-u32be buffer 0)))
           (serval-cext-ackno (unwrap (read-u32be buffer 4)))
           )

      (ok (list
        (cons 'serval-ext-type (list (cons 'raw serval-ext-type) (cons 'formatted (number->string serval-ext-type))))
        (cons 'serval-cext-flags (list (cons 'raw serval-cext-flags) (cons 'formatted (fmt-hex serval-cext-flags))))
        (cons 'serval-cext-syn (list (cons 'raw serval-cext-syn) (cons 'formatted (if (= serval-cext-syn 0) "Not set" "Set"))))
        (cons 'serval-cext-rsyn (list (cons 'raw serval-cext-rsyn) (cons 'formatted (if (= serval-cext-rsyn 0) "Not set" "Set"))))
        (cons 'serval-cext-ack (list (cons 'raw serval-cext-ack) (cons 'formatted (if (= serval-cext-ack 0) "Not set" "Set"))))
        (cons 'serval-cext-nack (list (cons 'raw serval-cext-nack) (cons 'formatted (if (= serval-cext-nack 0) "Not set" "Set"))))
        (cons 'serval-cext-rst (list (cons 'raw serval-cext-rst) (cons 'formatted (if (= serval-cext-rst 0) "Not set" "Set"))))
        (cons 'serval-cext-fin (list (cons 'raw serval-cext-fin) (cons 'formatted (if (= serval-cext-fin 0) "Not set" "Set"))))
        (cons 'serval-cext-verno (list (cons 'raw serval-cext-verno) (cons 'formatted (number->string serval-cext-verno))))
        (cons 'serval-cext-ackno (list (cons 'raw serval-cext-ackno) (cons 'formatted (number->string serval-cext-ackno))))
        )))

    (catch (e)
      (err (str "XIP-SERVAL parse error: " e)))))

;; dissect-xip-serval: parse XIP-SERVAL from bytevector
;; Returns (ok fields-alist) or (err message)