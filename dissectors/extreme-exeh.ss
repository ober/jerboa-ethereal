;; packet-extreme-exeh.c
;; Routines for the disassembly of Extreme Networks internal
;; Ethernet capture headers
;;
;; Copyright 2021 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/extreme-exeh.ss
;; Auto-generated from wireshark/epan/dissectors/packet-extreme_exeh.c

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
(def (dissect-extreme-exeh buffer)
  "EXtreme extra Eth Header"
  (try
    (let* (
           (module1 (unwrap (read-u16be buffer 2)))
           (port1 (unwrap (read-u16be buffer 4)))
           (module2 (unwrap (read-u16be buffer 6)))
           (port2 (unwrap (read-u16be buffer 8)))
           (unknown-10-16 (unwrap (slice buffer 10 7)))
           (unknown-17-0xfd (unwrap (read-u8 buffer 17)))
           (unknown-17-0x02 (unwrap (read-u8 buffer 17)))
           (unknown-18-21 (unwrap (slice buffer 18 4)))
           (vlan (unwrap (read-u16be buffer 26)))
           (unknown-28-29 (unwrap (slice buffer 28 2)))
           (unknown-32-33 (unwrap (slice buffer 32 2)))
           (etype (unwrap (read-u16be buffer 34)))
           (etypelen (unwrap (read-u16be buffer 34)))
           (etypedata (unwrap (read-u16be buffer 34)))
           (unknown-00-01 (unwrap (slice buffer 36 2)))
           )

      (ok (list
        (cons 'module1 (list (cons 'raw module1) (cons 'formatted (number->string module1))))
        (cons 'port1 (list (cons 'raw port1) (cons 'formatted (number->string port1))))
        (cons 'module2 (list (cons 'raw module2) (cons 'formatted (number->string module2))))
        (cons 'port2 (list (cons 'raw port2) (cons 'formatted (number->string port2))))
        (cons 'unknown-10-16 (list (cons 'raw unknown-10-16) (cons 'formatted (fmt-bytes unknown-10-16))))
        (cons 'unknown-17-0xfd (list (cons 'raw unknown-17-0xfd) (cons 'formatted (fmt-hex unknown-17-0xfd))))
        (cons 'unknown-17-0x02 (list (cons 'raw unknown-17-0x02) (cons 'formatted (if (= unknown-17-0x02 0) "False" "True"))))
        (cons 'unknown-18-21 (list (cons 'raw unknown-18-21) (cons 'formatted (fmt-bytes unknown-18-21))))
        (cons 'vlan (list (cons 'raw vlan) (cons 'formatted (number->string vlan))))
        (cons 'unknown-28-29 (list (cons 'raw unknown-28-29) (cons 'formatted (fmt-bytes unknown-28-29))))
        (cons 'unknown-32-33 (list (cons 'raw unknown-32-33) (cons 'formatted (fmt-bytes unknown-32-33))))
        (cons 'etype (list (cons 'raw etype) (cons 'formatted (fmt-hex etype))))
        (cons 'etypelen (list (cons 'raw etypelen) (cons 'formatted (number->string etypelen))))
        (cons 'etypedata (list (cons 'raw etypedata) (cons 'formatted (fmt-hex etypedata))))
        (cons 'unknown-00-01 (list (cons 'raw unknown-00-01) (cons 'formatted (fmt-bytes unknown-00-01))))
        )))

    (catch (e)
      (err (str "EXTREME-EXEH parse error: " e)))))

;; dissect-extreme-exeh: parse EXTREME-EXEH from bytevector
;; Returns (ok fields-alist) or (err message)