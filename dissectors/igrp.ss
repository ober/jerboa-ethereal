;; packet-igrp.c
;; Routines for IGRP dissection
;; Copyright 2000, Paul Ionescu <paul@acorp.ro>
;;
;; See
;;
;; http://www.cisco.com/en/US/tech/tk365/technologies_white_paper09186a00800c8ae1.shtml
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-syslog.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/igrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-igrp.c

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
(def (dissect-igrp buffer)
  "Cisco Interior Gateway Routing Protocol"
  (try
    (let* (
           (command (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (update (unwrap (read-u8 buffer 1)))
           (as (unwrap (read-u16be buffer 2)))
           (interior-routes (unwrap (read-u16be buffer 4)))
           (system-routes (unwrap (read-u16be buffer 6)))
           (exterior-routes (unwrap (read-u16be buffer 8)))
           )

      (ok (list
        (cons 'command (list (cons 'raw command) (cons 'formatted (number->string command))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'update (list (cons 'raw update) (cons 'formatted (number->string update))))
        (cons 'as (list (cons 'raw as) (cons 'formatted (number->string as))))
        (cons 'interior-routes (list (cons 'raw interior-routes) (cons 'formatted (number->string interior-routes))))
        (cons 'system-routes (list (cons 'raw system-routes) (cons 'formatted (number->string system-routes))))
        (cons 'exterior-routes (list (cons 'raw exterior-routes) (cons 'formatted (number->string exterior-routes))))
        )))

    (catch (e)
      (err (str "IGRP parse error: " e)))))

;; dissect-igrp: parse IGRP from bytevector
;; Returns (ok fields-alist) or (err message)