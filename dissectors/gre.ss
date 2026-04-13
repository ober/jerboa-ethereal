;; packet-gre.c
;; Routines for the Generic Routing Encapsulation (GRE) protocol
;; Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gre.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gre.c
;; RFC 1701

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
(def (dissect-gre buffer)
  "Generic Routing Encapsulation"
  (try
    (let* (
           (flags-checksum (unwrap (read-u8 buffer 0)))
           (flags-routing (unwrap (read-u8 buffer 0)))
           (flags-key (unwrap (read-u8 buffer 0)))
           (flags-sequence-number (unwrap (read-u8 buffer 0)))
           (flags-strict-source-route (unwrap (read-u8 buffer 0)))
           (flags-recursion-control (unwrap (read-u16be buffer 0)))
           (flags-ack (unwrap (read-u8 buffer 0)))
           (flags-reserved-ppp (unwrap (read-u16be buffer 0)))
           (flags-reserved (unwrap (read-u16be buffer 0)))
           (offset (unwrap (read-u16be buffer 6)))
           (key-payload-length (unwrap (read-u16be buffer 8)))
           (key-call-id (unwrap (read-u16be buffer 10)))
           (key (unwrap (read-u32be buffer 12)))
           (sequence-number (unwrap (read-u32be buffer 16)))
           (ack-number (unwrap (read-u32be buffer 20)))
           (routing-address-family (unwrap (read-u16be buffer 24)))
           (routing-sre-offset (unwrap (read-u8 buffer 26)))
           (routing-sre-length (unwrap (read-u8 buffer 27)))
           (routing-information (unwrap (slice buffer 28 1)))
           (flags-and-version (unwrap (read-u16be buffer 29)))
           )

      (ok (list
        (cons 'flags-checksum (list (cons 'raw flags-checksum) (cons 'formatted (if (= flags-checksum 0) "False" "True"))))
        (cons 'flags-routing (list (cons 'raw flags-routing) (cons 'formatted (if (= flags-routing 0) "False" "True"))))
        (cons 'flags-key (list (cons 'raw flags-key) (cons 'formatted (if (= flags-key 0) "False" "True"))))
        (cons 'flags-sequence-number (list (cons 'raw flags-sequence-number) (cons 'formatted (if (= flags-sequence-number 0) "False" "True"))))
        (cons 'flags-strict-source-route (list (cons 'raw flags-strict-source-route) (cons 'formatted (if (= flags-strict-source-route 0) "False" "True"))))
        (cons 'flags-recursion-control (list (cons 'raw flags-recursion-control) (cons 'formatted (number->string flags-recursion-control))))
        (cons 'flags-ack (list (cons 'raw flags-ack) (cons 'formatted (if (= flags-ack 0) "False" "True"))))
        (cons 'flags-reserved-ppp (list (cons 'raw flags-reserved-ppp) (cons 'formatted (number->string flags-reserved-ppp))))
        (cons 'flags-reserved (list (cons 'raw flags-reserved) (cons 'formatted (number->string flags-reserved))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'key-payload-length (list (cons 'raw key-payload-length) (cons 'formatted (number->string key-payload-length))))
        (cons 'key-call-id (list (cons 'raw key-call-id) (cons 'formatted (number->string key-call-id))))
        (cons 'key (list (cons 'raw key) (cons 'formatted (fmt-hex key))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'ack-number (list (cons 'raw ack-number) (cons 'formatted (number->string ack-number))))
        (cons 'routing-address-family (list (cons 'raw routing-address-family) (cons 'formatted (number->string routing-address-family))))
        (cons 'routing-sre-offset (list (cons 'raw routing-sre-offset) (cons 'formatted (number->string routing-sre-offset))))
        (cons 'routing-sre-length (list (cons 'raw routing-sre-length) (cons 'formatted (number->string routing-sre-length))))
        (cons 'routing-information (list (cons 'raw routing-information) (cons 'formatted (fmt-bytes routing-information))))
        (cons 'flags-and-version (list (cons 'raw flags-and-version) (cons 'formatted (fmt-hex flags-and-version))))
        )))

    (catch (e)
      (err (str "GRE parse error: " e)))))

;; dissect-gre: parse GRE from bytevector
;; Returns (ok fields-alist) or (err message)