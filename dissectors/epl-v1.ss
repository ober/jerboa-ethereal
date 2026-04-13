;; packet-epl_v1.c
;; Routines for "ETHERNET Powerlink 1.0" dissection
;; (ETHERNET Powerlink Powerlink WhitePaper V0006-B)
;;
;; Copyright (c) 2006: Zurich University of Applied Sciences Winterthur (ZHW)
;; Institute of Embedded Systems (InES)
;; http://ines.zhwin.ch
;;
;; - Dominic Bechaz <bdo@zhwin.ch>
;; - David Buechi <bhd@zhwin.ch>
;;
;;
;; A dissector for:
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/epl-v1.ss
;; Auto-generated from wireshark/epan/dissectors/packet-epl_v1.c

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
(def (dissect-epl-v1 buffer)
  "ETHERNET Powerlink V1.0"
  (try
    (let* (
           (v1-soc-ps (unwrap (read-u8 buffer 0)))
           (v1-dest (unwrap (read-u8 buffer 1)))
           (v1-src (unwrap (read-u8 buffer 2)))
           (v1-soc-net-time (unwrap (read-u32be buffer 3)))
           (v1-soc-powerlink-cycle-time (unwrap (read-u32be buffer 7)))
           (v1-soc-net-command-parameter (unwrap (slice buffer 11 32)))
           (v1-eoc-net-command-parameter (unwrap (slice buffer 52 32)))
           (v1-preq-ms (unwrap (read-u8 buffer 84)))
           (v1-preq-rd (unwrap (read-u8 buffer 84)))
           (v1-preq-poll-size-out (unwrap (read-u16be buffer 85)))
           (v1-preq-out-data (unwrap (slice buffer 91 1)))
           (v1-pres-ms (unwrap (read-u8 buffer 91)))
           (v1-pres-ex (unwrap (read-u8 buffer 91)))
           (v1-pres-rs (unwrap (read-u8 buffer 91)))
           (v1-pres-wa (unwrap (read-u8 buffer 91)))
           (v1-pres-er (unwrap (read-u8 buffer 91)))
           (v1-pres-rd (unwrap (read-u8 buffer 91)))
           (v1-pres-poll-size-in (unwrap (read-u16be buffer 92)))
           (v1-pres-in-data (unwrap (slice buffer 98 1)))
           (v1-asnd-size (unwrap (read-u16be buffer 100)))
           (v1-asnd-node-id (unwrap (read-u32be buffer 102)))
           (v1-asnd-hardware-revision (unwrap (read-u32be buffer 106)))
           (v1-asnd-firmware-version (unwrap (read-u32be buffer 110)))
           (v1-asnd-device-variant (unwrap (read-u32be buffer 114)))
           (v1-asnd-poll-in-size (unwrap (read-u32be buffer 118)))
           (v1-asnd-poll-out-size (unwrap (read-u32be buffer 122)))
           (v1-asnd-data (unwrap (slice buffer 126 1)))
           (v1-soc-ms (unwrap (read-u8 buffer 127)))
           )

      (ok (list
        (cons 'v1-soc-ps (list (cons 'raw v1-soc-ps) (cons 'formatted (number->string v1-soc-ps))))
        (cons 'v1-dest (list (cons 'raw v1-dest) (cons 'formatted (number->string v1-dest))))
        (cons 'v1-src (list (cons 'raw v1-src) (cons 'formatted (number->string v1-src))))
        (cons 'v1-soc-net-time (list (cons 'raw v1-soc-net-time) (cons 'formatted (number->string v1-soc-net-time))))
        (cons 'v1-soc-powerlink-cycle-time (list (cons 'raw v1-soc-powerlink-cycle-time) (cons 'formatted (number->string v1-soc-powerlink-cycle-time))))
        (cons 'v1-soc-net-command-parameter (list (cons 'raw v1-soc-net-command-parameter) (cons 'formatted (fmt-bytes v1-soc-net-command-parameter))))
        (cons 'v1-eoc-net-command-parameter (list (cons 'raw v1-eoc-net-command-parameter) (cons 'formatted (fmt-bytes v1-eoc-net-command-parameter))))
        (cons 'v1-preq-ms (list (cons 'raw v1-preq-ms) (cons 'formatted (number->string v1-preq-ms))))
        (cons 'v1-preq-rd (list (cons 'raw v1-preq-rd) (cons 'formatted (number->string v1-preq-rd))))
        (cons 'v1-preq-poll-size-out (list (cons 'raw v1-preq-poll-size-out) (cons 'formatted (number->string v1-preq-poll-size-out))))
        (cons 'v1-preq-out-data (list (cons 'raw v1-preq-out-data) (cons 'formatted (fmt-bytes v1-preq-out-data))))
        (cons 'v1-pres-ms (list (cons 'raw v1-pres-ms) (cons 'formatted (number->string v1-pres-ms))))
        (cons 'v1-pres-ex (list (cons 'raw v1-pres-ex) (cons 'formatted (number->string v1-pres-ex))))
        (cons 'v1-pres-rs (list (cons 'raw v1-pres-rs) (cons 'formatted (number->string v1-pres-rs))))
        (cons 'v1-pres-wa (list (cons 'raw v1-pres-wa) (cons 'formatted (number->string v1-pres-wa))))
        (cons 'v1-pres-er (list (cons 'raw v1-pres-er) (cons 'formatted (number->string v1-pres-er))))
        (cons 'v1-pres-rd (list (cons 'raw v1-pres-rd) (cons 'formatted (number->string v1-pres-rd))))
        (cons 'v1-pres-poll-size-in (list (cons 'raw v1-pres-poll-size-in) (cons 'formatted (number->string v1-pres-poll-size-in))))
        (cons 'v1-pres-in-data (list (cons 'raw v1-pres-in-data) (cons 'formatted (fmt-bytes v1-pres-in-data))))
        (cons 'v1-asnd-size (list (cons 'raw v1-asnd-size) (cons 'formatted (number->string v1-asnd-size))))
        (cons 'v1-asnd-node-id (list (cons 'raw v1-asnd-node-id) (cons 'formatted (number->string v1-asnd-node-id))))
        (cons 'v1-asnd-hardware-revision (list (cons 'raw v1-asnd-hardware-revision) (cons 'formatted (number->string v1-asnd-hardware-revision))))
        (cons 'v1-asnd-firmware-version (list (cons 'raw v1-asnd-firmware-version) (cons 'formatted (number->string v1-asnd-firmware-version))))
        (cons 'v1-asnd-device-variant (list (cons 'raw v1-asnd-device-variant) (cons 'formatted (number->string v1-asnd-device-variant))))
        (cons 'v1-asnd-poll-in-size (list (cons 'raw v1-asnd-poll-in-size) (cons 'formatted (number->string v1-asnd-poll-in-size))))
        (cons 'v1-asnd-poll-out-size (list (cons 'raw v1-asnd-poll-out-size) (cons 'formatted (number->string v1-asnd-poll-out-size))))
        (cons 'v1-asnd-data (list (cons 'raw v1-asnd-data) (cons 'formatted (fmt-bytes v1-asnd-data))))
        (cons 'v1-soc-ms (list (cons 'raw v1-soc-ms) (cons 'formatted (number->string v1-soc-ms))))
        )))

    (catch (e)
      (err (str "EPL-V1 parse error: " e)))))

;; dissect-epl-v1: parse EPL-V1 from bytevector
;; Returns (ok fields-alist) or (err message)