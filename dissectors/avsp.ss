;; packet-avsp.c
;; Arista Vendor Specific ethertype Protocol (AVSP)
;;
;; Copyright (c) 2018-2022 by Arista Networks
;; Author: Nikhil AP <nikhilap@arista.com>
;; Author: PMcL <peterm@arista.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/avsp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-avsp.c

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
(def (dissect-avsp buffer)
  "Arista Vendor Specific Protocol"
  (try
    (let* (
           (ts-64-sec (unwrap (read-u32be buffer 12)))
           (ts-64-ns (unwrap (read-u32be buffer 16)))
           (ts-48-sec (unwrap (read-u16be buffer 26)))
           (ts-48-ns (unwrap (read-u32be buffer 28)))
           (greentap-sec (unwrap (read-u16be buffer 42)))
           (greentap-ns (unwrap (read-u32be buffer 44)))
           (greent-session (unwrap (read-u16be buffer 52)))
           (greent-flags (unwrap (read-u8 buffer 54)))
           (greent-sample-count (unwrap (read-u8 buffer 55)))
           (greent-sample-len (unwrap (read-u16be buffer 56)))
           (greent-sample-sec (unwrap (read-u16be buffer 58)))
           (greent-sample-ns (unwrap (read-u32be buffer 60)))
           (greent-sample-ingress (unwrap (read-u32be buffer 64)))
           (greent-sample-egress (unwrap (read-u32be buffer 68)))
           (greent-sample-rate (unwrap (read-u16be buffer 72)))
           (greent-sample-sum (unwrap (read-u16be buffer 74)))
           (greent-sample-data (unwrap (slice buffer 76 1)))
           (dzgre-a-switch (unwrap (read-u16be buffer 78)))
           (dzgre-a-port (unwrap (read-u16be buffer 80)))
           (dzgre-a-policy (unwrap (read-u16be buffer 82)))
           (dzgre-a-reserved (unwrap (read-u16be buffer 84)))
           (dzgre-b-port (unwrap (read-u16be buffer 88)))
           (dzgre-b-policy (unwrap (read-u16be buffer 90)))
           (dzgre-ts-reserved (unwrap (read-u16be buffer 100)))
           (dzgre-ts-switch (unwrap (read-u16be buffer 110)))
           (dzgre-ts-port (unwrap (read-u16be buffer 112)))
           (dzgre-ts-policy (unwrap (read-u16be buffer 114)))
           (dzgre-ts-sec (unwrap (read-u32be buffer 118)))
           (dzgre-ts-ns (unwrap (read-u32be buffer 122)))
           (tgen-hdr-seq-num (unwrap (read-u16be buffer 130)))
           (tgen-hdr-payload-len (unwrap (read-u16be buffer 132)))
           )

      (ok (list
        (cons 'ts-64-sec (list (cons 'raw ts-64-sec) (cons 'formatted (number->string ts-64-sec))))
        (cons 'ts-64-ns (list (cons 'raw ts-64-ns) (cons 'formatted (number->string ts-64-ns))))
        (cons 'ts-48-sec (list (cons 'raw ts-48-sec) (cons 'formatted (number->string ts-48-sec))))
        (cons 'ts-48-ns (list (cons 'raw ts-48-ns) (cons 'formatted (number->string ts-48-ns))))
        (cons 'greentap-sec (list (cons 'raw greentap-sec) (cons 'formatted (number->string greentap-sec))))
        (cons 'greentap-ns (list (cons 'raw greentap-ns) (cons 'formatted (number->string greentap-ns))))
        (cons 'greent-session (list (cons 'raw greent-session) (cons 'formatted (number->string greent-session))))
        (cons 'greent-flags (list (cons 'raw greent-flags) (cons 'formatted (fmt-hex greent-flags))))
        (cons 'greent-sample-count (list (cons 'raw greent-sample-count) (cons 'formatted (number->string greent-sample-count))))
        (cons 'greent-sample-len (list (cons 'raw greent-sample-len) (cons 'formatted (number->string greent-sample-len))))
        (cons 'greent-sample-sec (list (cons 'raw greent-sample-sec) (cons 'formatted (number->string greent-sample-sec))))
        (cons 'greent-sample-ns (list (cons 'raw greent-sample-ns) (cons 'formatted (number->string greent-sample-ns))))
        (cons 'greent-sample-ingress (list (cons 'raw greent-sample-ingress) (cons 'formatted (number->string greent-sample-ingress))))
        (cons 'greent-sample-egress (list (cons 'raw greent-sample-egress) (cons 'formatted (number->string greent-sample-egress))))
        (cons 'greent-sample-rate (list (cons 'raw greent-sample-rate) (cons 'formatted (number->string greent-sample-rate))))
        (cons 'greent-sample-sum (list (cons 'raw greent-sample-sum) (cons 'formatted (fmt-hex greent-sample-sum))))
        (cons 'greent-sample-data (list (cons 'raw greent-sample-data) (cons 'formatted (fmt-bytes greent-sample-data))))
        (cons 'dzgre-a-switch (list (cons 'raw dzgre-a-switch) (cons 'formatted (number->string dzgre-a-switch))))
        (cons 'dzgre-a-port (list (cons 'raw dzgre-a-port) (cons 'formatted (number->string dzgre-a-port))))
        (cons 'dzgre-a-policy (list (cons 'raw dzgre-a-policy) (cons 'formatted (number->string dzgre-a-policy))))
        (cons 'dzgre-a-reserved (list (cons 'raw dzgre-a-reserved) (cons 'formatted (fmt-hex dzgre-a-reserved))))
        (cons 'dzgre-b-port (list (cons 'raw dzgre-b-port) (cons 'formatted (number->string dzgre-b-port))))
        (cons 'dzgre-b-policy (list (cons 'raw dzgre-b-policy) (cons 'formatted (number->string dzgre-b-policy))))
        (cons 'dzgre-ts-reserved (list (cons 'raw dzgre-ts-reserved) (cons 'formatted (fmt-hex dzgre-ts-reserved))))
        (cons 'dzgre-ts-switch (list (cons 'raw dzgre-ts-switch) (cons 'formatted (number->string dzgre-ts-switch))))
        (cons 'dzgre-ts-port (list (cons 'raw dzgre-ts-port) (cons 'formatted (number->string dzgre-ts-port))))
        (cons 'dzgre-ts-policy (list (cons 'raw dzgre-ts-policy) (cons 'formatted (number->string dzgre-ts-policy))))
        (cons 'dzgre-ts-sec (list (cons 'raw dzgre-ts-sec) (cons 'formatted (number->string dzgre-ts-sec))))
        (cons 'dzgre-ts-ns (list (cons 'raw dzgre-ts-ns) (cons 'formatted (number->string dzgre-ts-ns))))
        (cons 'tgen-hdr-seq-num (list (cons 'raw tgen-hdr-seq-num) (cons 'formatted (number->string tgen-hdr-seq-num))))
        (cons 'tgen-hdr-payload-len (list (cons 'raw tgen-hdr-payload-len) (cons 'formatted (number->string tgen-hdr-payload-len))))
        )))

    (catch (e)
      (err (str "AVSP parse error: " e)))))

;; dissect-avsp: parse AVSP from bytevector
;; Returns (ok fields-alist) or (err message)