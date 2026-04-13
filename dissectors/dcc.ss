;; packet-dcc.c
;; Routines for Distributed Checksum Clearinghouse packet dissection
;; DCC Home: http://www.rhyolite.com/anti-spam/dcc/
;;
;; Copyright 1999, Nathan Neulinger <nneul@umr.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-tftp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dcc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcc.c

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
(def (dissect-dcc buffer)
  "Distributed Checksum Clearinghouse protocol"
  (try
    (let* (
           (pkt-vers (unwrap (read-u16be buffer 2)))
           (clientid (unwrap (read-u32be buffer 4)))
           (opnums-host (unwrap (read-u32be buffer 8)))
           (opnums-pid (unwrap (read-u32be buffer 12)))
           (opnums-report (unwrap (read-u32be buffer 16)))
           (opnums-retrans (unwrap (read-u32be buffer 20)))
           (ck-len (unwrap (read-u8 buffer 25)))
           (addr (unwrap (slice buffer 26 16)))
           (last-used (unwrap (read-u32be buffer 42)))
           (requests (unwrap (read-u32be buffer 46)))
           (response-text (unwrap (slice buffer 50 1)))
           (trace (unwrap (read-u32be buffer 54)))
           (trace-admin (extract-bits trace 0x1 0))
           (trace-anon (extract-bits trace 0x2 1))
           (trace-client (extract-bits trace 0x4 2))
           (trace-rlim (extract-bits trace 0x8 3))
           (trace-query (extract-bits trace 0x10 4))
           (trace-ridc (extract-bits trace 0x20 5))
           (trace-flood (extract-bits trace 0x40 6))
           (adminval (unwrap (read-u32be buffer 54)))
           (pad (unwrap (slice buffer 59 3)))
           (max-pkt-vers (unwrap (read-u8 buffer 62)))
           (unused (unwrap (slice buffer 63 1)))
           (qdelay-ms (unwrap (read-u16be buffer 64)))
           (len (unwrap (read-u16be buffer 66)))
           )

      (ok (list
        (cons 'pkt-vers (list (cons 'raw pkt-vers) (cons 'formatted (number->string pkt-vers))))
        (cons 'clientid (list (cons 'raw clientid) (cons 'formatted (number->string clientid))))
        (cons 'opnums-host (list (cons 'raw opnums-host) (cons 'formatted (number->string opnums-host))))
        (cons 'opnums-pid (list (cons 'raw opnums-pid) (cons 'formatted (number->string opnums-pid))))
        (cons 'opnums-report (list (cons 'raw opnums-report) (cons 'formatted (number->string opnums-report))))
        (cons 'opnums-retrans (list (cons 'raw opnums-retrans) (cons 'formatted (number->string opnums-retrans))))
        (cons 'ck-len (list (cons 'raw ck-len) (cons 'formatted (number->string ck-len))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (fmt-bytes addr))))
        (cons 'last-used (list (cons 'raw last-used) (cons 'formatted (number->string last-used))))
        (cons 'requests (list (cons 'raw requests) (cons 'formatted (number->string requests))))
        (cons 'response-text (list (cons 'raw response-text) (cons 'formatted (utf8->string response-text))))
        (cons 'trace (list (cons 'raw trace) (cons 'formatted (fmt-hex trace))))
        (cons 'trace-admin (list (cons 'raw trace-admin) (cons 'formatted (if (= trace-admin 0) "Not set" "Set"))))
        (cons 'trace-anon (list (cons 'raw trace-anon) (cons 'formatted (if (= trace-anon 0) "Not set" "Set"))))
        (cons 'trace-client (list (cons 'raw trace-client) (cons 'formatted (if (= trace-client 0) "Not set" "Set"))))
        (cons 'trace-rlim (list (cons 'raw trace-rlim) (cons 'formatted (if (= trace-rlim 0) "Not set" "Set"))))
        (cons 'trace-query (list (cons 'raw trace-query) (cons 'formatted (if (= trace-query 0) "Not set" "Set"))))
        (cons 'trace-ridc (list (cons 'raw trace-ridc) (cons 'formatted (if (= trace-ridc 0) "Not set" "Set"))))
        (cons 'trace-flood (list (cons 'raw trace-flood) (cons 'formatted (if (= trace-flood 0) "Not set" "Set"))))
        (cons 'adminval (list (cons 'raw adminval) (cons 'formatted (number->string adminval))))
        (cons 'pad (list (cons 'raw pad) (cons 'formatted (fmt-bytes pad))))
        (cons 'max-pkt-vers (list (cons 'raw max-pkt-vers) (cons 'formatted (number->string max-pkt-vers))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (fmt-bytes unused))))
        (cons 'qdelay-ms (list (cons 'raw qdelay-ms) (cons 'formatted (number->string qdelay-ms))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        )))

    (catch (e)
      (err (str "DCC parse error: " e)))))

;; dissect-dcc: parse DCC from bytevector
;; Returns (ok fields-alist) or (err message)