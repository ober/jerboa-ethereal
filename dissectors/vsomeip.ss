;; packet-vsomeip.c
;; vSomeIP dissector.
;; By Dr. Lars Völker <lars.voelker@technica-engineering.de>
;; Copyright 2024-2025 Dr. Lars Völker
;;
;;
;; Dissector for the vSomeIP internally used protocol.
;;
;; Specification: https://github.com/COVESA/vsomeip/blob/master/documentation/vsomeipProtocol.md
;; lua dissector: https://github.com/COVESA/vsomeip/blob/master/tools/wireshark_plugin/vsomeip-dissector.lua
;;
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vsomeip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vsomeip.c

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
(def (dissect-vsomeip buffer)
  "vSomeIP"
  (try
    (let* (
           (magic-start (unwrap (slice buffer 0 4)))
           (version (unwrap (read-u16be buffer 5)))
           (client (unwrap (read-u16be buffer 7)))
           (size (unwrap (read-u32be buffer 9)))
           (name (unwrap (slice buffer 13 1)))
           (new-client (unwrap (read-u16be buffer 13)))
           (ri-size (unwrap (read-u32be buffer 16)))
           (ri-ci-size (unwrap (read-u32be buffer 20)))
           (ri-client (unwrap (read-u16be buffer 24)))
           (ri-ipv4 (unwrap (read-u32be buffer 26)))
           (ri-port (unwrap (read-u16be buffer 30)))
           (ri-srv-size (unwrap (read-u32be buffer 32)))
           (subscriberid (unwrap (read-u16be buffer 46)))
           (eventid (unwrap (read-u16be buffer 48)))
           (instance (unwrap (read-u16be buffer 52)))
           (crc (unwrap (read-u8 buffer 55)))
           (dest (unwrap (read-u16be buffer 56)))
           (payload (unwrap (slice buffer 58 1)))
           (num-entries (unwrap (read-u16be buffer 68)))
           (notifierid (unwrap (read-u16be buffer 76)))
           (osr-size (unwrap (read-u32be buffer 82)))
           (serviceid (unwrap (read-u16be buffer 86)))
           (instanceid (unwrap (read-u16be buffer 88)))
           (eventgroupid (unwrap (read-u16be buffer 90)))
           (id (unwrap (read-u16be buffer 92)))
           (pend-offer (unwrap (read-u32be buffer 94)))
           (cfg-key-size (unwrap (read-u32be buffer 98)))
           (cfg-key (unwrap (slice buffer 102 1)))
           (cfg-val-size (unwrap (read-u32be buffer 102)))
           (cfg-val (unwrap (slice buffer 106 1)))
           (unparsed (unwrap (slice buffer 106 1)))
           (magic-end (unwrap (slice buffer 106 4)))
           )

      (ok (list
        (cons 'magic-start (list (cons 'raw magic-start) (cons 'formatted (fmt-bytes magic-start))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'client (list (cons 'raw client) (cons 'formatted (fmt-hex client))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'new-client (list (cons 'raw new-client) (cons 'formatted (fmt-hex new-client))))
        (cons 'ri-size (list (cons 'raw ri-size) (cons 'formatted (number->string ri-size))))
        (cons 'ri-ci-size (list (cons 'raw ri-ci-size) (cons 'formatted (number->string ri-ci-size))))
        (cons 'ri-client (list (cons 'raw ri-client) (cons 'formatted (fmt-hex ri-client))))
        (cons 'ri-ipv4 (list (cons 'raw ri-ipv4) (cons 'formatted (fmt-ipv4 ri-ipv4))))
        (cons 'ri-port (list (cons 'raw ri-port) (cons 'formatted (number->string ri-port))))
        (cons 'ri-srv-size (list (cons 'raw ri-srv-size) (cons 'formatted (number->string ri-srv-size))))
        (cons 'subscriberid (list (cons 'raw subscriberid) (cons 'formatted (fmt-hex subscriberid))))
        (cons 'eventid (list (cons 'raw eventid) (cons 'formatted (fmt-hex eventid))))
        (cons 'instance (list (cons 'raw instance) (cons 'formatted (fmt-hex instance))))
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-hex crc))))
        (cons 'dest (list (cons 'raw dest) (cons 'formatted (fmt-hex dest))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'num-entries (list (cons 'raw num-entries) (cons 'formatted (number->string num-entries))))
        (cons 'notifierid (list (cons 'raw notifierid) (cons 'formatted (fmt-hex notifierid))))
        (cons 'osr-size (list (cons 'raw osr-size) (cons 'formatted (number->string osr-size))))
        (cons 'serviceid (list (cons 'raw serviceid) (cons 'formatted (fmt-hex serviceid))))
        (cons 'instanceid (list (cons 'raw instanceid) (cons 'formatted (fmt-hex instanceid))))
        (cons 'eventgroupid (list (cons 'raw eventgroupid) (cons 'formatted (fmt-hex eventgroupid))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'pend-offer (list (cons 'raw pend-offer) (cons 'formatted (fmt-hex pend-offer))))
        (cons 'cfg-key-size (list (cons 'raw cfg-key-size) (cons 'formatted (number->string cfg-key-size))))
        (cons 'cfg-key (list (cons 'raw cfg-key) (cons 'formatted (utf8->string cfg-key))))
        (cons 'cfg-val-size (list (cons 'raw cfg-val-size) (cons 'formatted (number->string cfg-val-size))))
        (cons 'cfg-val (list (cons 'raw cfg-val) (cons 'formatted (utf8->string cfg-val))))
        (cons 'unparsed (list (cons 'raw unparsed) (cons 'formatted (fmt-bytes unparsed))))
        (cons 'magic-end (list (cons 'raw magic-end) (cons 'formatted (fmt-bytes magic-end))))
        )))

    (catch (e)
      (err (str "VSOMEIP parse error: " e)))))

;; dissect-vsomeip: parse VSOMEIP from bytevector
;; Returns (ok fields-alist) or (err message)