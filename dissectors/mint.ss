;; packet-mint.c
;; Routines for the disassembly of the Media Independent Network Transport
;; protocol used between wireless controllers and APs
;;
;; Copyright 2013 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mint.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mint.c

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
(def (dissect-mint buffer)
  "Media Independent Network Transport"
  (try
    (let* (
           (header (unwrap (slice buffer 0 16)))
           (header-unknown1 (unwrap (slice buffer 0 1)))
           (header-ttl (unwrap (read-u8 buffer 1)))
           (header-unknown2 (unwrap (slice buffer 2 2)))
           (header-dstid (unwrap (slice buffer 4 4)))
           (header-srcid (unwrap (slice buffer 8 4)))
           (data (unwrap (slice buffer 18 1)))
           (data-vlan (unwrap (read-u16be buffer 18)))
           (data-seqno (unwrap (read-u32be buffer 20)))
           (router-unknown1 (unwrap (read-u8 buffer 60)))
           (router-unknown2 (unwrap (read-u8 buffer 61)))
           (router-unknown3 (unwrap (read-u8 buffer 62)))
           (router-header-length (unwrap (read-u8 buffer 63)))
           (router-message-type (unwrap (slice buffer 64 4)))
           (router-header-sender (unwrap (slice buffer 68 4)))
           (router-header-unknown (unwrap (slice buffer 72 1)))
           (router-array (unwrap (read-u8 buffer 73)))
           (router-length (unwrap (read-u8 buffer 74)))
           (router-element (unwrap (slice buffer 75 1)))
           (router-value (unwrap (slice buffer 75 1)))
           (neighbor-unknown (unwrap (slice buffer 107 1)))
           (control (unwrap (slice buffer 107 1)))
           (control-32zerobytes (unwrap (slice buffer 107 32)))
           (mlcp-message (unwrap (read-u16be buffer 139)))
           (mlcp-length (unwrap (read-u8 buffer 142)))
           (mlcp-value (unwrap (slice buffer 143 1)))
           (control-unknown1 (unwrap (slice buffer 143 1)))
           (data-unknown1 (unwrap (slice buffer 143 1)))
           )

      (ok (list
        (cons 'header (list (cons 'raw header) (cons 'formatted (fmt-bytes header))))
        (cons 'header-unknown1 (list (cons 'raw header-unknown1) (cons 'formatted (fmt-bytes header-unknown1))))
        (cons 'header-ttl (list (cons 'raw header-ttl) (cons 'formatted (number->string header-ttl))))
        (cons 'header-unknown2 (list (cons 'raw header-unknown2) (cons 'formatted (fmt-bytes header-unknown2))))
        (cons 'header-dstid (list (cons 'raw header-dstid) (cons 'formatted (fmt-bytes header-dstid))))
        (cons 'header-srcid (list (cons 'raw header-srcid) (cons 'formatted (fmt-bytes header-srcid))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'data-vlan (list (cons 'raw data-vlan) (cons 'formatted (number->string data-vlan))))
        (cons 'data-seqno (list (cons 'raw data-seqno) (cons 'formatted (number->string data-seqno))))
        (cons 'router-unknown1 (list (cons 'raw router-unknown1) (cons 'formatted (fmt-hex router-unknown1))))
        (cons 'router-unknown2 (list (cons 'raw router-unknown2) (cons 'formatted (number->string router-unknown2))))
        (cons 'router-unknown3 (list (cons 'raw router-unknown3) (cons 'formatted (fmt-hex router-unknown3))))
        (cons 'router-header-length (list (cons 'raw router-header-length) (cons 'formatted (fmt-hex router-header-length))))
        (cons 'router-message-type (list (cons 'raw router-message-type) (cons 'formatted (utf8->string router-message-type))))
        (cons 'router-header-sender (list (cons 'raw router-header-sender) (cons 'formatted (fmt-bytes router-header-sender))))
        (cons 'router-header-unknown (list (cons 'raw router-header-unknown) (cons 'formatted (fmt-bytes router-header-unknown))))
        (cons 'router-array (list (cons 'raw router-array) (cons 'formatted (number->string router-array))))
        (cons 'router-length (list (cons 'raw router-length) (cons 'formatted (number->string router-length))))
        (cons 'router-element (list (cons 'raw router-element) (cons 'formatted (fmt-bytes router-element))))
        (cons 'router-value (list (cons 'raw router-value) (cons 'formatted (fmt-bytes router-value))))
        (cons 'neighbor-unknown (list (cons 'raw neighbor-unknown) (cons 'formatted (fmt-bytes neighbor-unknown))))
        (cons 'control (list (cons 'raw control) (cons 'formatted (fmt-bytes control))))
        (cons 'control-32zerobytes (list (cons 'raw control-32zerobytes) (cons 'formatted (fmt-bytes control-32zerobytes))))
        (cons 'mlcp-message (list (cons 'raw mlcp-message) (cons 'formatted (fmt-hex mlcp-message))))
        (cons 'mlcp-length (list (cons 'raw mlcp-length) (cons 'formatted (number->string mlcp-length))))
        (cons 'mlcp-value (list (cons 'raw mlcp-value) (cons 'formatted (fmt-bytes mlcp-value))))
        (cons 'control-unknown1 (list (cons 'raw control-unknown1) (cons 'formatted (fmt-bytes control-unknown1))))
        (cons 'data-unknown1 (list (cons 'raw data-unknown1) (cons 'formatted (fmt-bytes data-unknown1))))
        )))

    (catch (e)
      (err (str "MINT parse error: " e)))))

;; dissect-mint: parse MINT from bytevector
;; Returns (ok fields-alist) or (err message)