;; packet-ancp.c
;;
;; Dissector for ANCP - Access Node Control Protocol
;;
;; More info on the protocol can be found on IETF:
;; https://tools.ietf.org/wg/ancp/
;; https://tools.ietf.org/html/draft-ietf-ancp-protocol-09
;; https://tools.ietf.org/html/rfc6320
;; https://tools.ietf.org/html/rfc7256
;; https://www.iana.org/assignments/ancp/ancp.xhtml
;;
;; Copyright 2010, Aniruddha.A (anira@cisco.com)
;; Uli Heilmeier, 2017; Update to RFC6320; current IANA registry types
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ancp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ancp.c
;; RFC 6320

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
(def (dissect-ancp buffer)
  "Access Node Control Protocol"
  (try
    (let* (
           (ext-tlv-len (unwrap (read-u16be buffer 2)))
           (len (unwrap (read-u16be buffer 2)))
           (ver (unwrap (read-u8 buffer 4)))
           (dsl-line-stlv-len (unwrap (read-u16be buffer 6)))
           (dsl-line-stlv-value (unwrap (read-u32be buffer 8)))
           (p-id (unwrap (read-u8 buffer 8)))
           (trans-id (unwrap (read-u24be buffer 9)))
           (i-flag (unwrap (read-u8 buffer 12)))
           (submsg-num (unwrap (read-u16be buffer 12)))
           (len2 (unwrap (read-u16be buffer 14)))
           (oam-loopb-cnt (unwrap (read-u8 buffer 16)))
           (oam-timeout (unwrap (read-u8 buffer 17)))
           (ext-tlv-value-str (unwrap (slice buffer 20 1)))
           (x-function (unwrap (read-u8 buffer 35)))
           (pudm-unused (unwrap (slice buffer 36 4)))
           (ext-flags-res (unwrap (slice buffer 60 1)))
           (num-ext-tlvs (unwrap (read-u16be buffer 66)))
           (blk-len (unwrap (read-u16be buffer 68)))
           (sender-name (unwrap (slice buffer 72 6)))
           (receiver-name (unwrap (slice buffer 78 6)))
           (sender-port (unwrap (read-u64be buffer 84)))
           (receiver-port (unwrap (read-u64be buffer 88)))
           (p-info (unwrap (read-u8 buffer 92)))
           (sender-instance (unwrap (read-u24be buffer 93)))
           (receiver-instance (unwrap (read-u24be buffer 97)))
           (reserved (unwrap (slice buffer 100 1)))
           (num-tlvs (unwrap (read-u8 buffer 101)))
           )

      (ok (list
        (cons 'ext-tlv-len (list (cons 'raw ext-tlv-len) (cons 'formatted (number->string ext-tlv-len))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (fmt-hex ver))))
        (cons 'dsl-line-stlv-len (list (cons 'raw dsl-line-stlv-len) (cons 'formatted (number->string dsl-line-stlv-len))))
        (cons 'dsl-line-stlv-value (list (cons 'raw dsl-line-stlv-value) (cons 'formatted (number->string dsl-line-stlv-value))))
        (cons 'p-id (list (cons 'raw p-id) (cons 'formatted (number->string p-id))))
        (cons 'trans-id (list (cons 'raw trans-id) (cons 'formatted (number->string trans-id))))
        (cons 'i-flag (list (cons 'raw i-flag) (cons 'formatted (if (= i-flag 0) "False" "True"))))
        (cons 'submsg-num (list (cons 'raw submsg-num) (cons 'formatted (number->string submsg-num))))
        (cons 'len2 (list (cons 'raw len2) (cons 'formatted (number->string len2))))
        (cons 'oam-loopb-cnt (list (cons 'raw oam-loopb-cnt) (cons 'formatted (number->string oam-loopb-cnt))))
        (cons 'oam-timeout (list (cons 'raw oam-timeout) (cons 'formatted (number->string oam-timeout))))
        (cons 'ext-tlv-value-str (list (cons 'raw ext-tlv-value-str) (cons 'formatted (utf8->string ext-tlv-value-str))))
        (cons 'x-function (list (cons 'raw x-function) (cons 'formatted (number->string x-function))))
        (cons 'pudm-unused (list (cons 'raw pudm-unused) (cons 'formatted (fmt-bytes pudm-unused))))
        (cons 'ext-flags-res (list (cons 'raw ext-flags-res) (cons 'formatted (fmt-bytes ext-flags-res))))
        (cons 'num-ext-tlvs (list (cons 'raw num-ext-tlvs) (cons 'formatted (number->string num-ext-tlvs))))
        (cons 'blk-len (list (cons 'raw blk-len) (cons 'formatted (number->string blk-len))))
        (cons 'sender-name (list (cons 'raw sender-name) (cons 'formatted (fmt-mac sender-name))))
        (cons 'receiver-name (list (cons 'raw receiver-name) (cons 'formatted (fmt-mac receiver-name))))
        (cons 'sender-port (list (cons 'raw sender-port) (cons 'formatted (number->string sender-port))))
        (cons 'receiver-port (list (cons 'raw receiver-port) (cons 'formatted (number->string receiver-port))))
        (cons 'p-info (list (cons 'raw p-info) (cons 'formatted (fmt-hex p-info))))
        (cons 'sender-instance (list (cons 'raw sender-instance) (cons 'formatted (number->string sender-instance))))
        (cons 'receiver-instance (list (cons 'raw receiver-instance) (cons 'formatted (number->string receiver-instance))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'num-tlvs (list (cons 'raw num-tlvs) (cons 'formatted (number->string num-tlvs))))
        )))

    (catch (e)
      (err (str "ANCP parse error: " e)))))

;; dissect-ancp: parse ANCP from bytevector
;; Returns (ok fields-alist) or (err message)