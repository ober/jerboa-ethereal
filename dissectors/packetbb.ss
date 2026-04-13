;; packet-packetbb.c
;; Routines for parsing packetbb rfc 5444
;; Parser created by Henning Rogge <henning.rogge@fkie.fraunhofer.de> of Fraunhover
;; TLV values decoding by Francois Schneider <francois.schneider_@_airbus.com>
;;
;; https://tools.ietf.org/html/rfc5444
;; https://tools.ietf.org/html/rfc5498
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/packetbb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-packetbb.c
;; RFC 5497

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
(def (dissect-packetbb buffer)
  "PacketBB Protocol"
  (try
    (let* (
           (header-flags (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (tlv-mprwillingness (unwrap (read-u8 buffer 0)))
           (tlv-mprwillingness-flooding (extract-bits tlv-mprwillingness 0xF0 4))
           (tlv-mprwillingness-routing (extract-bits tlv-mprwillingness 0xF 0))
           (tlv-contseqnum (unwrap (read-u16be buffer 0)))
           (tlv-intervaltime (unwrap (read-u8 buffer 0)))
           (tlv-validitytime (unwrap (read-u8 buffer 0)))
           (tlv-icv (unwrap (slice buffer 0 1)))
           (tlv-timestamp (unwrap (slice buffer 0 1)))
           (tlv-linkmetric-flags-linkin (unwrap (read-u8 buffer 0)))
           (tlv-linkmetric-flags-linkout (unwrap (read-u8 buffer 0)))
           (tlv-linkmetric-flags-neighin (unwrap (read-u8 buffer 0)))
           (tlv-linkmetric-flags-neighout (unwrap (read-u8 buffer 0)))
           (tlv-linkmetric-value (unwrap (read-u16be buffer 0)))
           (tlv-gateway (unwrap (read-u8 buffer 0)))
           (tlvblock-length (unwrap (read-u16be buffer 0)))
           (seqnr (unwrap (read-u16be buffer 1)))
           (tlv-flags (unwrap (read-u8 buffer 4)))
           (header-flags-phasseqnum (extract-bits tlv-flags 0x0 0))
           (header-flags-phastlv (extract-bits tlv-flags 0x0 0))
           (tlv-indexend (unwrap (read-u8 buffer 4)))
           (tlv-indexstart (unwrap (read-u8 buffer 4)))
           (tlv-length (unwrap (read-u16be buffer 4)))
           (tlv-value (unwrap (slice buffer 6 1)))
           (tlv-multivalue (unwrap (slice buffer 6 1)))
           (msgheader-flags (unwrap (read-u8 buffer 6)))
           (msgheader-flags-mhasorig (unwrap (read-u8 buffer 6)))
           (msgheader-flags-mhashoplimit (unwrap (read-u8 buffer 6)))
           (msgheader-flags-mhashopcount (unwrap (read-u8 buffer 6)))
           (msgheader-flags-mhasseqnr (unwrap (read-u8 buffer 6)))
           (msgheader-addresssize (unwrap (read-u8 buffer 6)))
           (msgheader-size (unwrap (read-u16be buffer 6)))
           (msgheader-origaddripv4 (unwrap (read-u32be buffer 10)))
           (msgheader-origaddripv6 (unwrap (slice buffer 10 16)))
           (msgheader-origaddrmac (unwrap (slice buffer 10 6)))
           (msgheader-origaddrcustom (unwrap (slice buffer 10 1)))
           (msgheader-seqnr (unwrap (read-u16be buffer 10)))
           )

      (ok (list
        (cons 'header-flags (list (cons 'raw header-flags) (cons 'formatted (fmt-hex header-flags))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'tlv-mprwillingness (list (cons 'raw tlv-mprwillingness) (cons 'formatted (fmt-hex tlv-mprwillingness))))
        (cons 'tlv-mprwillingness-flooding (list (cons 'raw tlv-mprwillingness-flooding) (cons 'formatted (if (= tlv-mprwillingness-flooding 0) "Not set" "Set"))))
        (cons 'tlv-mprwillingness-routing (list (cons 'raw tlv-mprwillingness-routing) (cons 'formatted (if (= tlv-mprwillingness-routing 0) "Not set" "Set"))))
        (cons 'tlv-contseqnum (list (cons 'raw tlv-contseqnum) (cons 'formatted (fmt-hex tlv-contseqnum))))
        (cons 'tlv-intervaltime (list (cons 'raw tlv-intervaltime) (cons 'formatted (fmt-hex tlv-intervaltime))))
        (cons 'tlv-validitytime (list (cons 'raw tlv-validitytime) (cons 'formatted (fmt-hex tlv-validitytime))))
        (cons 'tlv-icv (list (cons 'raw tlv-icv) (cons 'formatted (fmt-bytes tlv-icv))))
        (cons 'tlv-timestamp (list (cons 'raw tlv-timestamp) (cons 'formatted (fmt-bytes tlv-timestamp))))
        (cons 'tlv-linkmetric-flags-linkin (list (cons 'raw tlv-linkmetric-flags-linkin) (cons 'formatted (number->string tlv-linkmetric-flags-linkin))))
        (cons 'tlv-linkmetric-flags-linkout (list (cons 'raw tlv-linkmetric-flags-linkout) (cons 'formatted (number->string tlv-linkmetric-flags-linkout))))
        (cons 'tlv-linkmetric-flags-neighin (list (cons 'raw tlv-linkmetric-flags-neighin) (cons 'formatted (number->string tlv-linkmetric-flags-neighin))))
        (cons 'tlv-linkmetric-flags-neighout (list (cons 'raw tlv-linkmetric-flags-neighout) (cons 'formatted (number->string tlv-linkmetric-flags-neighout))))
        (cons 'tlv-linkmetric-value (list (cons 'raw tlv-linkmetric-value) (cons 'formatted (fmt-hex tlv-linkmetric-value))))
        (cons 'tlv-gateway (list (cons 'raw tlv-gateway) (cons 'formatted (number->string tlv-gateway))))
        (cons 'tlvblock-length (list (cons 'raw tlvblock-length) (cons 'formatted (number->string tlvblock-length))))
        (cons 'seqnr (list (cons 'raw seqnr) (cons 'formatted (number->string seqnr))))
        (cons 'tlv-flags (list (cons 'raw tlv-flags) (cons 'formatted (fmt-hex tlv-flags))))
        (cons 'header-flags-phasseqnum (list (cons 'raw header-flags-phasseqnum) (cons 'formatted (if (= header-flags-phasseqnum 0) "Not set" "Set"))))
        (cons 'header-flags-phastlv (list (cons 'raw header-flags-phastlv) (cons 'formatted (if (= header-flags-phastlv 0) "Not set" "Set"))))
        (cons 'tlv-indexend (list (cons 'raw tlv-indexend) (cons 'formatted (number->string tlv-indexend))))
        (cons 'tlv-indexstart (list (cons 'raw tlv-indexstart) (cons 'formatted (number->string tlv-indexstart))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (number->string tlv-length))))
        (cons 'tlv-value (list (cons 'raw tlv-value) (cons 'formatted (fmt-bytes tlv-value))))
        (cons 'tlv-multivalue (list (cons 'raw tlv-multivalue) (cons 'formatted (fmt-bytes tlv-multivalue))))
        (cons 'msgheader-flags (list (cons 'raw msgheader-flags) (cons 'formatted (fmt-hex msgheader-flags))))
        (cons 'msgheader-flags-mhasorig (list (cons 'raw msgheader-flags-mhasorig) (cons 'formatted (number->string msgheader-flags-mhasorig))))
        (cons 'msgheader-flags-mhashoplimit (list (cons 'raw msgheader-flags-mhashoplimit) (cons 'formatted (number->string msgheader-flags-mhashoplimit))))
        (cons 'msgheader-flags-mhashopcount (list (cons 'raw msgheader-flags-mhashopcount) (cons 'formatted (number->string msgheader-flags-mhashopcount))))
        (cons 'msgheader-flags-mhasseqnr (list (cons 'raw msgheader-flags-mhasseqnr) (cons 'formatted (number->string msgheader-flags-mhasseqnr))))
        (cons 'msgheader-addresssize (list (cons 'raw msgheader-addresssize) (cons 'formatted (number->string msgheader-addresssize))))
        (cons 'msgheader-size (list (cons 'raw msgheader-size) (cons 'formatted (number->string msgheader-size))))
        (cons 'msgheader-origaddripv4 (list (cons 'raw msgheader-origaddripv4) (cons 'formatted (fmt-ipv4 msgheader-origaddripv4))))
        (cons 'msgheader-origaddripv6 (list (cons 'raw msgheader-origaddripv6) (cons 'formatted (fmt-ipv6-address msgheader-origaddripv6))))
        (cons 'msgheader-origaddrmac (list (cons 'raw msgheader-origaddrmac) (cons 'formatted (fmt-mac msgheader-origaddrmac))))
        (cons 'msgheader-origaddrcustom (list (cons 'raw msgheader-origaddrcustom) (cons 'formatted (fmt-bytes msgheader-origaddrcustom))))
        (cons 'msgheader-seqnr (list (cons 'raw msgheader-seqnr) (cons 'formatted (number->string msgheader-seqnr))))
        )))

    (catch (e)
      (err (str "PACKETBB parse error: " e)))))

;; dissect-packetbb: parse PACKETBB from bytevector
;; Returns (ok fields-alist) or (err message)