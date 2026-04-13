;; packet-mip.c
;; Routines for Mobile IP dissection
;; Copyright 2000, Stefan Raab <sraab@cisco.com>
;; Copyright 2007, Ville Nuorvala <Ville.Nuorvala@secgo.com>
;; Copyright 2009, Ohuchi Munenori <ohuchi_at_iij.ad.jp>
;; Copyright 2010, Yi Ren          <yi_ren1@agilent.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mip.c

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
(def (dissect-mip buffer)
  "Mobile IP"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 0)))
           (nvse-3gpp2-type17-subtype1 (unwrap (read-u8 buffer 2)))
           (nvse-3gpp2-type17-prim-dns (unwrap (read-u32be buffer 2)))
           (nvse-3gpp2-type17-subtype2 (unwrap (read-u8 buffer 6)))
           (nvse-3gpp2-type17-length (unwrap (read-u8 buffer 6)))
           (nvse-3gpp2-type17-sec-dns (unwrap (read-u32be buffer 6)))
           (next-nai (unwrap (slice buffer 6 1)))
           (aext-spi (unwrap (read-u32be buffer 8)))
           (aext-auth (unwrap (slice buffer 8 1)))
           (rext-flags (unwrap (read-u16be buffer 8)))
           (rext-tstamp (unwrap (read-u32be buffer 8)))
           (dhaext-addr (unwrap (read-u32be buffer 8)))
           (mstrext-text (unwrap (slice buffer 8 1)))
           (utrqext-reserved1 (unwrap (read-u8 buffer 8)))
           (utrqext-flags (unwrap (read-u8 buffer 8)))
           (utrqext-reserved3 (unwrap (read-u16be buffer 8)))
           (utrpext-flags (unwrap (read-u16be buffer 8)))
           (s (extract-bits utrpext-flags 0x80 7))
           (b (extract-bits utrpext-flags 0x40 6))
           (d (extract-bits utrpext-flags 0x20 5))
           (m (extract-bits utrpext-flags 0x10 4))
           (g (extract-bits utrpext-flags 0x8 3))
           (v (extract-bits utrpext-flags 0x4 2))
           (t (extract-bits utrpext-flags 0x2 1))
           (x (extract-bits utrpext-flags 0x1 0))
           (utrpext-keepalive (unwrap (read-u16be buffer 8)))
           (pmipv4skipext-interfaceid (unwrap (slice buffer 10 1)))
           (pmipv4skipext-deviceid-id (unwrap (slice buffer 10 1)))
           (pmipv4skipext-subscriberid-id (unwrap (slice buffer 10 1)))
           (cvse-reserved (unwrap (read-u8 buffer 10)))
           (ext-len (unwrap (read-u16be buffer 10)))
           (coa (unwrap (read-u32be buffer 10)))
           (nvse-reserved (unwrap (read-u16be buffer 16)))
           (ext (unwrap (slice buffer 22 1)))
           (life (unwrap (read-u16be buffer 46)))
           (haaddr (unwrap (read-u32be buffer 52)))
           (nattt-reserved (unwrap (read-u16be buffer 84)))
           (rev-reserved (unwrap (read-u8 buffer 90)))
           (hda (unwrap (read-u32be buffer 96)))
           (fda (unwrap (read-u32be buffer 100)))
           (ack-reserved (unwrap (read-u8 buffer 128)))
           (flags2 (unwrap (read-u16be buffer 128)))
           (ack-i (extract-bits flags2 0x8000 15))
           (ack-reserved2 (extract-bits flags2 0x7FFF 0))
           (homeaddr (unwrap (read-u32be buffer 130)))
           (revid (unwrap (read-u32be buffer 134)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'nvse-3gpp2-type17-subtype1 (list (cons 'raw nvse-3gpp2-type17-subtype1) (cons 'formatted (number->string nvse-3gpp2-type17-subtype1))))
        (cons 'nvse-3gpp2-type17-prim-dns (list (cons 'raw nvse-3gpp2-type17-prim-dns) (cons 'formatted (fmt-ipv4 nvse-3gpp2-type17-prim-dns))))
        (cons 'nvse-3gpp2-type17-subtype2 (list (cons 'raw nvse-3gpp2-type17-subtype2) (cons 'formatted (number->string nvse-3gpp2-type17-subtype2))))
        (cons 'nvse-3gpp2-type17-length (list (cons 'raw nvse-3gpp2-type17-length) (cons 'formatted (number->string nvse-3gpp2-type17-length))))
        (cons 'nvse-3gpp2-type17-sec-dns (list (cons 'raw nvse-3gpp2-type17-sec-dns) (cons 'formatted (fmt-ipv4 nvse-3gpp2-type17-sec-dns))))
        (cons 'next-nai (list (cons 'raw next-nai) (cons 'formatted (utf8->string next-nai))))
        (cons 'aext-spi (list (cons 'raw aext-spi) (cons 'formatted (fmt-hex aext-spi))))
        (cons 'aext-auth (list (cons 'raw aext-auth) (cons 'formatted (fmt-bytes aext-auth))))
        (cons 'rext-flags (list (cons 'raw rext-flags) (cons 'formatted (fmt-hex rext-flags))))
        (cons 'rext-tstamp (list (cons 'raw rext-tstamp) (cons 'formatted (number->string rext-tstamp))))
        (cons 'dhaext-addr (list (cons 'raw dhaext-addr) (cons 'formatted (fmt-ipv4 dhaext-addr))))
        (cons 'mstrext-text (list (cons 'raw mstrext-text) (cons 'formatted (utf8->string mstrext-text))))
        (cons 'utrqext-reserved1 (list (cons 'raw utrqext-reserved1) (cons 'formatted (fmt-hex utrqext-reserved1))))
        (cons 'utrqext-flags (list (cons 'raw utrqext-flags) (cons 'formatted (fmt-hex utrqext-flags))))
        (cons 'utrqext-reserved3 (list (cons 'raw utrqext-reserved3) (cons 'formatted (fmt-hex utrqext-reserved3))))
        (cons 'utrpext-flags (list (cons 'raw utrpext-flags) (cons 'formatted (fmt-hex utrpext-flags))))
        (cons 's (list (cons 'raw s) (cons 'formatted (if (= s 0) "Not set" "Set"))))
        (cons 'b (list (cons 'raw b) (cons 'formatted (if (= b 0) "Not set" "Set"))))
        (cons 'd (list (cons 'raw d) (cons 'formatted (if (= d 0) "Not set" "Set"))))
        (cons 'm (list (cons 'raw m) (cons 'formatted (if (= m 0) "Not set" "Set"))))
        (cons 'g (list (cons 'raw g) (cons 'formatted (if (= g 0) "Not set" "Set"))))
        (cons 'v (list (cons 'raw v) (cons 'formatted (if (= v 0) "Not set" "Set"))))
        (cons 't (list (cons 'raw t) (cons 'formatted (if (= t 0) "Not set" "Set"))))
        (cons 'x (list (cons 'raw x) (cons 'formatted (if (= x 0) "Not set" "Set"))))
        (cons 'utrpext-keepalive (list (cons 'raw utrpext-keepalive) (cons 'formatted (number->string utrpext-keepalive))))
        (cons 'pmipv4skipext-interfaceid (list (cons 'raw pmipv4skipext-interfaceid) (cons 'formatted (fmt-bytes pmipv4skipext-interfaceid))))
        (cons 'pmipv4skipext-deviceid-id (list (cons 'raw pmipv4skipext-deviceid-id) (cons 'formatted (fmt-bytes pmipv4skipext-deviceid-id))))
        (cons 'pmipv4skipext-subscriberid-id (list (cons 'raw pmipv4skipext-subscriberid-id) (cons 'formatted (fmt-bytes pmipv4skipext-subscriberid-id))))
        (cons 'cvse-reserved (list (cons 'raw cvse-reserved) (cons 'formatted (fmt-hex cvse-reserved))))
        (cons 'ext-len (list (cons 'raw ext-len) (cons 'formatted (number->string ext-len))))
        (cons 'coa (list (cons 'raw coa) (cons 'formatted (fmt-ipv4 coa))))
        (cons 'nvse-reserved (list (cons 'raw nvse-reserved) (cons 'formatted (fmt-hex nvse-reserved))))
        (cons 'ext (list (cons 'raw ext) (cons 'formatted (fmt-bytes ext))))
        (cons 'life (list (cons 'raw life) (cons 'formatted (number->string life))))
        (cons 'haaddr (list (cons 'raw haaddr) (cons 'formatted (fmt-ipv4 haaddr))))
        (cons 'nattt-reserved (list (cons 'raw nattt-reserved) (cons 'formatted (fmt-hex nattt-reserved))))
        (cons 'rev-reserved (list (cons 'raw rev-reserved) (cons 'formatted (fmt-hex rev-reserved))))
        (cons 'hda (list (cons 'raw hda) (cons 'formatted (fmt-ipv4 hda))))
        (cons 'fda (list (cons 'raw fda) (cons 'formatted (fmt-ipv4 fda))))
        (cons 'ack-reserved (list (cons 'raw ack-reserved) (cons 'formatted (fmt-hex ack-reserved))))
        (cons 'flags2 (list (cons 'raw flags2) (cons 'formatted (fmt-hex flags2))))
        (cons 'ack-i (list (cons 'raw ack-i) (cons 'formatted (if (= ack-i 0) "Not set" "Set"))))
        (cons 'ack-reserved2 (list (cons 'raw ack-reserved2) (cons 'formatted (if (= ack-reserved2 0) "Not set" "Set"))))
        (cons 'homeaddr (list (cons 'raw homeaddr) (cons 'formatted (fmt-ipv4 homeaddr))))
        (cons 'revid (list (cons 'raw revid) (cons 'formatted (number->string revid))))
        )))

    (catch (e)
      (err (str "MIP parse error: " e)))))

;; dissect-mip: parse MIP from bytevector
;; Returns (ok fields-alist) or (err message)