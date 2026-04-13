;; packet-iec104.c
;; Routines for IEC-60870-5-101 & 104 Protocol disassembly
;;
;; Copyright (c) 2008 by Joan Ramio <joan@ramio.cat>
;; Joan is a masculine catalan name. Search the Internet for Joan Pujol (alias Garbo).
;;
;; Copyright (c) 2009 by Kjell Hultman <kjell.hultman@gmail.com>
;; Added dissection of signal (ASDU) information.
;; Kjell is also a masculine name, but a Scandinavian one.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iec104.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iec104.c

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
(def (dissect-iec104 buffer)
  "IEC 60870-5-104"
  (try
    (let* (
           (hf-apcidata (unwrap (slice buffer 0 1)))
           (hf-sq (unwrap (read-u8 buffer 1)))
           (hf-numix (unwrap (read-u8 buffer 1)))
           (101-length (unwrap (read-u8 buffer 1)))
           (101-num-user-octets (unwrap (read-u8 buffer 1)))
           (5-103-length (unwrap (read-u8 buffer 1)))
           (5-103-num-user-octets (unwrap (read-u8 buffer 1)))
           (hf-nega (unwrap (read-u8 buffer 2)))
           (hf-test (unwrap (read-u8 buffer 2)))
           (hf-oa (unwrap (read-u8 buffer 3)))
           (hf-addr (unwrap (read-u16be buffer 4)))
           (101-ctrlfield (unwrap (read-u8 buffer 4)))
           (101-ctrl-fcb (unwrap (read-u8 buffer 4)))
           (101-ctrl-fcv (unwrap (read-u8 buffer 4)))
           (101-ctrl-dfc (unwrap (read-u8 buffer 4)))
           (5-103-ctrlfield (unwrap (read-u8 buffer 4)))
           (5-103-ctrl-fcb (unwrap (read-u8 buffer 4)))
           (5-103-ctrl-fcv (unwrap (read-u8 buffer 4)))
           (5-103-ctrl-dfc (unwrap (read-u8 buffer 4)))
           (101-linkaddr (unwrap (read-u16be buffer 5)))
           (101-checksum (unwrap (read-u8 buffer 5)))
           (101-stopchar (unwrap (read-u8 buffer 5)))
           (5-103-linkaddr (unwrap (read-u8 buffer 5)))
           (hf-ioa (unwrap (read-u24be buffer 6)))
           (5-103-sq (unwrap (read-u8 buffer 6)))
           (5-103-asdu-address (unwrap (read-u8 buffer 6)))
           (5-103-func-type (unwrap (read-u8 buffer 6)))
           (5-103-info-num (unwrap (read-u8 buffer 6)))
           (raw-data (unwrap (slice buffer 9 1)))
           (5-103-rii (unwrap (read-u8 buffer 13)))
           (5-103-areva-cmd (unwrap (read-u8 buffer 15)))
           (5-103-sin (unwrap (read-u8 buffer 17)))
           (5-103-col (unwrap (read-u8 buffer 18)))
           (5-103-mfg (unwrap (slice buffer 19 8)))
           (5-103-mfg-sw (unwrap (read-u32be buffer 27)))
           (5-103-scn (unwrap (read-u8 buffer 31)))
           (5-103-asdu205-value (unwrap (read-u32be buffer 32)))
           (5-103-asdu205-ms (unwrap (read-u16be buffer 32)))
           (5-103-asdu205-min (unwrap (read-u8 buffer 32)))
           (5-103-asdu205-h (unwrap (read-u8 buffer 32)))
           (5-103-checksum (unwrap (read-u8 buffer 40)))
           (5-103-stopchar (unwrap (read-u8 buffer 40)))
           )

      (ok (list
        (cons 'hf-apcidata (list (cons 'raw hf-apcidata) (cons 'formatted (fmt-bytes hf-apcidata))))
        (cons 'hf-sq (list (cons 'raw hf-sq) (cons 'formatted (number->string hf-sq))))
        (cons 'hf-numix (list (cons 'raw hf-numix) (cons 'formatted (number->string hf-numix))))
        (cons '101-length (list (cons 'raw 101-length) (cons 'formatted (number->string 101-length))))
        (cons '101-num-user-octets (list (cons 'raw 101-num-user-octets) (cons 'formatted (number->string 101-num-user-octets))))
        (cons '5-103-length (list (cons 'raw 5-103-length) (cons 'formatted (number->string 5-103-length))))
        (cons '5-103-num-user-octets (list (cons 'raw 5-103-num-user-octets) (cons 'formatted (number->string 5-103-num-user-octets))))
        (cons 'hf-nega (list (cons 'raw hf-nega) (cons 'formatted (number->string hf-nega))))
        (cons 'hf-test (list (cons 'raw hf-test) (cons 'formatted (number->string hf-test))))
        (cons 'hf-oa (list (cons 'raw hf-oa) (cons 'formatted (number->string hf-oa))))
        (cons 'hf-addr (list (cons 'raw hf-addr) (cons 'formatted (number->string hf-addr))))
        (cons '101-ctrlfield (list (cons 'raw 101-ctrlfield) (cons 'formatted (fmt-hex 101-ctrlfield))))
        (cons '101-ctrl-fcb (list (cons 'raw 101-ctrl-fcb) (cons 'formatted (number->string 101-ctrl-fcb))))
        (cons '101-ctrl-fcv (list (cons 'raw 101-ctrl-fcv) (cons 'formatted (number->string 101-ctrl-fcv))))
        (cons '101-ctrl-dfc (list (cons 'raw 101-ctrl-dfc) (cons 'formatted (number->string 101-ctrl-dfc))))
        (cons '5-103-ctrlfield (list (cons 'raw 5-103-ctrlfield) (cons 'formatted (fmt-hex 5-103-ctrlfield))))
        (cons '5-103-ctrl-fcb (list (cons 'raw 5-103-ctrl-fcb) (cons 'formatted (number->string 5-103-ctrl-fcb))))
        (cons '5-103-ctrl-fcv (list (cons 'raw 5-103-ctrl-fcv) (cons 'formatted (number->string 5-103-ctrl-fcv))))
        (cons '5-103-ctrl-dfc (list (cons 'raw 5-103-ctrl-dfc) (cons 'formatted (number->string 5-103-ctrl-dfc))))
        (cons '101-linkaddr (list (cons 'raw 101-linkaddr) (cons 'formatted (number->string 101-linkaddr))))
        (cons '101-checksum (list (cons 'raw 101-checksum) (cons 'formatted (fmt-hex 101-checksum))))
        (cons '101-stopchar (list (cons 'raw 101-stopchar) (cons 'formatted (fmt-hex 101-stopchar))))
        (cons '5-103-linkaddr (list (cons 'raw 5-103-linkaddr) (cons 'formatted (number->string 5-103-linkaddr))))
        (cons 'hf-ioa (list (cons 'raw hf-ioa) (cons 'formatted (number->string hf-ioa))))
        (cons '5-103-sq (list (cons 'raw 5-103-sq) (cons 'formatted (fmt-hex 5-103-sq))))
        (cons '5-103-asdu-address (list (cons 'raw 5-103-asdu-address) (cons 'formatted (number->string 5-103-asdu-address))))
        (cons '5-103-func-type (list (cons 'raw 5-103-func-type) (cons 'formatted (number->string 5-103-func-type))))
        (cons '5-103-info-num (list (cons 'raw 5-103-info-num) (cons 'formatted (number->string 5-103-info-num))))
        (cons 'raw-data (list (cons 'raw raw-data) (cons 'formatted (fmt-bytes raw-data))))
        (cons '5-103-rii (list (cons 'raw 5-103-rii) (cons 'formatted (number->string 5-103-rii))))
        (cons '5-103-areva-cmd (list (cons 'raw 5-103-areva-cmd) (cons 'formatted (fmt-hex 5-103-areva-cmd))))
        (cons '5-103-sin (list (cons 'raw 5-103-sin) (cons 'formatted (number->string 5-103-sin))))
        (cons '5-103-col (list (cons 'raw 5-103-col) (cons 'formatted (number->string 5-103-col))))
        (cons '5-103-mfg (list (cons 'raw 5-103-mfg) (cons 'formatted (utf8->string 5-103-mfg))))
        (cons '5-103-mfg-sw (list (cons 'raw 5-103-mfg-sw) (cons 'formatted (number->string 5-103-mfg-sw))))
        (cons '5-103-scn (list (cons 'raw 5-103-scn) (cons 'formatted (number->string 5-103-scn))))
        (cons '5-103-asdu205-value (list (cons 'raw 5-103-asdu205-value) (cons 'formatted (number->string 5-103-asdu205-value))))
        (cons '5-103-asdu205-ms (list (cons 'raw 5-103-asdu205-ms) (cons 'formatted (number->string 5-103-asdu205-ms))))
        (cons '5-103-asdu205-min (list (cons 'raw 5-103-asdu205-min) (cons 'formatted (number->string 5-103-asdu205-min))))
        (cons '5-103-asdu205-h (list (cons 'raw 5-103-asdu205-h) (cons 'formatted (number->string 5-103-asdu205-h))))
        (cons '5-103-checksum (list (cons 'raw 5-103-checksum) (cons 'formatted (fmt-hex 5-103-checksum))))
        (cons '5-103-stopchar (list (cons 'raw 5-103-stopchar) (cons 'formatted (fmt-hex 5-103-stopchar))))
        )))

    (catch (e)
      (err (str "IEC104 parse error: " e)))))

;; dissect-iec104: parse IEC104 from bytevector
;; Returns (ok fields-alist) or (err message)