;; packet-mp2t.c
;;
;; Routines for RFC 2250 MPEG2 (ISO/IEC 13818-1) Transport Stream dissection
;;
;; Copyright 2006, Erwin Rol <erwin@erwinrol.com>
;; Copyright 2012-2014, Guy Martin <gmsoft@tuxicoman.be>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mp2t.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mp2t.c
;; RFC 2250

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
(def (dissect-mp2t buffer)
  "ISO/IEC 13818-1"
  (try
    (let* (
           (af-di (unwrap (read-u8 buffer 1)))
           (af-rai (unwrap (read-u8 buffer 1)))
           (af-espi (unwrap (read-u8 buffer 1)))
           (af-pcr-flag (unwrap (read-u8 buffer 1)))
           (af-opcr-flag (unwrap (read-u8 buffer 1)))
           (af-sp-flag (unwrap (read-u8 buffer 1)))
           (af-tpd-flag (unwrap (read-u8 buffer 1)))
           (af-afe-flag (unwrap (read-u8 buffer 1)))
           (af-pcr (unwrap (read-u64be buffer 2)))
           (af-opcr (unwrap (read-u64be buffer 8)))
           (af-sc (unwrap (read-u8 buffer 14)))
           (af-tpd-length (unwrap (read-u8 buffer 15)))
           (af-tpd (unwrap (slice buffer 16 1)))
           (af-e-length (unwrap (read-u8 buffer 16)))
           (af-e-ltw-flag (unwrap (read-u8 buffer 17)))
           (af-e-pr-flag (unwrap (read-u8 buffer 17)))
           (af-e-ss-flag (unwrap (read-u8 buffer 17)))
           (af-e-reserved (unwrap (read-u8 buffer 17)))
           (af-e-ltwv-flag (unwrap (read-u16be buffer 18)))
           (af-e-ltwo (unwrap (read-u16be buffer 18)))
           (af-e-pr-reserved (unwrap (read-u24be buffer 20)))
           (af-e-pr (unwrap (read-u24be buffer 20)))
           (af-e-st (unwrap (read-u8 buffer 23)))
           (af-e-dnau-32-30 (unwrap (read-u8 buffer 23)))
           (af-e-m-1 (unwrap (read-u8 buffer 23)))
           (af-e-dnau-29-15 (unwrap (read-u16be buffer 24)))
           (af-e-m-2 (unwrap (read-u16be buffer 24)))
           (af-e-dnau-14-0 (unwrap (read-u16be buffer 26)))
           (af-e-m-3 (unwrap (read-u16be buffer 26)))
           (af-e-reserved-bytes (unwrap (slice buffer 28 1)))
           (af-stuffing-bytes (unwrap (slice buffer 28 1)))
           (af-length (unwrap (read-u8 buffer 29)))
           )

      (ok (list
        (cons 'af-di (list (cons 'raw af-di) (cons 'formatted (number->string af-di))))
        (cons 'af-rai (list (cons 'raw af-rai) (cons 'formatted (number->string af-rai))))
        (cons 'af-espi (list (cons 'raw af-espi) (cons 'formatted (number->string af-espi))))
        (cons 'af-pcr-flag (list (cons 'raw af-pcr-flag) (cons 'formatted (number->string af-pcr-flag))))
        (cons 'af-opcr-flag (list (cons 'raw af-opcr-flag) (cons 'formatted (number->string af-opcr-flag))))
        (cons 'af-sp-flag (list (cons 'raw af-sp-flag) (cons 'formatted (number->string af-sp-flag))))
        (cons 'af-tpd-flag (list (cons 'raw af-tpd-flag) (cons 'formatted (number->string af-tpd-flag))))
        (cons 'af-afe-flag (list (cons 'raw af-afe-flag) (cons 'formatted (number->string af-afe-flag))))
        (cons 'af-pcr (list (cons 'raw af-pcr) (cons 'formatted (fmt-hex af-pcr))))
        (cons 'af-opcr (list (cons 'raw af-opcr) (cons 'formatted (fmt-hex af-opcr))))
        (cons 'af-sc (list (cons 'raw af-sc) (cons 'formatted (number->string af-sc))))
        (cons 'af-tpd-length (list (cons 'raw af-tpd-length) (cons 'formatted (number->string af-tpd-length))))
        (cons 'af-tpd (list (cons 'raw af-tpd) (cons 'formatted (fmt-bytes af-tpd))))
        (cons 'af-e-length (list (cons 'raw af-e-length) (cons 'formatted (number->string af-e-length))))
        (cons 'af-e-ltw-flag (list (cons 'raw af-e-ltw-flag) (cons 'formatted (number->string af-e-ltw-flag))))
        (cons 'af-e-pr-flag (list (cons 'raw af-e-pr-flag) (cons 'formatted (number->string af-e-pr-flag))))
        (cons 'af-e-ss-flag (list (cons 'raw af-e-ss-flag) (cons 'formatted (number->string af-e-ss-flag))))
        (cons 'af-e-reserved (list (cons 'raw af-e-reserved) (cons 'formatted (number->string af-e-reserved))))
        (cons 'af-e-ltwv-flag (list (cons 'raw af-e-ltwv-flag) (cons 'formatted (number->string af-e-ltwv-flag))))
        (cons 'af-e-ltwo (list (cons 'raw af-e-ltwo) (cons 'formatted (number->string af-e-ltwo))))
        (cons 'af-e-pr-reserved (list (cons 'raw af-e-pr-reserved) (cons 'formatted (number->string af-e-pr-reserved))))
        (cons 'af-e-pr (list (cons 'raw af-e-pr) (cons 'formatted (number->string af-e-pr))))
        (cons 'af-e-st (list (cons 'raw af-e-st) (cons 'formatted (number->string af-e-st))))
        (cons 'af-e-dnau-32-30 (list (cons 'raw af-e-dnau-32-30) (cons 'formatted (number->string af-e-dnau-32-30))))
        (cons 'af-e-m-1 (list (cons 'raw af-e-m-1) (cons 'formatted (number->string af-e-m-1))))
        (cons 'af-e-dnau-29-15 (list (cons 'raw af-e-dnau-29-15) (cons 'formatted (number->string af-e-dnau-29-15))))
        (cons 'af-e-m-2 (list (cons 'raw af-e-m-2) (cons 'formatted (number->string af-e-m-2))))
        (cons 'af-e-dnau-14-0 (list (cons 'raw af-e-dnau-14-0) (cons 'formatted (number->string af-e-dnau-14-0))))
        (cons 'af-e-m-3 (list (cons 'raw af-e-m-3) (cons 'formatted (number->string af-e-m-3))))
        (cons 'af-e-reserved-bytes (list (cons 'raw af-e-reserved-bytes) (cons 'formatted (fmt-bytes af-e-reserved-bytes))))
        (cons 'af-stuffing-bytes (list (cons 'raw af-stuffing-bytes) (cons 'formatted (fmt-bytes af-stuffing-bytes))))
        (cons 'af-length (list (cons 'raw af-length) (cons 'formatted (number->string af-length))))
        )))

    (catch (e)
      (err (str "MP2T parse error: " e)))))

;; dissect-mp2t: parse MP2T from bytevector
;; Returns (ok fields-alist) or (err message)