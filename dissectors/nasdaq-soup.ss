;; packet-nasdaq-soup.c
;; Routines for NASDAQ SOUP 2.0 Protocol dissection
;; Copyright 2007,2008 Didier Gautheron <dgautheron@magic.fr>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Documentation: http://www.nasdaqtrader.com/Trader.aspx?id=DPSpecs
;; ex:
;; http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/souptcp.pdf
;;

;; jerboa-ethereal/dissectors/nasdaq-soup.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nasdaq_soup.c

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
(def (dissect-nasdaq-soup buffer)
  "Nasdaq-SoupTCP version 2.0"
  (try
    (let* (
           (soup-text (unwrap (slice buffer 0 1)))
           (soup-username (unwrap (slice buffer 20 6)))
           (soup-password (unwrap (slice buffer 26 10)))
           (soup-session (unwrap (slice buffer 36 10)))
           (soup-seq-number (unwrap (slice buffer 46 10)))
           (soup-message (unwrap (slice buffer 56 1)))
           (soup-packet-eol (unwrap (slice buffer 56 1)))
           )

      (ok (list
        (cons 'soup-text (list (cons 'raw soup-text) (cons 'formatted (utf8->string soup-text))))
        (cons 'soup-username (list (cons 'raw soup-username) (cons 'formatted (utf8->string soup-username))))
        (cons 'soup-password (list (cons 'raw soup-password) (cons 'formatted (utf8->string soup-password))))
        (cons 'soup-session (list (cons 'raw soup-session) (cons 'formatted (utf8->string soup-session))))
        (cons 'soup-seq-number (list (cons 'raw soup-seq-number) (cons 'formatted (utf8->string soup-seq-number))))
        (cons 'soup-message (list (cons 'raw soup-message) (cons 'formatted (utf8->string soup-message))))
        (cons 'soup-packet-eol (list (cons 'raw soup-packet-eol) (cons 'formatted (utf8->string soup-packet-eol))))
        )))

    (catch (e)
      (err (str "NASDAQ-SOUP parse error: " e)))))

;; dissect-nasdaq-soup: parse NASDAQ-SOUP from bytevector
;; Returns (ok fields-alist) or (err message)