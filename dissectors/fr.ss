;; packet-fr.c
;; Routines for Frame Relay  dissection
;;
;; Copyright 2001, Paul Ionescu <paul@acorp.ro>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;;
;; https://web.archive.org/web/20150510093619/http://www.protocols.com/pbook/frame.htm
;; https://www.broadband-forum.org/wp-content/uploads/2018/12/FRF.3.2.pdf
;; ITU Recommendations Q.922 and Q.933
;; RFC-1490
;; RFC-2427
;; Cisco encapsulation
;; https://web.archive.org/web/20030422173700/https://www.trillium.com/assets/legacyframe/white_paper/8771019.pdf
;;

;; jerboa-ethereal/dissectors/fr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fr.c

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
(def (dissect-fr buffer)
  "Frame Relay"
  (try
    (let* (
           (dlci (unwrap (read-u32be buffer 0)))
           (first-addr-octet (unwrap (read-u8 buffer 0)))
           (upper-dlci (extract-bits first-addr-octet 0x0 0))
           (cr (extract-bits first-addr-octet 0x0 0))
           (second-addr-octet (unwrap (read-u8 buffer 0)))
           (second-dlci (extract-bits second-addr-octet 0x0 0))
           (fecn (extract-bits second-addr-octet 0x0 0))
           (becn (extract-bits second-addr-octet 0x0 0))
           (de (extract-bits second-addr-octet 0x0 0))
           (third-addr-octet (unwrap (read-u8 buffer 0)))
           (third-dlci (extract-bits third-addr-octet 0x0 0))
           (dlcore-control (unwrap (read-u8 buffer 0)))
           (lower-dlci (unwrap (read-u8 buffer 0)))
           (dc (unwrap (read-u8 buffer 0)))
           (ea (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'dlci (list (cons 'raw dlci) (cons 'formatted (number->string dlci))))
        (cons 'first-addr-octet (list (cons 'raw first-addr-octet) (cons 'formatted (fmt-hex first-addr-octet))))
        (cons 'upper-dlci (list (cons 'raw upper-dlci) (cons 'formatted (if (= upper-dlci 0) "Not set" "Set"))))
        (cons 'cr (list (cons 'raw cr) (cons 'formatted (if (= cr 0) "Not set" "Set"))))
        (cons 'second-addr-octet (list (cons 'raw second-addr-octet) (cons 'formatted (fmt-hex second-addr-octet))))
        (cons 'second-dlci (list (cons 'raw second-dlci) (cons 'formatted (if (= second-dlci 0) "Not set" "Set"))))
        (cons 'fecn (list (cons 'raw fecn) (cons 'formatted (if (= fecn 0) "Not set" "Set"))))
        (cons 'becn (list (cons 'raw becn) (cons 'formatted (if (= becn 0) "Not set" "Set"))))
        (cons 'de (list (cons 'raw de) (cons 'formatted (if (= de 0) "Not set" "Set"))))
        (cons 'third-addr-octet (list (cons 'raw third-addr-octet) (cons 'formatted (fmt-hex third-addr-octet))))
        (cons 'third-dlci (list (cons 'raw third-dlci) (cons 'formatted (if (= third-dlci 0) "Not set" "Set"))))
        (cons 'dlcore-control (list (cons 'raw dlcore-control) (cons 'formatted (fmt-hex dlcore-control))))
        (cons 'lower-dlci (list (cons 'raw lower-dlci) (cons 'formatted (fmt-hex lower-dlci))))
        (cons 'dc (list (cons 'raw dc) (cons 'formatted (if (= dc 0) "Control" "DLCI Address"))))
        (cons 'ea (list (cons 'raw ea) (cons 'formatted (if (= ea 0) "More Follows" "Last Octet"))))
        )))

    (catch (e)
      (err (str "FR parse error: " e)))))

;; dissect-fr: parse FR from bytevector
;; Returns (ok fields-alist) or (err message)