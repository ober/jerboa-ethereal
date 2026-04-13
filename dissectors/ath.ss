;; packet-ath.c
;; Routines for ATH (Apache Tribes Heartbeat) dissection
;; Copyright 2015, Eugene Adell <eugene.adell@d2-si.eu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ath.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ath.c

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
(def (dissect-ath buffer)
  "Apache Tribes Heartbeat Protocol"
  (try
    (let* (
           (begin (unwrap (slice buffer 57 8)))
           (padding (unwrap (read-u16be buffer 65)))
           (length (unwrap (read-u32be buffer 67)))
           (alive (unwrap (read-u64be buffer 71)))
           (port (unwrap (read-u32be buffer 79)))
           (sport (unwrap (read-u32be buffer 83)))
           (uport (unwrap (read-u32be buffer 87)))
           (hlen (unwrap (read-u8 buffer 91)))
           (ipv4 (unwrap (read-u32be buffer 92)))
           (ipv6 (unwrap (slice buffer 92 6)))
           (clen (unwrap (read-u32be buffer 92)))
           (comm (unwrap (slice buffer 96 1)))
           (dlen (unwrap (read-u32be buffer 96)))
           (domain (unwrap (slice buffer 100 1)))
           (unique (unwrap (slice buffer 100 16)))
           (plen (unwrap (read-u32be buffer 116)))
           (payload (unwrap (slice buffer 120 1)))
           (end (unwrap (slice buffer 120 8)))
           )

      (ok (list
        (cons 'begin (list (cons 'raw begin) (cons 'formatted (utf8->string begin))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-hex padding))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'alive (list (cons 'raw alive) (cons 'formatted (number->string alive))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'sport (list (cons 'raw sport) (cons 'formatted (number->string sport))))
        (cons 'uport (list (cons 'raw uport) (cons 'formatted (number->string uport))))
        (cons 'hlen (list (cons 'raw hlen) (cons 'formatted (number->string hlen))))
        (cons 'ipv4 (list (cons 'raw ipv4) (cons 'formatted (fmt-ipv4 ipv4))))
        (cons 'ipv6 (list (cons 'raw ipv6) (cons 'formatted (fmt-ipv6-address ipv6))))
        (cons 'clen (list (cons 'raw clen) (cons 'formatted (number->string clen))))
        (cons 'comm (list (cons 'raw comm) (cons 'formatted (utf8->string comm))))
        (cons 'dlen (list (cons 'raw dlen) (cons 'formatted (number->string dlen))))
        (cons 'domain (list (cons 'raw domain) (cons 'formatted (utf8->string domain))))
        (cons 'unique (list (cons 'raw unique) (cons 'formatted (fmt-bytes unique))))
        (cons 'plen (list (cons 'raw plen) (cons 'formatted (number->string plen))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (utf8->string payload))))
        (cons 'end (list (cons 'raw end) (cons 'formatted (utf8->string end))))
        )))

    (catch (e)
      (err (str "ATH parse error: " e)))))

;; dissect-ath: parse ATH from bytevector
;; Returns (ok fields-alist) or (err message)