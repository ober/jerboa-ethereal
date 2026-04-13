;; packet-clique-rm.c
;; Routines for clique reliable multicast dissector
;; Copyright 2007, Collabora Ltd.
;; @author: Sjoerd Simons <sjoerd.simons@collabora.co.uk>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/clique-rm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-clique_rm.c

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
(def (dissect-clique-rm buffer)
  "Clique Reliable Multicast Protocol"
  (try
    (let* (
           (rm-data-flags (unwrap (read-u8 buffer 4)))
           (rm-data-stream-id (unwrap (read-u16be buffer 5)))
           (rm-version (unwrap (read-u8 buffer 6)))
           (rm-sender (unwrap (read-u32be buffer 6)))
           (rm-data-size (unwrap (read-u32be buffer 7)))
           (rm-data-data (unwrap (slice buffer 11 1)))
           (rm-depends (unwrap (read-u8 buffer 11)))
           (rm-depend-sender (unwrap (read-u32be buffer 12)))
           (rm-depend-packet-id (unwrap (read-u32be buffer 12)))
           (rm-packet-id (unwrap (read-u32be buffer 20)))
           (rm-whois-request-id (unwrap (read-u32be buffer 24)))
           (rm-whois-reply-name-length (unwrap (read-u8 buffer 24)))
           (rm-whois-reply-name (unwrap (slice buffer 25 1)))
           (rm-repair-request-sender-id (unwrap (read-u32be buffer 25)))
           (rm-repair-request-packet-id (unwrap (read-u32be buffer 29)))
           )

      (ok (list
        (cons 'rm-data-flags (list (cons 'raw rm-data-flags) (cons 'formatted (fmt-hex rm-data-flags))))
        (cons 'rm-data-stream-id (list (cons 'raw rm-data-stream-id) (cons 'formatted (fmt-hex rm-data-stream-id))))
        (cons 'rm-version (list (cons 'raw rm-version) (cons 'formatted (number->string rm-version))))
        (cons 'rm-sender (list (cons 'raw rm-sender) (cons 'formatted (fmt-hex rm-sender))))
        (cons 'rm-data-size (list (cons 'raw rm-data-size) (cons 'formatted (number->string rm-data-size))))
        (cons 'rm-data-data (list (cons 'raw rm-data-data) (cons 'formatted (fmt-bytes rm-data-data))))
        (cons 'rm-depends (list (cons 'raw rm-depends) (cons 'formatted (fmt-hex rm-depends))))
        (cons 'rm-depend-sender (list (cons 'raw rm-depend-sender) (cons 'formatted (fmt-hex rm-depend-sender))))
        (cons 'rm-depend-packet-id (list (cons 'raw rm-depend-packet-id) (cons 'formatted (fmt-hex rm-depend-packet-id))))
        (cons 'rm-packet-id (list (cons 'raw rm-packet-id) (cons 'formatted (fmt-hex rm-packet-id))))
        (cons 'rm-whois-request-id (list (cons 'raw rm-whois-request-id) (cons 'formatted (fmt-hex rm-whois-request-id))))
        (cons 'rm-whois-reply-name-length (list (cons 'raw rm-whois-reply-name-length) (cons 'formatted (number->string rm-whois-reply-name-length))))
        (cons 'rm-whois-reply-name (list (cons 'raw rm-whois-reply-name) (cons 'formatted (utf8->string rm-whois-reply-name))))
        (cons 'rm-repair-request-sender-id (list (cons 'raw rm-repair-request-sender-id) (cons 'formatted (fmt-hex rm-repair-request-sender-id))))
        (cons 'rm-repair-request-packet-id (list (cons 'raw rm-repair-request-packet-id) (cons 'formatted (fmt-hex rm-repair-request-packet-id))))
        )))

    (catch (e)
      (err (str "CLIQUE-RM parse error: " e)))))

;; dissect-clique-rm: parse CLIQUE-RM from bytevector
;; Returns (ok fields-alist) or (err message)