;; packet-jxta.c
;;
;; Routines for JXTA packet dissection
;; JXTA specification from https://jxta-spec.dev.java.net (now at https://github.com/chaupal/jxta-spec ?)
;;
;; Copyright 2004-08, Mike Duigou <bondolo@dev.java.net>
;;
;; Heavily based on packet-jabber.c, which in turn is heavily based on
;; on packet-acap.c, which in turn is heavily based on
;; packet-imap.c, Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
;; Copied from packet-pop.c, packet-jabber.c, packet-udp.c, packet-http.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 2000 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/jxta.ss
;; Auto-generated from wireshark/epan/dissectors/packet-jxta.c

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
(def (dissect-jxta buffer)
  "JXTA P2P"
  (try
    (let* (
           (dst (unwrap (slice buffer 0 1)))
           (message-dst (unwrap (slice buffer 0 1)))
           (addr (unwrap (slice buffer 0 1)))
           (src (unwrap (slice buffer 0 1)))
           (message-address (unwrap (slice buffer 0 1)))
           (message-src (unwrap (slice buffer 0 1)))
           (welcome-initiator (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (utf8->string dst))))
        (cons 'message-dst (list (cons 'raw message-dst) (cons 'formatted (utf8->string message-dst))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (utf8->string addr))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (utf8->string src))))
        (cons 'message-address (list (cons 'raw message-address) (cons 'formatted (utf8->string message-address))))
        (cons 'message-src (list (cons 'raw message-src) (cons 'formatted (utf8->string message-src))))
        (cons 'welcome-initiator (list (cons 'raw welcome-initiator) (cons 'formatted (number->string welcome-initiator))))
        )))

    (catch (e)
      (err (str "JXTA parse error: " e)))))

;; dissect-jxta: parse JXTA from bytevector
;; Returns (ok fields-alist) or (err message)