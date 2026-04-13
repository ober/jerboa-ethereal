;; packet-http.c
;; Routines for HTTP packet disassembly
;; RFC 1945 (HTTP/1.0)
;; RFC 2616 (HTTP/1.1)
;;
;; Guy Harris <guy@alum.mit.edu>
;;
;; Copyright 2017, Eugene Adell <eugene.adell@gmail.com>
;; Copyright 2004, Jerry Talkington <jtalkington@users.sourceforge.net>
;; Copyright 2002, Tim Potter <tpot@samba.org>
;; Copyright 1999, Andrew Tridgell <tridge@samba.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/http.ss
;; Auto-generated from wireshark/epan/dissectors/packet-http.c
;; RFC 1945

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
(def (dissect-http buffer)
  "Hypertext Transfer Protocol"
  (try
    (let* (
           (citrix (unwrap (read-u8 buffer 0)))
           (proxy-connect-port (unwrap (read-u16be buffer 0)))
           (proxy-connect-host (unwrap (slice buffer 0 1)))
           (request (unwrap (read-u8 buffer 0)))
           (request-full-uri (unwrap (slice buffer 0 1)))
           (response (unwrap (read-u8 buffer 0)))
           (notification (unwrap (read-u8 buffer 0)))
           (request-path (unwrap (slice buffer 0 1)))
           (request-path-segment (unwrap (slice buffer 0 1)))
           (request-query-parameter (unwrap (slice buffer 0 1)))
           (request-method (unwrap (slice buffer 10 1)))
           (request-uri (unwrap (slice buffer 10 1)))
           (request-version (unwrap (slice buffer 10 1)))
           (response-version (unwrap (slice buffer 10 1)))
           (response-code (unwrap (read-u24be buffer 10)))
           (response-code-desc (unwrap (slice buffer 10 3)))
           (response-phrase (unwrap (slice buffer 10 1)))
           (chunked-trailer-part (unwrap (slice buffer 12 1)))
           (unknown-header (unwrap (slice buffer 12 1)))
           (content-length (unwrap (read-u64be buffer 12)))
           (citrix-user (unwrap (slice buffer 31 1)))
           (citrix-domain (unwrap (slice buffer 41 1)))
           (citrix-passwd (unwrap (slice buffer 53 1)))
           (citrix-session (unwrap (slice buffer 69 1)))
           )

      (ok (list
        (cons 'citrix (list (cons 'raw citrix) (cons 'formatted (number->string citrix))))
        (cons 'proxy-connect-port (list (cons 'raw proxy-connect-port) (cons 'formatted (number->string proxy-connect-port))))
        (cons 'proxy-connect-host (list (cons 'raw proxy-connect-host) (cons 'formatted (utf8->string proxy-connect-host))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (number->string request))))
        (cons 'request-full-uri (list (cons 'raw request-full-uri) (cons 'formatted (utf8->string request-full-uri))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (number->string response))))
        (cons 'notification (list (cons 'raw notification) (cons 'formatted (number->string notification))))
        (cons 'request-path (list (cons 'raw request-path) (cons 'formatted (utf8->string request-path))))
        (cons 'request-path-segment (list (cons 'raw request-path-segment) (cons 'formatted (utf8->string request-path-segment))))
        (cons 'request-query-parameter (list (cons 'raw request-query-parameter) (cons 'formatted (utf8->string request-query-parameter))))
        (cons 'request-method (list (cons 'raw request-method) (cons 'formatted (utf8->string request-method))))
        (cons 'request-uri (list (cons 'raw request-uri) (cons 'formatted (utf8->string request-uri))))
        (cons 'request-version (list (cons 'raw request-version) (cons 'formatted (utf8->string request-version))))
        (cons 'response-version (list (cons 'raw response-version) (cons 'formatted (utf8->string response-version))))
        (cons 'response-code (list (cons 'raw response-code) (cons 'formatted (number->string response-code))))
        (cons 'response-code-desc (list (cons 'raw response-code-desc) (cons 'formatted (utf8->string response-code-desc))))
        (cons 'response-phrase (list (cons 'raw response-phrase) (cons 'formatted (utf8->string response-phrase))))
        (cons 'chunked-trailer-part (list (cons 'raw chunked-trailer-part) (cons 'formatted (utf8->string chunked-trailer-part))))
        (cons 'unknown-header (list (cons 'raw unknown-header) (cons 'formatted (utf8->string unknown-header))))
        (cons 'content-length (list (cons 'raw content-length) (cons 'formatted (number->string content-length))))
        (cons 'citrix-user (list (cons 'raw citrix-user) (cons 'formatted (utf8->string citrix-user))))
        (cons 'citrix-domain (list (cons 'raw citrix-domain) (cons 'formatted (utf8->string citrix-domain))))
        (cons 'citrix-passwd (list (cons 'raw citrix-passwd) (cons 'formatted (utf8->string citrix-passwd))))
        (cons 'citrix-session (list (cons 'raw citrix-session) (cons 'formatted (utf8->string citrix-session))))
        )))

    (catch (e)
      (err (str "HTTP parse error: " e)))))

;; dissect-http: parse HTTP from bytevector
;; Returns (ok fields-alist) or (err message)