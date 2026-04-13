;; packet-irc.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-tftp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/irc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-irc.c
;; RFC 1459

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
(def (dissect-irc buffer)
  "Internet Relay Chat"
  (try
    (let* (
           (ctcp-delimiter-odd (unwrap (slice buffer 0 1)))
           (request (unwrap (slice buffer 0 1)))
           (request-prefix (unwrap (slice buffer 0 1)))
           (request-command (unwrap (slice buffer 0 1)))
           (request-trailer (unwrap (slice buffer 0 1)))
           (request-command-param (unwrap (slice buffer 0 1)))
           (response (unwrap (slice buffer 0 1)))
           (response-prefix (unwrap (slice buffer 0 1)))
           (response-command (unwrap (slice buffer 0 1)))
           (response-num-command (unwrap (read-u16be buffer 0)))
           (response-trailer (unwrap (slice buffer 0 1)))
           (response-command-param (unwrap (slice buffer 0 1)))
           (ctcp-command (unwrap (slice buffer 1 1)))
           )

      (ok (list
        (cons 'ctcp-delimiter-odd (list (cons 'raw ctcp-delimiter-odd) (cons 'formatted (utf8->string ctcp-delimiter-odd))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (utf8->string request))))
        (cons 'request-prefix (list (cons 'raw request-prefix) (cons 'formatted (utf8->string request-prefix))))
        (cons 'request-command (list (cons 'raw request-command) (cons 'formatted (utf8->string request-command))))
        (cons 'request-trailer (list (cons 'raw request-trailer) (cons 'formatted (utf8->string request-trailer))))
        (cons 'request-command-param (list (cons 'raw request-command-param) (cons 'formatted (utf8->string request-command-param))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (utf8->string response))))
        (cons 'response-prefix (list (cons 'raw response-prefix) (cons 'formatted (utf8->string response-prefix))))
        (cons 'response-command (list (cons 'raw response-command) (cons 'formatted (utf8->string response-command))))
        (cons 'response-num-command (list (cons 'raw response-num-command) (cons 'formatted (number->string response-num-command))))
        (cons 'response-trailer (list (cons 'raw response-trailer) (cons 'formatted (utf8->string response-trailer))))
        (cons 'response-command-param (list (cons 'raw response-command-param) (cons 'formatted (utf8->string response-command-param))))
        (cons 'ctcp-command (list (cons 'raw ctcp-command) (cons 'formatted (utf8->string ctcp-command))))
        )))

    (catch (e)
      (err (str "IRC parse error: " e)))))

;; dissect-irc: parse IRC from bytevector
;; Returns (ok fields-alist) or (err message)