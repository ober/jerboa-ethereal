;; packet-ftp.c
;; Routines for ftp packet dissection
;; Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
;; Copyright 2001, Juan Toledo <toledo@users.sourceforge.net> (Passive FTP)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml
;;
;; Copied from packet-pop.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ftp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ftp.c

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
(def (dissect-ftp buffer)
  "File Transfer Protocol (FTP)"
  (try
    (let* (
           (command-command (unwrap (slice buffer 0 1)))
           (command-response-bytes (unwrap (read-u32be buffer 0)))
           (command-response-frames (unwrap (read-u32be buffer 0)))
           (current-working-directory (unwrap (slice buffer 0 1)))
           (epsv-ipv6 (unwrap (slice buffer 0 16)))
           (epsv-ip (unwrap (read-u32be buffer 0)))
           (pasv-nat (unwrap (read-u8 buffer 0)))
           (active-nat (unwrap (read-u8 buffer 0)))
           (request-command (unwrap (slice buffer 0 1)))
           (response (unwrap (read-u8 buffer 0)))
           (request (unwrap (read-u8 buffer 0)))
           (request-arg (unwrap (slice buffer 0 1)))
           (response-arg (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'command-command (list (cons 'raw command-command) (cons 'formatted (utf8->string command-command))))
        (cons 'command-response-bytes (list (cons 'raw command-response-bytes) (cons 'formatted (number->string command-response-bytes))))
        (cons 'command-response-frames (list (cons 'raw command-response-frames) (cons 'formatted (number->string command-response-frames))))
        (cons 'current-working-directory (list (cons 'raw current-working-directory) (cons 'formatted (utf8->string current-working-directory))))
        (cons 'epsv-ipv6 (list (cons 'raw epsv-ipv6) (cons 'formatted (fmt-ipv6-address epsv-ipv6))))
        (cons 'epsv-ip (list (cons 'raw epsv-ip) (cons 'formatted (fmt-ipv4 epsv-ip))))
        (cons 'pasv-nat (list (cons 'raw pasv-nat) (cons 'formatted (number->string pasv-nat))))
        (cons 'active-nat (list (cons 'raw active-nat) (cons 'formatted (number->string active-nat))))
        (cons 'request-command (list (cons 'raw request-command) (cons 'formatted (utf8->string request-command))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (number->string response))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (number->string request))))
        (cons 'request-arg (list (cons 'raw request-arg) (cons 'formatted (utf8->string request-arg))))
        (cons 'response-arg (list (cons 'raw response-arg) (cons 'formatted (utf8->string response-arg))))
        )))

    (catch (e)
      (err (str "FTP parse error: " e)))))

;; dissect-ftp: parse FTP from bytevector
;; Returns (ok fields-alist) or (err message)