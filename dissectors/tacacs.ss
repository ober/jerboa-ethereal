;; packet-tacacs.c
;; Routines for cisco tacacs/xtacacs/tacacs+ packet dissection
;; Copyright 2001, Paul Ionescu <paul@acorp.ro>
;;
;; Full Tacacs+ parsing with decryption by
;; Emanuele Caratti <wiz@iol.it>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from old packet-tacacs.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tacacs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tacacs.c

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
(def (dissect-tacacs buffer)
  "TACACS"
  (try
    (let* (
           (minvers (unwrap (read-u8 buffer 0)))
           (majvers (unwrap (read-u8 buffer 0)))
           (response (unwrap (read-u8 buffer 0)))
           (request (unwrap (read-u8 buffer 0)))
           (privilege-level (unwrap (read-u8 buffer 0)))
           (user-len (unwrap (read-u8 buffer 0)))
           (port-len (unwrap (read-u8 buffer 0)))
           (remote-address-len (unwrap (read-u8 buffer 0)))
           (seqno (unwrap (read-u8 buffer 2)))
           (nonce (unwrap (read-u16be buffer 2)))
           (flags-connection-type (unwrap (read-u8 buffer 3)))
           (flags-payload-type (unwrap (read-u8 buffer 3)))
           (flags (unwrap (read-u8 buffer 3)))
           (session-id (unwrap (read-u32be buffer 4)))
           (userlen (unwrap (read-u8 buffer 4)))
           (passlen (unwrap (read-u8 buffer 5)))
           (username (unwrap (slice buffer 6 1)))
           (packet-len (unwrap (read-u32be buffer 8)))
           (result1 (unwrap (read-u32be buffer 8)))
           (destaddr (unwrap (read-u32be buffer 12)))
           (destport (unwrap (read-u16be buffer 16)))
           (line (unwrap (read-u16be buffer 18)))
           (result2 (unwrap (read-u32be buffer 20)))
           (result3 (unwrap (read-u16be buffer 24)))
           )

      (ok (list
        (cons 'minvers (list (cons 'raw minvers) (cons 'formatted (number->string minvers))))
        (cons 'majvers (list (cons 'raw majvers) (cons 'formatted (number->string majvers))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (number->string response))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (number->string request))))
        (cons 'privilege-level (list (cons 'raw privilege-level) (cons 'formatted (number->string privilege-level))))
        (cons 'user-len (list (cons 'raw user-len) (cons 'formatted (number->string user-len))))
        (cons 'port-len (list (cons 'raw port-len) (cons 'formatted (number->string port-len))))
        (cons 'remote-address-len (list (cons 'raw remote-address-len) (cons 'formatted (number->string remote-address-len))))
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-hex nonce))))
        (cons 'flags-connection-type (list (cons 'raw flags-connection-type) (cons 'formatted (if (= flags-connection-type 0) "False" "True"))))
        (cons 'flags-payload-type (list (cons 'raw flags-payload-type) (cons 'formatted (if (= flags-payload-type 0) "False" "True"))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (number->string session-id))))
        (cons 'userlen (list (cons 'raw userlen) (cons 'formatted (number->string userlen))))
        (cons 'passlen (list (cons 'raw passlen) (cons 'formatted (number->string passlen))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'packet-len (list (cons 'raw packet-len) (cons 'formatted (number->string packet-len))))
        (cons 'result1 (list (cons 'raw result1) (cons 'formatted (fmt-hex result1))))
        (cons 'destaddr (list (cons 'raw destaddr) (cons 'formatted (fmt-ipv4 destaddr))))
        (cons 'destport (list (cons 'raw destport) (cons 'formatted (number->string destport))))
        (cons 'line (list (cons 'raw line) (cons 'formatted (number->string line))))
        (cons 'result2 (list (cons 'raw result2) (cons 'formatted (fmt-hex result2))))
        (cons 'result3 (list (cons 'raw result3) (cons 'formatted (fmt-hex result3))))
        )))

    (catch (e)
      (err (str "TACACS parse error: " e)))))

;; dissect-tacacs: parse TACACS from bytevector
;; Returns (ok fields-alist) or (err message)