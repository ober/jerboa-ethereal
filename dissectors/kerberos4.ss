;; packet-kerberos4.c
;; Routines for Kerberos v4 packet dissection
;;
;; Ronnie Sahlberg 2004
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/kerberos4.ss
;; Auto-generated from wireshark/epan/dissectors/packet-kerberos4.c

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
(def (dissect-kerberos4 buffer)
  "Kerberos v4"
  (try
    (let* (
           (unknown-transarc-blob (unwrap (slice buffer 0 8)))
           (version (unwrap (read-u8 buffer 0)))
           (length (unwrap (read-u32be buffer 20)))
           (encrypted-blob (unwrap (slice buffer 22 1)))
           (kvno (unwrap (read-u8 buffer 22)))
           (ticket-length (unwrap (read-u8 buffer 22)))
           (request-length (unwrap (read-u8 buffer 22)))
           (ticket-blob (unwrap (slice buffer 22 1)))
           (request-blob (unwrap (slice buffer 22 1)))
           (lifetime (unwrap (read-u8 buffer 26)))
           (auth-msg-type (unwrap (read-u8 buffer 26)))
           )

      (ok (list
        (cons 'unknown-transarc-blob (list (cons 'raw unknown-transarc-blob) (cons 'formatted (fmt-bytes unknown-transarc-blob))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'encrypted-blob (list (cons 'raw encrypted-blob) (cons 'formatted (fmt-bytes encrypted-blob))))
        (cons 'kvno (list (cons 'raw kvno) (cons 'formatted (number->string kvno))))
        (cons 'ticket-length (list (cons 'raw ticket-length) (cons 'formatted (number->string ticket-length))))
        (cons 'request-length (list (cons 'raw request-length) (cons 'formatted (number->string request-length))))
        (cons 'ticket-blob (list (cons 'raw ticket-blob) (cons 'formatted (fmt-bytes ticket-blob))))
        (cons 'request-blob (list (cons 'raw request-blob) (cons 'formatted (fmt-bytes request-blob))))
        (cons 'lifetime (list (cons 'raw lifetime) (cons 'formatted (number->string lifetime))))
        (cons 'auth-msg-type (list (cons 'raw auth-msg-type) (cons 'formatted (fmt-hex auth-msg-type))))
        )))

    (catch (e)
      (err (str "KERBEROS4 parse error: " e)))))

;; dissect-kerberos4: parse KERBEROS4 from bytevector
;; Returns (ok fields-alist) or (err message)