;; packet-teredo.c  v.1.0
;; Routines for Teredo packets disassembly
;; draft-huitema-v6ops-teredo-02.txt
;;
;; Copyright 2003, Ragi BEJJANI - 6WIND - <ragi.bejjani@6wind.com>
;; Copyright 2003, Vincent JARDIN - 6WIND - <vincent.jardin@6wind.com>
;; Copyright 2004, Remi DENIS-COURMONT
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/teredo.ss
;; Auto-generated from wireshark/epan/dissectors/packet-teredo.c

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
(def (dissect-teredo buffer)
  "Teredo IPv6 over UDP tunneling"
  (try
    (let* (
           (auth-idlen (unwrap (read-u8 buffer 2)))
           (auth-aulen (unwrap (read-u8 buffer 2)))
           (auth-id (unwrap (slice buffer 2 1)))
           (auth-value (unwrap (slice buffer 2 1)))
           (auth-nonce (unwrap (slice buffer 2 8)))
           (auth-conf (unwrap (slice buffer 10 1)))
           (orig-port (unwrap (read-u16be buffer 12)))
           (orig-addr (unwrap (read-u32be buffer 14)))
           )

      (ok (list
        (cons 'auth-idlen (list (cons 'raw auth-idlen) (cons 'formatted (number->string auth-idlen))))
        (cons 'auth-aulen (list (cons 'raw auth-aulen) (cons 'formatted (number->string auth-aulen))))
        (cons 'auth-id (list (cons 'raw auth-id) (cons 'formatted (fmt-bytes auth-id))))
        (cons 'auth-value (list (cons 'raw auth-value) (cons 'formatted (fmt-bytes auth-value))))
        (cons 'auth-nonce (list (cons 'raw auth-nonce) (cons 'formatted (fmt-bytes auth-nonce))))
        (cons 'auth-conf (list (cons 'raw auth-conf) (cons 'formatted (fmt-bytes auth-conf))))
        (cons 'orig-port (list (cons 'raw orig-port) (cons 'formatted (number->string orig-port))))
        (cons 'orig-addr (list (cons 'raw orig-addr) (cons 'formatted (fmt-ipv4 orig-addr))))
        )))

    (catch (e)
      (err (str "TEREDO parse error: " e)))))

;; dissect-teredo: parse TEREDO from bytevector
;; Returns (ok fields-alist) or (err message)