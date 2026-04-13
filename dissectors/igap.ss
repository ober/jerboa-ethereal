;; packet-igap.c
;; Routines for IGMP/IGAP packet disassembly
;; 2003, Endoh Akria (see AUTHORS for email)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/igap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-igap.c

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
(def (dissect-igap buffer)
  "Internet Group membership Authentication Protocol"
  (try
    (let* (
           (resp (unwrap (read-u8 buffer 1)))
           (hf-maddr (unwrap (read-u32be buffer 4)))
           (hf-challengeid (unwrap (read-u8 buffer 11)))
           (hf-asize (unwrap (read-u8 buffer 12)))
           (hf-msize (unwrap (read-u8 buffer 13)))
           (hf-account (unwrap (slice buffer 16 1)))
           (user-password (unwrap (slice buffer 16 1)))
           (result-of-md5-calculation (unwrap (slice buffer 16 1)))
           (challenge (unwrap (slice buffer 16 1)))
           (unknown-message (unwrap (slice buffer 16 1)))
           )

      (ok (list
        (cons 'resp (list (cons 'raw resp) (cons 'formatted (number->string resp))))
        (cons 'hf-maddr (list (cons 'raw hf-maddr) (cons 'formatted (fmt-ipv4 hf-maddr))))
        (cons 'hf-challengeid (list (cons 'raw hf-challengeid) (cons 'formatted (fmt-hex hf-challengeid))))
        (cons 'hf-asize (list (cons 'raw hf-asize) (cons 'formatted (number->string hf-asize))))
        (cons 'hf-msize (list (cons 'raw hf-msize) (cons 'formatted (number->string hf-msize))))
        (cons 'hf-account (list (cons 'raw hf-account) (cons 'formatted (utf8->string hf-account))))
        (cons 'user-password (list (cons 'raw user-password) (cons 'formatted (utf8->string user-password))))
        (cons 'result-of-md5-calculation (list (cons 'raw result-of-md5-calculation) (cons 'formatted (fmt-bytes result-of-md5-calculation))))
        (cons 'challenge (list (cons 'raw challenge) (cons 'formatted (fmt-bytes challenge))))
        (cons 'unknown-message (list (cons 'raw unknown-message) (cons 'formatted (fmt-bytes unknown-message))))
        )))

    (catch (e)
      (err (str "IGAP parse error: " e)))))

;; dissect-igap: parse IGAP from bytevector
;; Returns (ok fields-alist) or (err message)