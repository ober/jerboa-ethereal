;; packet-tibia.c
;; Routines for Tibia/OTServ login and game protocol dissection
;;
;; Copyright 2017, Ahmad Fatoum <ahmad[AT]a3f.at>
;;
;; A dissector for:
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tibia.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tibia.c

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
(def (dissect-tibia buffer)
  "Tibia Protocol"
  (try
    (let* (
           (len (unwrap (read-u16be buffer 0)))
           (proto-version (unwrap (read-u16be buffer 13)))
           (client-version (unwrap (read-u32be buffer 15)))
           (file-version-spr (unwrap (read-u32be buffer 19)))
           (file-version-dat (unwrap (read-u32be buffer 23)))
           (file-version-pic (unwrap (read-u32be buffer 27)))
           (content-revision (unwrap (read-u16be buffer 31)))
           (game-preview-state (unwrap (read-u8 buffer 33)))
           (undecoded-rsa-data (unwrap (slice buffer 34 1)))
           )

      (ok (list
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'proto-version (list (cons 'raw proto-version) (cons 'formatted (number->string proto-version))))
        (cons 'client-version (list (cons 'raw client-version) (cons 'formatted (number->string client-version))))
        (cons 'file-version-spr (list (cons 'raw file-version-spr) (cons 'formatted (fmt-hex file-version-spr))))
        (cons 'file-version-dat (list (cons 'raw file-version-dat) (cons 'formatted (fmt-hex file-version-dat))))
        (cons 'file-version-pic (list (cons 'raw file-version-pic) (cons 'formatted (fmt-hex file-version-pic))))
        (cons 'content-revision (list (cons 'raw content-revision) (cons 'formatted (fmt-hex content-revision))))
        (cons 'game-preview-state (list (cons 'raw game-preview-state) (cons 'formatted (number->string game-preview-state))))
        (cons 'undecoded-rsa-data (list (cons 'raw undecoded-rsa-data) (cons 'formatted (fmt-bytes undecoded-rsa-data))))
        )))

    (catch (e)
      (err (str "TIBIA parse error: " e)))))

;; dissect-tibia: parse TIBIA from bytevector
;; Returns (ok fields-alist) or (err message)