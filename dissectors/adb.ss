;; packet-adb.c
;; Routines for Android Debug Bridge Transport Protocol
;;
;; Copyright 2014 Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/adb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-adb.c

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
(def (dissect-adb buffer)
  "Android Debug Bridge"
  (try
    (let* (
           (start-in-frame (unwrap (read-u32be buffer 0)))
           (local-in-frame (unwrap (read-u32be buffer 0)))
           (remote-in-frame (unwrap (read-u32be buffer 0)))
           (0 (unwrap (read-u32be buffer 4)))
           (1 (unwrap (read-u32be buffer 8)))
           (hf-version (unwrap (read-u32be buffer 12)))
           (data (unwrap (read-u32be buffer 12)))
           (hf-zero (unwrap (read-u32be buffer 12)))
           (id (unwrap (read-u32be buffer 12)))
           (hf-online (unwrap (read-u8 buffer 12)))
           (hf-sequence (unwrap (read-u32be buffer 12)))
           (length (unwrap (read-u32be buffer 24)))
           (crc32 (unwrap (read-u32be buffer 24)))
           (in-frame (unwrap (read-u32be buffer 24)))
           (hf-service (unwrap (slice buffer 24 1)))
           (info (unwrap (slice buffer 24 1)))
           )

      (ok (list
        (cons 'start-in-frame (list (cons 'raw start-in-frame) (cons 'formatted (number->string start-in-frame))))
        (cons 'local-in-frame (list (cons 'raw local-in-frame) (cons 'formatted (number->string local-in-frame))))
        (cons 'remote-in-frame (list (cons 'raw remote-in-frame) (cons 'formatted (number->string remote-in-frame))))
        (cons '0 (list (cons 'raw 0) (cons 'formatted (fmt-hex 0))))
        (cons '1 (list (cons 'raw 1) (cons 'formatted (fmt-hex 1))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (fmt-hex hf-version))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (number->string data))))
        (cons 'hf-zero (list (cons 'raw hf-zero) (cons 'formatted (fmt-hex hf-zero))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'hf-online (list (cons 'raw hf-online) (cons 'formatted (if (= hf-online 0) "False" "True"))))
        (cons 'hf-sequence (list (cons 'raw hf-sequence) (cons 'formatted (number->string hf-sequence))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'crc32 (list (cons 'raw crc32) (cons 'formatted (fmt-hex crc32))))
        (cons 'in-frame (list (cons 'raw in-frame) (cons 'formatted (number->string in-frame))))
        (cons 'hf-service (list (cons 'raw hf-service) (cons 'formatted (utf8->string hf-service))))
        (cons 'info (list (cons 'raw info) (cons 'formatted (utf8->string info))))
        )))

    (catch (e)
      (err (str "ADB parse error: " e)))))

;; dissect-adb: parse ADB from bytevector
;; Returns (ok fields-alist) or (err message)