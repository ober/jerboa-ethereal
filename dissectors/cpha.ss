;; packet-cpha.c
;; Routines for the Check Point High-Availability Protocol (CPHAP)
;; Copyright 2002, Yaniv Kaul <mykaul -at- gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cpha.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cpha.c

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
(def (dissect-cpha buffer)
  "Check Point High Availability Protocol"
  (try
    (let* (
           (number (unwrap (read-u16be buffer 0)))
           (if-num (unwrap (read-u16be buffer 8)))
           (machine-id (unwrap (read-u16be buffer 12)))
           (id (unwrap (read-u16be buffer 16)))
           (hf-filler (unwrap (read-u16be buffer 18)))
           (data (unwrap (slice buffer 20 1)))
           (time-unit (unwrap (read-u16be buffer 26)))
           (up-num (unwrap (read-u8 buffer 31)))
           (assumed-up-num (unwrap (read-u8 buffer 32)))
           (last-packet (unwrap (read-u8 buffer 33)))
           (num (unwrap (read-u16be buffer 34)))
           (hf-seed (unwrap (read-u32be buffer 38)))
           (len (unwrap (read-u32be buffer 42)))
           (hf-ifn (unwrap (read-u32be buffer 50)))
           (reported-ifs (unwrap (read-u32be buffer 54)))
           (add (unwrap (slice buffer 58 6)))
           (if-trusted (unwrap (read-u8 buffer 64)))
           (hf-ip (unwrap (read-u32be buffer 66)))
           )

      (ok (list
        (cons 'number (list (cons 'raw number) (cons 'formatted (fmt-hex number))))
        (cons 'if-num (list (cons 'raw if-num) (cons 'formatted (number->string if-num))))
        (cons 'machine-id (list (cons 'raw machine-id) (cons 'formatted (number->string machine-id))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'hf-filler (list (cons 'raw hf-filler) (cons 'formatted (number->string hf-filler))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'time-unit (list (cons 'raw time-unit) (cons 'formatted (number->string time-unit))))
        (cons 'up-num (list (cons 'raw up-num) (cons 'formatted (number->string up-num))))
        (cons 'assumed-up-num (list (cons 'raw assumed-up-num) (cons 'formatted (number->string assumed-up-num))))
        (cons 'last-packet (list (cons 'raw last-packet) (cons 'formatted (number->string last-packet))))
        (cons 'num (list (cons 'raw num) (cons 'formatted (number->string num))))
        (cons 'hf-seed (list (cons 'raw hf-seed) (cons 'formatted (number->string hf-seed))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'hf-ifn (list (cons 'raw hf-ifn) (cons 'formatted (number->string hf-ifn))))
        (cons 'reported-ifs (list (cons 'raw reported-ifs) (cons 'formatted (number->string reported-ifs))))
        (cons 'add (list (cons 'raw add) (cons 'formatted (fmt-mac add))))
        (cons 'if-trusted (list (cons 'raw if-trusted) (cons 'formatted (number->string if-trusted))))
        (cons 'hf-ip (list (cons 'raw hf-ip) (cons 'formatted (fmt-ipv4 hf-ip))))
        )))

    (catch (e)
      (err (str "CPHA parse error: " e)))))

;; dissect-cpha: parse CPHA from bytevector
;; Returns (ok fields-alist) or (err message)