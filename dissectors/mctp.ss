;; packet-mctp.c
;; Routines for Management Component Transport Protocol (MCTP) packet
;; disassembly
;; Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mctp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mctp.c

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
(def (dissect-mctp buffer)
  "MCTP"
  (try
    (let* (
           (ver (unwrap (read-u8 buffer 0)))
           (dst (unwrap (read-u8 buffer 1)))
           (src (unwrap (read-u8 buffer 2)))
           (tag (unwrap (read-u8 buffer 3)))
           (tag-to (extract-bits tag 0x8 3))
           (tag-value (extract-bits tag 0x7 0))
           (flags (unwrap (read-u8 buffer 3)))
           (flags-som (extract-bits flags 0x80 7))
           (flags-eom (extract-bits flags 0x40 6))
           (seq (unwrap (read-u8 buffer 3)))
           )

      (ok (list
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (number->string dst))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (number->string src))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (fmt-hex tag))))
        (cons 'tag-to (list (cons 'raw tag-to) (cons 'formatted (if (= tag-to 0) "Receiver" "Sender"))))
        (cons 'tag-value (list (cons 'raw tag-value) (cons 'formatted (if (= tag-value 0) "Not set" "Set"))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-som (list (cons 'raw flags-som) (cons 'formatted (if (= flags-som 0) "Not set" "Set"))))
        (cons 'flags-eom (list (cons 'raw flags-eom) (cons 'formatted (if (= flags-eom 0) "Not set" "Set"))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (fmt-hex seq))))
        )))

    (catch (e)
      (err (str "MCTP parse error: " e)))))

;; dissect-mctp: parse MCTP from bytevector
;; Returns (ok fields-alist) or (err message)