;; packet-ple.c
;; Routines for Private Line Emulation (PLE) dissection
;;
;; Copyright 2025, AimValley B.V.
;; Jaap Keuter <jaap.keuter@aimvalley.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ple.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ple.c
;; RFC 9801

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
(def (dissect-ple buffer)
  "Private Line Emulation"
  (try
    (let* (
           (seq (unwrap (read-u32be buffer 0)))
           (cw (unwrap (read-u32be buffer 0)))
           (cw-pfn (unwrap (read-u32be buffer 0)))
           (cw-l (unwrap (read-u8 buffer 0)))
           (cw-r (unwrap (read-u8 buffer 0)))
           (cw-rsv (unwrap (read-u32be buffer 0)))
           (cw-len (unwrap (read-u32be buffer 0)))
           (cw-seq (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'cw (list (cons 'raw cw) (cons 'formatted (fmt-hex cw))))
        (cons 'cw-pfn (list (cons 'raw cw-pfn) (cons 'formatted (fmt-hex cw-pfn))))
        (cons 'cw-l (list (cons 'raw cw-l) (cons 'formatted (if (= cw-l 0) "Ok" "Attachment circuit fault"))))
        (cons 'cw-r (list (cons 'raw cw-r) (cons 'formatted (if (= cw-r 0) "Ok" "Packet loss or Backward Fault"))))
        (cons 'cw-rsv (list (cons 'raw cw-rsv) (cons 'formatted (fmt-hex cw-rsv))))
        (cons 'cw-len (list (cons 'raw cw-len) (cons 'formatted (number->string cw-len))))
        (cons 'cw-seq (list (cons 'raw cw-seq) (cons 'formatted (number->string cw-seq))))
        )))

    (catch (e)
      (err (str "PLE parse error: " e)))))

;; dissect-ple: parse PLE from bytevector
;; Returns (ok fields-alist) or (err message)