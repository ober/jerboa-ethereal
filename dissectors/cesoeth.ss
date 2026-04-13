;; packet-cesoeth.c
;; Dissection of Circuit Emulation Service over Ethernet (MEF 8)
;; www.mef.net
;;
;; Copyright 2018, AimValley B.V.
;; Jaap Keuter <jkeuter@aimvalley.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cesoeth.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cesoeth.c

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
(def (dissect-cesoeth buffer)
  "Circuit Emulation Service over Ethernet"
  (try
    (let* (
           (pw-ecid (unwrap (read-u32be buffer 0)))
           (pw-res (unwrap (read-u32be buffer 0)))
           (cw (unwrap (read-u32be buffer 4)))
           (cw-reserved1 (extract-bits cw 0xF0000000 28))
           (cw-l (extract-bits cw 0x8000000 27))
           (cw-r (extract-bits cw 0x4000000 26))
           (cw-len (extract-bits cw 0x3F0000 16))
           (cw-seq (extract-bits cw 0xFFFF 0))
           (padding (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'pw-ecid (list (cons 'raw pw-ecid) (cons 'formatted (fmt-hex pw-ecid))))
        (cons 'pw-res (list (cons 'raw pw-res) (cons 'formatted (fmt-hex pw-res))))
        (cons 'cw (list (cons 'raw cw) (cons 'formatted (fmt-hex cw))))
        (cons 'cw-reserved1 (list (cons 'raw cw-reserved1) (cons 'formatted (if (= cw-reserved1 0) "Not set" "Set"))))
        (cons 'cw-l (list (cons 'raw cw-l) (cons 'formatted (if (= cw-l 0) "Not set" "Set"))))
        (cons 'cw-r (list (cons 'raw cw-r) (cons 'formatted (if (= cw-r 0) "Not set" "Set"))))
        (cons 'cw-len (list (cons 'raw cw-len) (cons 'formatted (if (= cw-len 0) "Not set" "Set"))))
        (cons 'cw-seq (list (cons 'raw cw-seq) (cons 'formatted (if (= cw-seq 0) "Not set" "Set"))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        )))

    (catch (e)
      (err (str "CESOETH parse error: " e)))))

;; dissect-cesoeth: parse CESOETH from bytevector
;; Returns (ok fields-alist) or (err message)