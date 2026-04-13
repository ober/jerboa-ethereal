;; packet-btp-matter.c
;; Routines for Matter Bluetooth Transport Protocol (BTP) dissection
;; Copyright 2024, Arkadiusz Bokowy <a.bokowy@samsung.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btp-matter.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btp_matter.c

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
(def (dissect-btp-matter buffer)
  "Matter Bluetooth Transport Protocol"
  (try
    (let* (
           (btp-versions (unwrap (read-u32be buffer 2)))
           (btp-versions-0 (extract-bits btp-versions 0xF000000 24))
           (btp-versions-1 (extract-bits btp-versions 0xF0000000 28))
           (btp-versions-2 (extract-bits btp-versions 0xF0000 16))
           (btp-versions-3 (extract-bits btp-versions 0xF00000 20))
           (btp-versions-4 (extract-bits btp-versions 0xF00 8))
           (btp-versions-5 (extract-bits btp-versions 0xF000 12))
           (btp-versions-6 (extract-bits btp-versions 0xF 0))
           (btp-versions-7 (extract-bits btp-versions 0xF0 4))
           (btp-version (unwrap (read-u8 buffer 9)))
           (btp-mtu (unwrap (read-u16be buffer 10)))
           (btp-window-size (unwrap (read-u8 buffer 12)))
           (btp-ack (unwrap (read-u8 buffer 13)))
           (btp-seq (unwrap (read-u8 buffer 14)))
           (btp-length (unwrap (read-u16be buffer 15)))
           (btp-payload (unwrap (slice buffer 17 1)))
           )

      (ok (list
        (cons 'btp-versions (list (cons 'raw btp-versions) (cons 'formatted (fmt-hex btp-versions))))
        (cons 'btp-versions-0 (list (cons 'raw btp-versions-0) (cons 'formatted (if (= btp-versions-0 0) "Not set" "Set"))))
        (cons 'btp-versions-1 (list (cons 'raw btp-versions-1) (cons 'formatted (if (= btp-versions-1 0) "Not set" "Set"))))
        (cons 'btp-versions-2 (list (cons 'raw btp-versions-2) (cons 'formatted (if (= btp-versions-2 0) "Not set" "Set"))))
        (cons 'btp-versions-3 (list (cons 'raw btp-versions-3) (cons 'formatted (if (= btp-versions-3 0) "Not set" "Set"))))
        (cons 'btp-versions-4 (list (cons 'raw btp-versions-4) (cons 'formatted (if (= btp-versions-4 0) "Not set" "Set"))))
        (cons 'btp-versions-5 (list (cons 'raw btp-versions-5) (cons 'formatted (if (= btp-versions-5 0) "Not set" "Set"))))
        (cons 'btp-versions-6 (list (cons 'raw btp-versions-6) (cons 'formatted (if (= btp-versions-6 0) "Not set" "Set"))))
        (cons 'btp-versions-7 (list (cons 'raw btp-versions-7) (cons 'formatted (if (= btp-versions-7 0) "Not set" "Set"))))
        (cons 'btp-version (list (cons 'raw btp-version) (cons 'formatted (number->string btp-version))))
        (cons 'btp-mtu (list (cons 'raw btp-mtu) (cons 'formatted (number->string btp-mtu))))
        (cons 'btp-window-size (list (cons 'raw btp-window-size) (cons 'formatted (number->string btp-window-size))))
        (cons 'btp-ack (list (cons 'raw btp-ack) (cons 'formatted (number->string btp-ack))))
        (cons 'btp-seq (list (cons 'raw btp-seq) (cons 'formatted (number->string btp-seq))))
        (cons 'btp-length (list (cons 'raw btp-length) (cons 'formatted (number->string btp-length))))
        (cons 'btp-payload (list (cons 'raw btp-payload) (cons 'formatted (fmt-bytes btp-payload))))
        )))

    (catch (e)
      (err (str "BTP-MATTER parse error: " e)))))

;; dissect-btp-matter: parse BTP-MATTER from bytevector
;; Returns (ok fields-alist) or (err message)