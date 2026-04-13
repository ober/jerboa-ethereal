;; packet-cosine.c
;; Routines for decoding CoSine IPNOS L2 debug output
;;
;; Motonori Shindo <motonori@shin.do>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cosine.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cosine.c

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
(def (dissect-cosine buffer)
  "CoSine IPNOS L2 debug output"
  (try
    (let* (
           (id (unwrap (slice buffer 0 4)))
           (hf-sar (unwrap (slice buffer 0 16)))
           (hf-err (unwrap (read-u8 buffer 0)))
           (hf-rm (unwrap (read-u8 buffer 0)))
           (hf-pri (unwrap (read-u8 buffer 0)))
           (hf-off (unwrap (read-u8 buffer 0)))
           (hf-pro (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-bytes id))))
        (cons 'hf-sar (list (cons 'raw hf-sar) (cons 'formatted (fmt-bytes hf-sar))))
        (cons 'hf-err (list (cons 'raw hf-err) (cons 'formatted (number->string hf-err))))
        (cons 'hf-rm (list (cons 'raw hf-rm) (cons 'formatted (number->string hf-rm))))
        (cons 'hf-pri (list (cons 'raw hf-pri) (cons 'formatted (number->string hf-pri))))
        (cons 'hf-off (list (cons 'raw hf-off) (cons 'formatted (number->string hf-off))))
        (cons 'hf-pro (list (cons 'raw hf-pro) (cons 'formatted (number->string hf-pro))))
        )))

    (catch (e)
      (err (str "COSINE parse error: " e)))))

;; dissect-cosine: parse COSINE from bytevector
;; Returns (ok fields-alist) or (err message)