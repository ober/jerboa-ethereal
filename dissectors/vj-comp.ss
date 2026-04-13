;; packet-vj-comp.c
;; Routines for decompression of PPP Van Jacobson compression
;; RFC 1144
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vj-comp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vj_comp.c
;; RFC 1144

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
(def (dissect-vj-comp buffer)
  "Van Jacobson PPP compression"
  (try
    (let* (
           (change-mask (unwrap (read-u8 buffer 0)))
           (change-mask-r (extract-bits change-mask 0x0 0))
           (change-mask-c (extract-bits change-mask 0x0 0))
           (change-mask-i (extract-bits change-mask 0x0 0))
           (change-mask-p (extract-bits change-mask 0x0 0))
           (change-mask-s (extract-bits change-mask 0x0 0))
           (change-mask-a (extract-bits change-mask 0x0 0))
           (change-mask-w (extract-bits change-mask 0x0 0))
           (change-mask-u (extract-bits change-mask 0x0 0))
           (comp (unwrap (read-u8 buffer 0)))
           (cnum (unwrap (read-u8 buffer 0)))
           (chksum (unwrap (read-u16be buffer 0)))
           (d-ack (unwrap (read-u16be buffer 2)))
           (d-seq (unwrap (read-u16be buffer 2)))
           (urg (unwrap (read-u16be buffer 2)))
           (d-ipid (unwrap (read-u16be buffer 4)))
           (tcpdata (unwrap (slice buffer 4 1)))
           )

      (ok (list
        (cons 'change-mask (list (cons 'raw change-mask) (cons 'formatted (fmt-hex change-mask))))
        (cons 'change-mask-r (list (cons 'raw change-mask-r) (cons 'formatted (if (= change-mask-r 0) "Not set" "Set"))))
        (cons 'change-mask-c (list (cons 'raw change-mask-c) (cons 'formatted (if (= change-mask-c 0) "Not set" "Set"))))
        (cons 'change-mask-i (list (cons 'raw change-mask-i) (cons 'formatted (if (= change-mask-i 0) "Not set" "Set"))))
        (cons 'change-mask-p (list (cons 'raw change-mask-p) (cons 'formatted (if (= change-mask-p 0) "Not set" "Set"))))
        (cons 'change-mask-s (list (cons 'raw change-mask-s) (cons 'formatted (if (= change-mask-s 0) "Not set" "Set"))))
        (cons 'change-mask-a (list (cons 'raw change-mask-a) (cons 'formatted (if (= change-mask-a 0) "Not set" "Set"))))
        (cons 'change-mask-w (list (cons 'raw change-mask-w) (cons 'formatted (if (= change-mask-w 0) "Not set" "Set"))))
        (cons 'change-mask-u (list (cons 'raw change-mask-u) (cons 'formatted (if (= change-mask-u 0) "Not set" "Set"))))
        (cons 'comp (list (cons 'raw comp) (cons 'formatted (number->string comp))))
        (cons 'cnum (list (cons 'raw cnum) (cons 'formatted (number->string cnum))))
        (cons 'chksum (list (cons 'raw chksum) (cons 'formatted (fmt-hex chksum))))
        (cons 'd-ack (list (cons 'raw d-ack) (cons 'formatted (number->string d-ack))))
        (cons 'd-seq (list (cons 'raw d-seq) (cons 'formatted (number->string d-seq))))
        (cons 'urg (list (cons 'raw urg) (cons 'formatted (number->string urg))))
        (cons 'd-ipid (list (cons 'raw d-ipid) (cons 'formatted (number->string d-ipid))))
        (cons 'tcpdata (list (cons 'raw tcpdata) (cons 'formatted (fmt-bytes tcpdata))))
        )))

    (catch (e)
      (err (str "VJ-COMP parse error: " e)))))

;; dissect-vj-comp: parse VJ-COMP from bytevector
;; Returns (ok fields-alist) or (err message)