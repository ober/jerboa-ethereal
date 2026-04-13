;; packet-brp.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/brp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-brp.c

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
(def (dissect-brp buffer)
  "BRP Protocol"
  (try
    (let* (
           (ver (unwrap (read-u32be buffer 4)))
           (trans (unwrap (read-u24be buffer 124)))
           (rmttl (unwrap (read-u32be buffer 131)))
           (srcip (unwrap (read-u32be buffer 135)))
           (dstip (unwrap (read-u32be buffer 139)))
           (dstuport (unwrap (read-u16be buffer 143)))
           (fltype (unwrap (read-u8 buffer 147)))
           (bw (unwrap (read-u32be buffer 148)))
           (life (unwrap (read-u32be buffer 151)))
           (mbz (unwrap (read-u24be buffer 159)))
           (flid (unwrap (read-u32be buffer 162)))
           )

      (ok (list
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'trans (list (cons 'raw trans) (cons 'formatted (number->string trans))))
        (cons 'rmttl (list (cons 'raw rmttl) (cons 'formatted (number->string rmttl))))
        (cons 'srcip (list (cons 'raw srcip) (cons 'formatted (fmt-ipv4 srcip))))
        (cons 'dstip (list (cons 'raw dstip) (cons 'formatted (fmt-ipv4 dstip))))
        (cons 'dstuport (list (cons 'raw dstuport) (cons 'formatted (fmt-port dstuport))))
        (cons 'fltype (list (cons 'raw fltype) (cons 'formatted (number->string fltype))))
        (cons 'bw (list (cons 'raw bw) (cons 'formatted (number->string bw))))
        (cons 'life (list (cons 'raw life) (cons 'formatted (number->string life))))
        (cons 'mbz (list (cons 'raw mbz) (cons 'formatted (number->string mbz))))
        (cons 'flid (list (cons 'raw flid) (cons 'formatted (number->string flid))))
        )))

    (catch (e)
      (err (str "BRP parse error: " e)))))

;; dissect-brp: parse BRP from bytevector
;; Returns (ok fields-alist) or (err message)