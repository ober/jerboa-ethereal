;; packet-nisplus.c
;; 2001  Ronnie Sahlberg   <See AUTHORS for email>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nisplus.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nisplus.c

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
(def (dissect-nisplus buffer)
  "NIS+"
  (try
    (let* (
           (access-mask (unwrap (read-u32be buffer 4)))
           (table-col-mask (unwrap (read-u32be buffer 8)))
           (entry-mask (unwrap (read-u32be buffer 12)))
           (entry-mask-binary (extract-bits entry-mask 0x0 0))
           (entry-mask-crypt (extract-bits entry-mask 0x0 0))
           (entry-mask-xdr (extract-bits entry-mask 0x0 0))
           (entry-mask-modified (extract-bits entry-mask 0x0 0))
           (entry-mask-asn (extract-bits entry-mask 0x0 0))
           )

      (ok (list
        (cons 'access-mask (list (cons 'raw access-mask) (cons 'formatted (fmt-hex access-mask))))
        (cons 'table-col-mask (list (cons 'raw table-col-mask) (cons 'formatted (fmt-hex table-col-mask))))
        (cons 'entry-mask (list (cons 'raw entry-mask) (cons 'formatted (fmt-hex entry-mask))))
        (cons 'entry-mask-binary (list (cons 'raw entry-mask-binary) (cons 'formatted (if (= entry-mask-binary 0) "entry is NOT binary" "entry is binary"))))
        (cons 'entry-mask-crypt (list (cons 'raw entry-mask-crypt) (cons 'formatted (if (= entry-mask-crypt 0) "entry is NOT encrypted" "entry is encrypted"))))
        (cons 'entry-mask-xdr (list (cons 'raw entry-mask-xdr) (cons 'formatted (if (= entry-mask-xdr 0) "entry is NOT xdr encoded" "entry is xdr encoded"))))
        (cons 'entry-mask-modified (list (cons 'raw entry-mask-modified) (cons 'formatted (if (= entry-mask-modified 0) "entry is NOT modified" "entry is modified"))))
        (cons 'entry-mask-asn (list (cons 'raw entry-mask-asn) (cons 'formatted (if (= entry-mask-asn 0) "entry is NOT asn.1 encoded" "entry is asn.1 encoded"))))
        )))

    (catch (e)
      (err (str "NISPLUS parse error: " e)))))

;; dissect-nisplus: parse NISPLUS from bytevector
;; Returns (ok fields-alist) or (err message)