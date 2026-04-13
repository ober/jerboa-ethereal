;; packet-f5ethtrailer.c
;;
;; F5 Ethernet Trailer Copyright 2008-2018 F5 Networks
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/f5ethtrailer.ss
;; Auto-generated from wireshark/epan/dissectors/packet-f5ethtrailer.c

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
(def (dissect-f5ethtrailer buffer)
  "F5 Ethernet Trailer Protocol"
  (try
    (let* (
           (keylog (unwrap (slice buffer 0 1)))
           (command (unwrap (slice buffer 0 1)))
           (version (unwrap (slice buffer 0 1)))
           (hostname (unwrap (slice buffer 0 1)))
           (platform (unwrap (slice buffer 0 1)))
           (platformname (unwrap (slice buffer 0 1)))
           (product (unwrap (slice buffer 0 1)))
           (session (unwrap (slice buffer 0 1)))
           (hf-provider (unwrap (read-u16be buffer 3)))
           (hf-type (unwrap (read-u16be buffer 3)))
           (hf-length (unwrap (read-u16be buffer 3)))
           (hf-version (unwrap (read-u16be buffer 3)))
           (hf-ingress (unwrap (read-u8 buffer 3)))
           (hf-flags (unwrap (read-u8 buffer 3)))
           (hf-slot1 (unwrap (read-u8 buffer 4)))
           (fcs (unwrap (read-u32be buffer 4)))
           (hf-tmm (unwrap (read-u8 buffer 5)))
           (hf-vipnamelen (unwrap (read-u8 buffer 6)))
           (hf-vip (unwrap (slice buffer 7 1)))
           (data-len (unwrap (read-u8 buffer 7)))
           )

      (ok (list
        (cons 'keylog (list (cons 'raw keylog) (cons 'formatted (utf8->string keylog))))
        (cons 'command (list (cons 'raw command) (cons 'formatted (utf8->string command))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (utf8->string version))))
        (cons 'hostname (list (cons 'raw hostname) (cons 'formatted (utf8->string hostname))))
        (cons 'platform (list (cons 'raw platform) (cons 'formatted (utf8->string platform))))
        (cons 'platformname (list (cons 'raw platformname) (cons 'formatted (utf8->string platformname))))
        (cons 'product (list (cons 'raw product) (cons 'formatted (utf8->string product))))
        (cons 'session (list (cons 'raw session) (cons 'formatted (utf8->string session))))
        (cons 'hf-provider (list (cons 'raw hf-provider) (cons 'formatted (number->string hf-provider))))
        (cons 'hf-type (list (cons 'raw hf-type) (cons 'formatted (number->string hf-type))))
        (cons 'hf-length (list (cons 'raw hf-length) (cons 'formatted (number->string hf-length))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-ingress (list (cons 'raw hf-ingress) (cons 'formatted (number->string hf-ingress))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (fmt-hex hf-flags))))
        (cons 'hf-slot1 (list (cons 'raw hf-slot1) (cons 'formatted (number->string hf-slot1))))
        (cons 'fcs (list (cons 'raw fcs) (cons 'formatted (fmt-hex fcs))))
        (cons 'hf-tmm (list (cons 'raw hf-tmm) (cons 'formatted (number->string hf-tmm))))
        (cons 'hf-vipnamelen (list (cons 'raw hf-vipnamelen) (cons 'formatted (number->string hf-vipnamelen))))
        (cons 'hf-vip (list (cons 'raw hf-vip) (cons 'formatted (utf8->string hf-vip))))
        (cons 'data-len (list (cons 'raw data-len) (cons 'formatted (number->string data-len))))
        )))

    (catch (e)
      (err (str "F5ETHTRAILER parse error: " e)))))

;; dissect-f5ethtrailer: parse F5ETHTRAILER from bytevector
;; Returns (ok fields-alist) or (err message)