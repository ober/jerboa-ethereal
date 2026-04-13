;; packet-btbnep.c
;; Routines for Bluetooth BNEP dissection
;;
;; Copyright 2012, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btbnep.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btbnep.c

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
(def (dissect-btbnep buffer)
  "Bluetooth BNEP Protocol"
  (try
    (let* (
           (extension-flag (unwrap (read-u8 buffer 0)))
           (dst (unwrap (slice buffer 1 6)))
           (addr (unwrap (slice buffer 1 6)))
           (lg (unwrap (read-u8 buffer 1)))
           (ig (unwrap (read-u8 buffer 1)))
           (src (unwrap (slice buffer 1 6)))
           (len (unwrap (read-u16be buffer 1)))
           (invalid-lentype (unwrap (read-u16be buffer 1)))
           (uuid-size (unwrap (read-u8 buffer 2)))
           (list-length (unwrap (read-u16be buffer 13)))
           (multicast-address-start (unwrap (slice buffer 15 6)))
           (multicast-address-end (unwrap (slice buffer 15 6)))
           (extension-length (unwrap (read-u8 buffer 18)))
           )

      (ok (list
        (cons 'extension-flag (list (cons 'raw extension-flag) (cons 'formatted (number->string extension-flag))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (fmt-mac dst))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (fmt-mac addr))))
        (cons 'lg (list (cons 'raw lg) (cons 'formatted (if (= lg 0) "Globally unique address (factory default)" "Locally administered address (this is NOT the factory default)"))))
        (cons 'ig (list (cons 'raw ig) (cons 'formatted (if (= ig 0) "Individual address (unicast)" "Group address (multicast/broadcast)"))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (fmt-mac src))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'invalid-lentype (list (cons 'raw invalid-lentype) (cons 'formatted (fmt-hex invalid-lentype))))
        (cons 'uuid-size (list (cons 'raw uuid-size) (cons 'formatted (number->string uuid-size))))
        (cons 'list-length (list (cons 'raw list-length) (cons 'formatted (number->string list-length))))
        (cons 'multicast-address-start (list (cons 'raw multicast-address-start) (cons 'formatted (fmt-mac multicast-address-start))))
        (cons 'multicast-address-end (list (cons 'raw multicast-address-end) (cons 'formatted (fmt-mac multicast-address-end))))
        (cons 'extension-length (list (cons 'raw extension-length) (cons 'formatted (number->string extension-length))))
        )))

    (catch (e)
      (err (str "BTBNEP parse error: " e)))))

;; dissect-btbnep: parse BTBNEP from bytevector
;; Returns (ok fields-alist) or (err message)