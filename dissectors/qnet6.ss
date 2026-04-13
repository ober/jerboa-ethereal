;; packet-qnet6.c Routines for qnet6 LwL4 dissection Copyright 2009,
;; dragonlinux <dragonlinux@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/qnet6.ss
;; Auto-generated from wireshark/epan/dissectors/packet-qnet6.c

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
(def (dissect-qnet6 buffer)
  "QNX6 QNET LWL4 protocol"
  (try
    (let* (
           (l4-flags (unwrap (read-u8 buffer 2)))
           (l4-flags-first (extract-bits l4-flags 0x0 0))
           (l4-flags-last (extract-bits l4-flags 0x0 0))
           (l4-flags-crc (extract-bits l4-flags 0x0 0))
           (l4-qos-src-nd-for-dst (unwrap (read-u16be buffer 2)))
           (l4-qos-dst-nd-for-src (unwrap (read-u16be buffer 4)))
           (l4-qos-src-conn-id (unwrap (read-u32be buffer 6)))
           (l4-qos-dst-conn-id (unwrap (read-u32be buffer 10)))
           (l4-qos-src-seq-num (unwrap (read-u32be buffer 14)))
           (l4-qos-src-qos-idx (unwrap (read-u16be buffer 20)))
           (l4-offset (unwrap (read-u32be buffer 22)))
           (l4-length (unwrap (read-u32be buffer 26)))
           (l4-crc (unwrap (read-u32be buffer 30)))
           (l4-padding (unwrap (read-u16be buffer 34)))
           )

      (ok (list
        (cons 'l4-flags (list (cons 'raw l4-flags) (cons 'formatted (fmt-hex l4-flags))))
        (cons 'l4-flags-first (list (cons 'raw l4-flags-first) (cons 'formatted (if (= l4-flags-first 0) "Not set" "Set"))))
        (cons 'l4-flags-last (list (cons 'raw l4-flags-last) (cons 'formatted (if (= l4-flags-last 0) "Not set" "Set"))))
        (cons 'l4-flags-crc (list (cons 'raw l4-flags-crc) (cons 'formatted (if (= l4-flags-crc 0) "Not set" "Set"))))
        (cons 'l4-qos-src-nd-for-dst (list (cons 'raw l4-qos-src-nd-for-dst) (cons 'formatted (number->string l4-qos-src-nd-for-dst))))
        (cons 'l4-qos-dst-nd-for-src (list (cons 'raw l4-qos-dst-nd-for-src) (cons 'formatted (number->string l4-qos-dst-nd-for-src))))
        (cons 'l4-qos-src-conn-id (list (cons 'raw l4-qos-src-conn-id) (cons 'formatted (fmt-hex l4-qos-src-conn-id))))
        (cons 'l4-qos-dst-conn-id (list (cons 'raw l4-qos-dst-conn-id) (cons 'formatted (fmt-hex l4-qos-dst-conn-id))))
        (cons 'l4-qos-src-seq-num (list (cons 'raw l4-qos-src-seq-num) (cons 'formatted (number->string l4-qos-src-seq-num))))
        (cons 'l4-qos-src-qos-idx (list (cons 'raw l4-qos-src-qos-idx) (cons 'formatted (number->string l4-qos-src-qos-idx))))
        (cons 'l4-offset (list (cons 'raw l4-offset) (cons 'formatted (number->string l4-offset))))
        (cons 'l4-length (list (cons 'raw l4-length) (cons 'formatted (number->string l4-length))))
        (cons 'l4-crc (list (cons 'raw l4-crc) (cons 'formatted (fmt-hex l4-crc))))
        (cons 'l4-padding (list (cons 'raw l4-padding) (cons 'formatted (fmt-hex l4-padding))))
        )))

    (catch (e)
      (err (str "QNET6 parse error: " e)))))

;; dissect-qnet6: parse QNET6 from bytevector
;; Returns (ok fields-alist) or (err message)