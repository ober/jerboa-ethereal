;; packet-zabbix.c
;; Routines for Zabbix protocol dissection
;; Copyright 2023, Markku Leiniö <markku.leinio@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zabbix.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zabbix.c

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
(def (dissect-zabbix buffer)
  "Zabbix Protocol"
  (try
    (let* (
           (header (unwrap (slice buffer 0 4)))
           (flags (unwrap (read-u8 buffer 4)))
           (flag-reserved (extract-bits flags 0x0 0))
           (flag-largepacket (extract-bits flags 0x0 0))
           (flag-compressed (extract-bits flags 0x0 0))
           (flag-zabbix-communications (extract-bits flags 0x0 0))
           (large-length (unwrap (read-u64be buffer 5)))
           (large-uncompressed-length (unwrap (read-u64be buffer 13)))
           (large-reserved (unwrap (read-u64be buffer 13)))
           (length (unwrap (read-u32be buffer 21)))
           (uncompressed-length (unwrap (read-u32be buffer 25)))
           (reserved (unwrap (read-u32be buffer 25)))
           )

      (ok (list
        (cons 'header (list (cons 'raw header) (cons 'formatted (utf8->string header))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-reserved (list (cons 'raw flag-reserved) (cons 'formatted (if (= flag-reserved 0) "Not set" "Set"))))
        (cons 'flag-largepacket (list (cons 'raw flag-largepacket) (cons 'formatted (if (= flag-largepacket 0) "Not set" "Set"))))
        (cons 'flag-compressed (list (cons 'raw flag-compressed) (cons 'formatted (if (= flag-compressed 0) "Not set" "Set"))))
        (cons 'flag-zabbix-communications (list (cons 'raw flag-zabbix-communications) (cons 'formatted (if (= flag-zabbix-communications 0) "Not set" "Set"))))
        (cons 'large-length (list (cons 'raw large-length) (cons 'formatted (number->string large-length))))
        (cons 'large-uncompressed-length (list (cons 'raw large-uncompressed-length) (cons 'formatted (number->string large-uncompressed-length))))
        (cons 'large-reserved (list (cons 'raw large-reserved) (cons 'formatted (number->string large-reserved))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'uncompressed-length (list (cons 'raw uncompressed-length) (cons 'formatted (number->string uncompressed-length))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        )))

    (catch (e)
      (err (str "ZABBIX parse error: " e)))))

;; dissect-zabbix: parse ZABBIX from bytevector
;; Returns (ok fields-alist) or (err message)