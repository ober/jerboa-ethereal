;; packet-uasip.c
;; Routines for UA/UDP (Universal Alcatel over UDP) and NOE/SIP packet dissection.
;; Copyright 2012, Alcatel-Lucent Enterprise <lars.ruoff@alcatel-lucent.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/uasip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-uasip.c

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
(def (dissect-uasip buffer)
  "UA/SIP Protocol"
  (try
    (let* (
           (length (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (window-size (unwrap (read-u8 buffer 0)))
           (mtu (unwrap (read-u8 buffer 0)))
           (udp-lost (unwrap (read-u8 buffer 0)))
           (udp-lost-reinit (unwrap (read-u8 buffer 0)))
           (keepalive (unwrap (read-u8 buffer 0)))
           (qos-ip-tos (unwrap (read-u8 buffer 0)))
           (qos-8021-vlid (unwrap (read-u8 buffer 0)))
           (qos-8021-pri (unwrap (read-u8 buffer 0)))
           (expseq (unwrap (read-u16be buffer 2)))
           (sntseq (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'window-size (list (cons 'raw window-size) (cons 'formatted (number->string window-size))))
        (cons 'mtu (list (cons 'raw mtu) (cons 'formatted (number->string mtu))))
        (cons 'udp-lost (list (cons 'raw udp-lost) (cons 'formatted (number->string udp-lost))))
        (cons 'udp-lost-reinit (list (cons 'raw udp-lost-reinit) (cons 'formatted (number->string udp-lost-reinit))))
        (cons 'keepalive (list (cons 'raw keepalive) (cons 'formatted (number->string keepalive))))
        (cons 'qos-ip-tos (list (cons 'raw qos-ip-tos) (cons 'formatted (number->string qos-ip-tos))))
        (cons 'qos-8021-vlid (list (cons 'raw qos-8021-vlid) (cons 'formatted (number->string qos-8021-vlid))))
        (cons 'qos-8021-pri (list (cons 'raw qos-8021-pri) (cons 'formatted (number->string qos-8021-pri))))
        (cons 'expseq (list (cons 'raw expseq) (cons 'formatted (number->string expseq))))
        (cons 'sntseq (list (cons 'raw sntseq) (cons 'formatted (number->string sntseq))))
        )))

    (catch (e)
      (err (str "UASIP parse error: " e)))))

;; dissect-uasip: parse UASIP from bytevector
;; Returns (ok fields-alist) or (err message)