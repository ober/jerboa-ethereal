;; packet-arp.c
;; Routines for ARP packet disassembly (RFC 826)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; By Deepti Ragha <dlragha@ncsu.edu>
;; Copyright 2012 Deepti Ragha
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/arp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-arp.c
;; RFC 826

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
(def (dissect-arp buffer)
  "Address Resolution Protocol"
  (try
    (let* (
           (isannouncement (unwrap (read-u8 buffer 0)))
           (isprobe (unwrap (read-u8 buffer 0)))
           (isgratuitous (unwrap (read-u8 buffer 0)))
           (duplicate-ip-address-seconds-since-earlier-frame (unwrap (read-u32be buffer 0)))
           (duplicate-ip-address-earlier-frame (unwrap (read-u32be buffer 0)))
           (src-atm-high-order-dsp (unwrap (slice buffer 0 10)))
           (src-atm-end-system-identifier (unwrap (slice buffer 0 6)))
           (src-atm-selector (unwrap (read-u8 buffer 0)))
           (src-atm-rest-of-address (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'isannouncement (list (cons 'raw isannouncement) (cons 'formatted (number->string isannouncement))))
        (cons 'isprobe (list (cons 'raw isprobe) (cons 'formatted (number->string isprobe))))
        (cons 'isgratuitous (list (cons 'raw isgratuitous) (cons 'formatted (number->string isgratuitous))))
        (cons 'duplicate-ip-address-seconds-since-earlier-frame (list (cons 'raw duplicate-ip-address-seconds-since-earlier-frame) (cons 'formatted (number->string duplicate-ip-address-seconds-since-earlier-frame))))
        (cons 'duplicate-ip-address-earlier-frame (list (cons 'raw duplicate-ip-address-earlier-frame) (cons 'formatted (number->string duplicate-ip-address-earlier-frame))))
        (cons 'src-atm-high-order-dsp (list (cons 'raw src-atm-high-order-dsp) (cons 'formatted (fmt-bytes src-atm-high-order-dsp))))
        (cons 'src-atm-end-system-identifier (list (cons 'raw src-atm-end-system-identifier) (cons 'formatted (fmt-bytes src-atm-end-system-identifier))))
        (cons 'src-atm-selector (list (cons 'raw src-atm-selector) (cons 'formatted (fmt-hex src-atm-selector))))
        (cons 'src-atm-rest-of-address (list (cons 'raw src-atm-rest-of-address) (cons 'formatted (fmt-bytes src-atm-rest-of-address))))
        )))

    (catch (e)
      (err (str "ARP parse error: " e)))))

;; dissect-arp: parse ARP from bytevector
;; Returns (ok fields-alist) or (err message)