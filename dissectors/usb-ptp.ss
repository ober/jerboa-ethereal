;; packet-usb-ptp.c
;;
;; USB Packet Dissector :
;; - Picture Transfer Protocol (PTP)
;; - Media   Transfer Protocol (MTP)
;;
;; (c)2013 Max Baker <max@warped.org>
;; (c)2022 Jake Merdich <jake@merdich.com>
;;
;; Much of this adapted from libgphoto2/libgphoto2/camlibs/ptp2/
;;
;; Copyright (C) 2001 Mariusz Woloszyn <emsi@ipartners.pl>
;; Copyright (C) 2003-2012 Marcus Meissner <marcus@jet.franken.de>
;; Copyright (C) 2006-2008 Linus Walleij <triad@df.lth.se>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/usb-ptp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-usb_ptp.c

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
(def (dissect-usb-ptp buffer)
  "USB Picture Transfer Protocol"
  (try
    (let* (
           (length (unwrap (read-u32be buffer 0)))
           (code (unwrap (read-u16be buffer 6)))
           (id (unwrap (read-u32be buffer 8)))
           (vendorextensionversion (unwrap (read-u16be buffer 21)))
           (functionalmode (unwrap (read-u16be buffer 23)))
           (hf-payload (unwrap (slice buffer 49 1)))
           (standardversion (unwrap (read-u16be buffer 50)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'code (list (cons 'raw code) (cons 'formatted (fmt-hex code))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'vendorextensionversion (list (cons 'raw vendorextensionversion) (cons 'formatted (fmt-hex vendorextensionversion))))
        (cons 'functionalmode (list (cons 'raw functionalmode) (cons 'formatted (fmt-hex functionalmode))))
        (cons 'hf-payload (list (cons 'raw hf-payload) (cons 'formatted (fmt-bytes hf-payload))))
        (cons 'standardversion (list (cons 'raw standardversion) (cons 'formatted (fmt-hex standardversion))))
        )))

    (catch (e)
      (err (str "USB-PTP parse error: " e)))))

;; dissect-usb-ptp: parse USB-PTP from bytevector
;; Returns (ok fields-alist) or (err message)