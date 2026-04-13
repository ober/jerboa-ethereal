;; packet-nxp_802154_sniffer.c
;; Routines for NXP JN51xx 802.15.4 Sniffer application packet dissection
;; Copyright 2017, Lee Mitchell <lee@indigopepper.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nxp-802154-sniffer.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nxp_802154_sniffer.c

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
(def (dissect-nxp-802154-sniffer buffer)
  "NXP 802.15.4 Sniffer Protocol"
  (try
    (let* (
           (802154-sniffer-id (unwrap (slice buffer 0 1)))
           (802154-sniffer-channel (unwrap (read-u8 buffer 0)))
           (802154-sniffer-lqi (unwrap (read-u8 buffer 1)))
           (802154-sniffer-length (unwrap (read-u8 buffer 2)))
           (802154-sniffer-timestamp (unwrap (slice buffer 3 5)))
           )

      (ok (list
        (cons '802154-sniffer-id (list (cons 'raw 802154-sniffer-id) (cons 'formatted (utf8->string 802154-sniffer-id))))
        (cons '802154-sniffer-channel (list (cons 'raw 802154-sniffer-channel) (cons 'formatted (number->string 802154-sniffer-channel))))
        (cons '802154-sniffer-lqi (list (cons 'raw 802154-sniffer-lqi) (cons 'formatted (number->string 802154-sniffer-lqi))))
        (cons '802154-sniffer-length (list (cons 'raw 802154-sniffer-length) (cons 'formatted (number->string 802154-sniffer-length))))
        (cons '802154-sniffer-timestamp (list (cons 'raw 802154-sniffer-timestamp) (cons 'formatted (number->string 802154-sniffer-timestamp))))
        )))

    (catch (e)
      (err (str "NXP-802154-SNIFFER parse error: " e)))))

;; dissect-nxp-802154-sniffer: parse NXP-802154-SNIFFER from bytevector
;; Returns (ok fields-alist) or (err message)