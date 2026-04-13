;; packet-ieee80211-prism.c
;; Routines for Prism monitoring mode header dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;; Copyright (c) 2016, The Linux Foundation. All rights reserved.
;; Copyright 2016 Cisco Meraki
;;
;; Copied from README.developer
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/ieee80211-prism.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ieee80211_prism.c

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
(def (dissect-ieee80211-prism buffer)
  "Prism capture header"
  (try
    (let* (
           (prism-msgcode (unwrap (read-u32be buffer 0)))
           (prism-msglen (unwrap (read-u32be buffer 4)))
           (prism-devname (unwrap (slice buffer 8 16)))
           (prism-did-length (unwrap (read-u16be buffer 30)))
           (prism-did-hosttime (unwrap (read-u32be buffer 32)))
           (prism-did-mactime (unwrap (read-u32be buffer 32)))
           (prism-did-channel (unwrap (read-u32be buffer 32)))
           (prism-did-rssi (unwrap (read-u32be buffer 32)))
           (prism-did-sq (unwrap (read-u32be buffer 32)))
           (prism-did-signal (unwrap (read-u32be buffer 32)))
           (prism-did-noise (unwrap (read-u32be buffer 32)))
           (prism-did-sig-a1 (unwrap (read-u32be buffer 32)))
           (prism-did-sig-a2 (unwrap (read-u32be buffer 32)))
           (prism-did-sig-b (unwrap (read-u32be buffer 32)))
           (prism-did-frmlen (unwrap (read-u32be buffer 32)))
           (prism-did-unknown (unwrap (read-u32be buffer 32)))
           )

      (ok (list
        (cons 'prism-msgcode (list (cons 'raw prism-msgcode) (cons 'formatted (fmt-hex prism-msgcode))))
        (cons 'prism-msglen (list (cons 'raw prism-msglen) (cons 'formatted (number->string prism-msglen))))
        (cons 'prism-devname (list (cons 'raw prism-devname) (cons 'formatted (utf8->string prism-devname))))
        (cons 'prism-did-length (list (cons 'raw prism-did-length) (cons 'formatted (number->string prism-did-length))))
        (cons 'prism-did-hosttime (list (cons 'raw prism-did-hosttime) (cons 'formatted (number->string prism-did-hosttime))))
        (cons 'prism-did-mactime (list (cons 'raw prism-did-mactime) (cons 'formatted (number->string prism-did-mactime))))
        (cons 'prism-did-channel (list (cons 'raw prism-did-channel) (cons 'formatted (number->string prism-did-channel))))
        (cons 'prism-did-rssi (list (cons 'raw prism-did-rssi) (cons 'formatted (number->string prism-did-rssi))))
        (cons 'prism-did-sq (list (cons 'raw prism-did-sq) (cons 'formatted (number->string prism-did-sq))))
        (cons 'prism-did-signal (list (cons 'raw prism-did-signal) (cons 'formatted (number->string prism-did-signal))))
        (cons 'prism-did-noise (list (cons 'raw prism-did-noise) (cons 'formatted (number->string prism-did-noise))))
        (cons 'prism-did-sig-a1 (list (cons 'raw prism-did-sig-a1) (cons 'formatted (fmt-hex prism-did-sig-a1))))
        (cons 'prism-did-sig-a2 (list (cons 'raw prism-did-sig-a2) (cons 'formatted (fmt-hex prism-did-sig-a2))))
        (cons 'prism-did-sig-b (list (cons 'raw prism-did-sig-b) (cons 'formatted (fmt-hex prism-did-sig-b))))
        (cons 'prism-did-frmlen (list (cons 'raw prism-did-frmlen) (cons 'formatted (number->string prism-did-frmlen))))
        (cons 'prism-did-unknown (list (cons 'raw prism-did-unknown) (cons 'formatted (fmt-hex prism-did-unknown))))
        )))

    (catch (e)
      (err (str "IEEE80211-PRISM parse error: " e)))))

;; dissect-ieee80211-prism: parse IEEE80211-PRISM from bytevector
;; Returns (ok fields-alist) or (err message)