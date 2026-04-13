;; packet-usb-hub.c
;; Routines for USB HUB dissection
;; Copyright 2009, Marton Nemeth <nm127@freemail.hu>
;;
;; USB HUB Specification can be found in the Universal Serial Bus
;; Specification 2.0, Chapter 11 Hub Specification.
;; http://www.usb.org/developers/docs/usb_20_052709.zip
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/usb-hub.ss
;; Auto-generated from wireshark/epan/dissectors/packet-usb_hub.c

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
(def (dissect-usb-hub buffer)
  "USB HUB"
  (try
    (let* (
           (hub-ep-num (unwrap (read-u8 buffer 10)))
           (hub-dev-addr (unwrap (read-u8 buffer 10)))
           (hub-port-status (unwrap (read-u16le buffer 30)))
           (hub-port-change (unwrap (read-u16le buffer 32)))
           (hub-tt-flags (unwrap (read-u8 buffer 34)))
           (hub-tt-state-length (unwrap (read-u16be buffer 38)))
           (hub-descriptor-index (unwrap (read-u8 buffer 46)))
           (hub-descriptor-type (unwrap (read-u8 buffer 46)))
           (hub-descriptor-length (unwrap (read-u16be buffer 48)))
           (hub-tt-port (unwrap (read-u16be buffer 52)))
           (hub-value (unwrap (read-u16be buffer 62)))
           (hub-index (unwrap (read-u16be buffer 64)))
           (hub-port (unwrap (read-u16be buffer 64)))
           (hub-port-selector (unwrap (read-u8 buffer 64)))
           (hub-length (unwrap (read-u16be buffer 64)))
           (hub-zero (unwrap (read-u16be buffer 64)))
           )

      (ok (list
        (cons 'hub-ep-num (list (cons 'raw hub-ep-num) (cons 'formatted (number->string hub-ep-num))))
        (cons 'hub-dev-addr (list (cons 'raw hub-dev-addr) (cons 'formatted (number->string hub-dev-addr))))
        (cons 'hub-port-status (list (cons 'raw hub-port-status) (cons 'formatted (fmt-hex hub-port-status))))
        (cons 'hub-port-change (list (cons 'raw hub-port-change) (cons 'formatted (fmt-hex hub-port-change))))
        (cons 'hub-tt-flags (list (cons 'raw hub-tt-flags) (cons 'formatted (number->string hub-tt-flags))))
        (cons 'hub-tt-state-length (list (cons 'raw hub-tt-state-length) (cons 'formatted (number->string hub-tt-state-length))))
        (cons 'hub-descriptor-index (list (cons 'raw hub-descriptor-index) (cons 'formatted (number->string hub-descriptor-index))))
        (cons 'hub-descriptor-type (list (cons 'raw hub-descriptor-type) (cons 'formatted (number->string hub-descriptor-type))))
        (cons 'hub-descriptor-length (list (cons 'raw hub-descriptor-length) (cons 'formatted (number->string hub-descriptor-length))))
        (cons 'hub-tt-port (list (cons 'raw hub-tt-port) (cons 'formatted (number->string hub-tt-port))))
        (cons 'hub-value (list (cons 'raw hub-value) (cons 'formatted (fmt-hex hub-value))))
        (cons 'hub-index (list (cons 'raw hub-index) (cons 'formatted (number->string hub-index))))
        (cons 'hub-port (list (cons 'raw hub-port) (cons 'formatted (number->string hub-port))))
        (cons 'hub-port-selector (list (cons 'raw hub-port-selector) (cons 'formatted (number->string hub-port-selector))))
        (cons 'hub-length (list (cons 'raw hub-length) (cons 'formatted (number->string hub-length))))
        (cons 'hub-zero (list (cons 'raw hub-zero) (cons 'formatted (number->string hub-zero))))
        )))

    (catch (e)
      (err (str "USB-HUB parse error: " e)))))

;; dissect-usb-hub: parse USB-HUB from bytevector
;; Returns (ok fields-alist) or (err message)