;; packet-ipmi-app.c
;; Sub-dissectors for IPMI messages (netFn=Application)
;; Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipmi-app.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipmi_app.c

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
(def (dissect-ipmi-app buffer)
  "ipmi-app dissector"
  (try
    (let* (
           (app-3c-session-id (unwrap (read-u32be buffer 0)))
           (app-39-temp-session (unwrap (read-u32be buffer 0)))
           (app-05-devspec (unwrap (slice buffer 0 1)))
           (app-01-dev-id (unwrap (read-u8 buffer 0)))
           (app-3a-session-id (unwrap (read-u32be buffer 1)))
           (app-39-user (unwrap (slice buffer 1 16)))
           (app-04-fail (unwrap (read-u8 buffer 1)))
           (app-3a-authcode (unwrap (slice buffer 2 16)))
           (app-01-fw-rev-min (unwrap (read-u8 buffer 3)))
           (app-3c-session-handle (unwrap (read-u8 buffer 4)))
           (app-39-challenge (unwrap (slice buffer 4 16)))
           (app-38-rs-oem-iana (unwrap (read-u24be buffer 4)))
           (app-25-initial-countdown (unwrap (read-u16be buffer 4)))
           (app-24-initial-countdown (unwrap (read-u16be buffer 4)))
           (app-3a-inbound-seq (unwrap (read-u32be buffer 5)))
           (app-25-present-countdown (unwrap (read-u16be buffer 6)))
           (app-01-manufacturer (unwrap (read-u24be buffer 6)))
           (app-38-rs-oem-aux (unwrap (read-u8 buffer 7)))
           (app-01-product (unwrap (read-u16be buffer 9)))
           (app-01-fw-aux (unwrap (slice buffer 11 4)))
           (app-3a-outbound-seq (unwrap (read-u32be buffer 18)))
           )

      (ok (list
        (cons 'app-3c-session-id (list (cons 'raw app-3c-session-id) (cons 'formatted (fmt-hex app-3c-session-id))))
        (cons 'app-39-temp-session (list (cons 'raw app-39-temp-session) (cons 'formatted (fmt-hex app-39-temp-session))))
        (cons 'app-05-devspec (list (cons 'raw app-05-devspec) (cons 'formatted (fmt-bytes app-05-devspec))))
        (cons 'app-01-dev-id (list (cons 'raw app-01-dev-id) (cons 'formatted (fmt-hex app-01-dev-id))))
        (cons 'app-3a-session-id (list (cons 'raw app-3a-session-id) (cons 'formatted (fmt-hex app-3a-session-id))))
        (cons 'app-39-user (list (cons 'raw app-39-user) (cons 'formatted (utf8->string app-39-user))))
        (cons 'app-04-fail (list (cons 'raw app-04-fail) (cons 'formatted (fmt-hex app-04-fail))))
        (cons 'app-3a-authcode (list (cons 'raw app-3a-authcode) (cons 'formatted (fmt-bytes app-3a-authcode))))
        (cons 'app-01-fw-rev-min (list (cons 'raw app-01-fw-rev-min) (cons 'formatted (fmt-hex app-01-fw-rev-min))))
        (cons 'app-3c-session-handle (list (cons 'raw app-3c-session-handle) (cons 'formatted (fmt-hex app-3c-session-handle))))
        (cons 'app-39-challenge (list (cons 'raw app-39-challenge) (cons 'formatted (fmt-bytes app-39-challenge))))
        (cons 'app-38-rs-oem-iana (list (cons 'raw app-38-rs-oem-iana) (cons 'formatted (number->string app-38-rs-oem-iana))))
        (cons 'app-25-initial-countdown (list (cons 'raw app-25-initial-countdown) (cons 'formatted (number->string app-25-initial-countdown))))
        (cons 'app-24-initial-countdown (list (cons 'raw app-24-initial-countdown) (cons 'formatted (number->string app-24-initial-countdown))))
        (cons 'app-3a-inbound-seq (list (cons 'raw app-3a-inbound-seq) (cons 'formatted (fmt-hex app-3a-inbound-seq))))
        (cons 'app-25-present-countdown (list (cons 'raw app-25-present-countdown) (cons 'formatted (number->string app-25-present-countdown))))
        (cons 'app-01-manufacturer (list (cons 'raw app-01-manufacturer) (cons 'formatted (number->string app-01-manufacturer))))
        (cons 'app-38-rs-oem-aux (list (cons 'raw app-38-rs-oem-aux) (cons 'formatted (fmt-hex app-38-rs-oem-aux))))
        (cons 'app-01-product (list (cons 'raw app-01-product) (cons 'formatted (fmt-hex app-01-product))))
        (cons 'app-01-fw-aux (list (cons 'raw app-01-fw-aux) (cons 'formatted (fmt-bytes app-01-fw-aux))))
        (cons 'app-3a-outbound-seq (list (cons 'raw app-3a-outbound-seq) (cons 'formatted (fmt-hex app-3a-outbound-seq))))
        )))

    (catch (e)
      (err (str "IPMI-APP parse error: " e)))))

;; dissect-ipmi-app: parse IPMI-APP from bytevector
;; Returns (ok fields-alist) or (err message)