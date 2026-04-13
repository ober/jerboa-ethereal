;; packet-bmc.c
;; Routines for Broadcast/Multicast Control dissection
;; Copyright 2011, Neil Piercy <Neil.Piercy@ipaccess.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bmc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bmc.c

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
(def (dissect-bmc buffer)
  "Broadcast/Multicast Control"
  (try
    (let* (
           (offset-to-begin-ctch-bs-index (unwrap (read-u8 buffer 1)))
           (broadcast-address (unwrap (slice buffer 1 5)))
           (length-of-cbs-schedule-period (unwrap (read-u8 buffer 2)))
           (new-message-bitmap (unwrap (slice buffer 3 1)))
           (message-id (unwrap (read-u16be buffer 4)))
           (offset-to-ctch-bs-index-of-first-transmission (unwrap (read-u8 buffer 6)))
           (cb-data41 (unwrap (slice buffer 6 1)))
           (future-extension-bitmap (unwrap (read-u8 buffer 7)))
           (length-of-serial-number-list (unwrap (read-u8 buffer 8)))
           (serial-number (unwrap (read-u16be buffer 9)))
           (ctch-bs-index (unwrap (read-u8 buffer 11)))
           )

      (ok (list
        (cons 'offset-to-begin-ctch-bs-index (list (cons 'raw offset-to-begin-ctch-bs-index) (cons 'formatted (number->string offset-to-begin-ctch-bs-index))))
        (cons 'broadcast-address (list (cons 'raw broadcast-address) (cons 'formatted (fmt-bytes broadcast-address))))
        (cons 'length-of-cbs-schedule-period (list (cons 'raw length-of-cbs-schedule-period) (cons 'formatted (number->string length-of-cbs-schedule-period))))
        (cons 'new-message-bitmap (list (cons 'raw new-message-bitmap) (cons 'formatted (fmt-bytes new-message-bitmap))))
        (cons 'message-id (list (cons 'raw message-id) (cons 'formatted (fmt-hex message-id))))
        (cons 'offset-to-ctch-bs-index-of-first-transmission (list (cons 'raw offset-to-ctch-bs-index-of-first-transmission) (cons 'formatted (number->string offset-to-ctch-bs-index-of-first-transmission))))
        (cons 'cb-data41 (list (cons 'raw cb-data41) (cons 'formatted (fmt-bytes cb-data41))))
        (cons 'future-extension-bitmap (list (cons 'raw future-extension-bitmap) (cons 'formatted (number->string future-extension-bitmap))))
        (cons 'length-of-serial-number-list (list (cons 'raw length-of-serial-number-list) (cons 'formatted (number->string length-of-serial-number-list))))
        (cons 'serial-number (list (cons 'raw serial-number) (cons 'formatted (fmt-hex serial-number))))
        (cons 'ctch-bs-index (list (cons 'raw ctch-bs-index) (cons 'formatted (number->string ctch-bs-index))))
        )))

    (catch (e)
      (err (str "BMC parse error: " e)))))

;; dissect-bmc: parse BMC from bytevector
;; Returns (ok fields-alist) or (err message)