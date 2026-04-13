;; packet-cell_broadcast.c
;; Routines for GSM Cell Broadcast Service dissection - A.K.A. 3GPP 23.041 (GSM 03.41) section 9.4
;;
;; Copyright 2011, Mike Morrin <mike.morrin [AT] ipaccess.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cell-broadcast.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cell_broadcast.c

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
(def (dissect-cell-broadcast buffer)
  "GSM Cell Broadcast Service"
  (try
    (let* (
           (cbs-serial-number (unwrap (read-u16be buffer 0)))
           (cbs-message-code (unwrap (read-u16be buffer 0)))
           (cbs-update-number (unwrap (read-u16be buffer 0)))
           (cbs-current-page (unwrap (read-u8 buffer 0)))
           (cbs-message-identifier (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'cbs-serial-number (list (cons 'raw cbs-serial-number) (cons 'formatted (fmt-hex cbs-serial-number))))
        (cons 'cbs-message-code (list (cons 'raw cbs-message-code) (cons 'formatted (number->string cbs-message-code))))
        (cons 'cbs-update-number (list (cons 'raw cbs-update-number) (cons 'formatted (number->string cbs-update-number))))
        (cons 'cbs-current-page (list (cons 'raw cbs-current-page) (cons 'formatted (number->string cbs-current-page))))
        (cons 'cbs-message-identifier (list (cons 'raw cbs-message-identifier) (cons 'formatted (number->string cbs-message-identifier))))
        )))

    (catch (e)
      (err (str "CELL-BROADCAST parse error: " e)))))

;; dissect-cell-broadcast: parse CELL-BROADCAST from bytevector
;; Returns (ok fields-alist) or (err message)