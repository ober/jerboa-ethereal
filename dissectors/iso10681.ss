;; packet-iso10681.c
;; ISO 10681-2 ISO FlexRay TP
;; By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
;; Copyright 2021-2023 Dr. Lars Voelker
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Also see packet-iso15765.c / packet-iso15765.h
;;

;; jerboa-ethereal/dissectors/iso10681.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iso10681.c

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
(def (dissect-iso10681 buffer)
  "ISO10681 Protocol"
  (try
    (let* (
           (target-address (unwrap (read-u16be buffer 0)))
           (source-address (unwrap (read-u16be buffer 2)))
           (sequence-number (unwrap (read-u8 buffer 8)))
           (frame-payload-length (unwrap (read-u8 buffer 10)))
           (message-length (unwrap (read-u16be buffer 10)))
           (fc-bandwidth-control (unwrap (read-u8 buffer 14)))
           (fc-bc-max-num-pdu-per-cycle (extract-bits fc-bandwidth-control 0xF8 3))
           (fc-buffer-size (unwrap (read-u16be buffer 14)))
           (fc-byte-position (unwrap (read-u16be buffer 14)))
           )

      (ok (list
        (cons 'target-address (list (cons 'raw target-address) (cons 'formatted (fmt-hex target-address))))
        (cons 'source-address (list (cons 'raw source-address) (cons 'formatted (fmt-hex source-address))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'frame-payload-length (list (cons 'raw frame-payload-length) (cons 'formatted (number->string frame-payload-length))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'fc-bandwidth-control (list (cons 'raw fc-bandwidth-control) (cons 'formatted (number->string fc-bandwidth-control))))
        (cons 'fc-bc-max-num-pdu-per-cycle (list (cons 'raw fc-bc-max-num-pdu-per-cycle) (cons 'formatted (if (= fc-bc-max-num-pdu-per-cycle 0) "Not set" "Set"))))
        (cons 'fc-buffer-size (list (cons 'raw fc-buffer-size) (cons 'formatted (number->string fc-buffer-size))))
        (cons 'fc-byte-position (list (cons 'raw fc-byte-position) (cons 'formatted (fmt-hex fc-byte-position))))
        )))

    (catch (e)
      (err (str "ISO10681 parse error: " e)))))

;; dissect-iso10681: parse ISO10681 from bytevector
;; Returns (ok fields-alist) or (err message)