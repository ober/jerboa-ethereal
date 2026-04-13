;; packet-iuup.c
;; IuUP Protocol 3GPP TS 25.415 V6.2.0 (2005-03)
;;
;; (c) 2005 Luis E. Garcia Ontanon <luis@ontanon.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iuup.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iuup.c

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
(def (dissect-iuup buffer)
  "IuUP"
  (try
    (let* (
           (circuit-id (unwrap (read-u16be buffer 0)))
           (direction (unwrap (read-u16be buffer 0)))
           (frame-number-t14 (unwrap (read-u8 buffer 0)))
           (frame-number (unwrap (read-u8 buffer 0)))
           (payload (unwrap (slice buffer 0 1)))
           (mode-version (unwrap (read-u8 buffer 1)))
           (rfci (unwrap (read-u8 buffer 1)))
           (spare-03 (unwrap (read-u8 buffer 2)))
           (payload-crc (unwrap (read-u16be buffer 2)))
           (spare-ff (unwrap (read-u8 buffer 3)))
           (errorevt-cause-val (unwrap (read-u8 buffer 4)))
           (advance (unwrap (read-u32be buffer 4)))
           (delta (unwrap (read-u32be buffer 4)))
           (delay (unwrap (read-u32be buffer 4)))
           (time-align (unwrap (read-u8 buffer 4)))
           (num-rfci-ind (unwrap (read-u8 buffer 4)))
           (spare-e0 (unwrap (read-u8 buffer 4)))
           (init-subflows-per-rfci (unwrap (read-u8 buffer 4)))
           (mode-versions (unwrap (read-u16be buffer 4)))
           (spare-bytes (unwrap (slice buffer 5 1)))
           )

      (ok (list
        (cons 'circuit-id (list (cons 'raw circuit-id) (cons 'formatted (number->string circuit-id))))
        (cons 'direction (list (cons 'raw direction) (cons 'formatted (number->string direction))))
        (cons 'frame-number-t14 (list (cons 'raw frame-number-t14) (cons 'formatted (number->string frame-number-t14))))
        (cons 'frame-number (list (cons 'raw frame-number) (cons 'formatted (number->string frame-number))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'mode-version (list (cons 'raw mode-version) (cons 'formatted (fmt-hex mode-version))))
        (cons 'rfci (list (cons 'raw rfci) (cons 'formatted (fmt-hex rfci))))
        (cons 'spare-03 (list (cons 'raw spare-03) (cons 'formatted (fmt-hex spare-03))))
        (cons 'payload-crc (list (cons 'raw payload-crc) (cons 'formatted (fmt-hex payload-crc))))
        (cons 'spare-ff (list (cons 'raw spare-ff) (cons 'formatted (fmt-hex spare-ff))))
        (cons 'errorevt-cause-val (list (cons 'raw errorevt-cause-val) (cons 'formatted (number->string errorevt-cause-val))))
        (cons 'advance (list (cons 'raw advance) (cons 'formatted (fmt-hex advance))))
        (cons 'delta (list (cons 'raw delta) (cons 'formatted (number->string delta))))
        (cons 'delay (list (cons 'raw delay) (cons 'formatted (fmt-hex delay))))
        (cons 'time-align (list (cons 'raw time-align) (cons 'formatted (fmt-hex time-align))))
        (cons 'num-rfci-ind (list (cons 'raw num-rfci-ind) (cons 'formatted (fmt-hex num-rfci-ind))))
        (cons 'spare-e0 (list (cons 'raw spare-e0) (cons 'formatted (fmt-hex spare-e0))))
        (cons 'init-subflows-per-rfci (list (cons 'raw init-subflows-per-rfci) (cons 'formatted (number->string init-subflows-per-rfci))))
        (cons 'mode-versions (list (cons 'raw mode-versions) (cons 'formatted (fmt-hex mode-versions))))
        (cons 'spare-bytes (list (cons 'raw spare-bytes) (cons 'formatted (fmt-bytes spare-bytes))))
        )))

    (catch (e)
      (err (str "IUUP parse error: " e)))))

;; dissect-iuup: parse IUUP from bytevector
;; Returns (ok fields-alist) or (err message)