;; packet-csm-encaps.c
;; Routines for CSM_ENCAPS dissection
;; Copyright 2005, Angelo Bannack <angelo.bannack@siemens.com>
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 2003 Gerald Combs
;;
;; Copied from packet-ans.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/csm-encaps.ss
;; Auto-generated from wireshark/epan/dissectors/packet-csm_encaps.c

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
(def (dissect-csm-encaps buffer)
  "CSM_ENCAPS"
  (try
    (let* (
           (encaps-seq (unwrap (read-u8 buffer 2)))
           (encaps-ctrl (unwrap (read-u8 buffer 3)))
           (encaps-ctrl-ack (extract-bits encaps-ctrl 0x0 0))
           (encaps-ctrl-ack-suppress (extract-bits encaps-ctrl 0x0 0))
           (encaps-ctrl-endian (extract-bits encaps-ctrl 0x0 0))
           (encaps-channel (unwrap (read-u16be buffer 4)))
           (encaps-length (unwrap (read-u8 buffer 6)))
           (encaps-index (unwrap (read-u8 buffer 7)))
           (encaps-type (unwrap (read-u8 buffer 8)))
           (encaps-class (unwrap (read-u8 buffer 9)))
           )

      (ok (list
        (cons 'encaps-seq (list (cons 'raw encaps-seq) (cons 'formatted (number->string encaps-seq))))
        (cons 'encaps-ctrl (list (cons 'raw encaps-ctrl) (cons 'formatted (fmt-hex encaps-ctrl))))
        (cons 'encaps-ctrl-ack (list (cons 'raw encaps-ctrl-ack) (cons 'formatted (if (= encaps-ctrl-ack 0) "Not set" "Set"))))
        (cons 'encaps-ctrl-ack-suppress (list (cons 'raw encaps-ctrl-ack-suppress) (cons 'formatted (if (= encaps-ctrl-ack-suppress 0) "Not set" "Set"))))
        (cons 'encaps-ctrl-endian (list (cons 'raw encaps-ctrl-endian) (cons 'formatted (if (= encaps-ctrl-endian 0) "Not set" "Set"))))
        (cons 'encaps-channel (list (cons 'raw encaps-channel) (cons 'formatted (fmt-hex encaps-channel))))
        (cons 'encaps-length (list (cons 'raw encaps-length) (cons 'formatted (number->string encaps-length))))
        (cons 'encaps-index (list (cons 'raw encaps-index) (cons 'formatted (number->string encaps-index))))
        (cons 'encaps-type (list (cons 'raw encaps-type) (cons 'formatted (number->string encaps-type))))
        (cons 'encaps-class (list (cons 'raw encaps-class) (cons 'formatted (number->string encaps-class))))
        )))

    (catch (e)
      (err (str "CSM-ENCAPS parse error: " e)))))

;; dissect-csm-encaps: parse CSM-ENCAPS from bytevector
;; Returns (ok fields-alist) or (err message)