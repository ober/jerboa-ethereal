;; packet-psn.c
;; Routines for PSN packet disassembly
;;
;; Copyright (c) 2025 by Matt Morris <mattm.dev.1[AT]gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; Specification:
;; https://github.com/vyv/psn-cpp/blob/master/doc/PosiStageNetprotocol_v2.03_2019_09_09.pdf
;; https://posistage.net/wp-content/uploads/2019/01/PosiStageNetprotocol_v2.02_2016_09_15.pdf
;; https://posistage.net/wp-content/uploads/2018/07/PosiStageNetprotocolv1.7.pdf
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/psn.ss
;; Auto-generated from wireshark/epan/dissectors/packet-psn.c

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
(def (dissect-psn buffer)
  "PosiStageNet"
  (try
    (let* (
           (chunk-data-field (unwrap (read-u16le buffer 2)))
           (chunk-length (extract-bits chunk-data-field 0x7FFF 0))
           (chunk-has-subchunks (extract-bits chunk-data-field 0x8000 15))
           (validity (unwrap (read-u32be buffer 40)))
           (tracker-name (unwrap (slice buffer 88 1)))
           (system-name (unwrap (slice buffer 100 1)))
           (v1-packet-counter (unwrap (read-u32be buffer 102)))
           (version-high (unwrap (read-u8 buffer 106)))
           (version-low (unwrap (read-u8 buffer 107)))
           (v1-world-id (unwrap (read-u32be buffer 108)))
           (v1-tracker-count (unwrap (read-u16be buffer 110)))
           (frame-id (unwrap (read-u8 buffer 112)))
           (frame-packet-count (unwrap (read-u8 buffer 113)))
           (v1-frame-index (unwrap (read-u8 buffer 114)))
           (tracker-id (unwrap (read-u16be buffer 118)))
           (v1-object-state (unwrap (read-u16be buffer 120)))
           (v1-reserved (unwrap (slice buffer 122 4)))
           )

      (ok (list
        (cons 'chunk-data-field (list (cons 'raw chunk-data-field) (cons 'formatted (fmt-hex chunk-data-field))))
        (cons 'chunk-length (list (cons 'raw chunk-length) (cons 'formatted (if (= chunk-length 0) "Not set" "Set"))))
        (cons 'chunk-has-subchunks (list (cons 'raw chunk-has-subchunks) (cons 'formatted (if (= chunk-has-subchunks 0) "Not set" "Set"))))
        (cons 'validity (list (cons 'raw validity) (cons 'formatted (number->string validity))))
        (cons 'tracker-name (list (cons 'raw tracker-name) (cons 'formatted (utf8->string tracker-name))))
        (cons 'system-name (list (cons 'raw system-name) (cons 'formatted (utf8->string system-name))))
        (cons 'v1-packet-counter (list (cons 'raw v1-packet-counter) (cons 'formatted (number->string v1-packet-counter))))
        (cons 'version-high (list (cons 'raw version-high) (cons 'formatted (number->string version-high))))
        (cons 'version-low (list (cons 'raw version-low) (cons 'formatted (number->string version-low))))
        (cons 'v1-world-id (list (cons 'raw v1-world-id) (cons 'formatted (number->string v1-world-id))))
        (cons 'v1-tracker-count (list (cons 'raw v1-tracker-count) (cons 'formatted (number->string v1-tracker-count))))
        (cons 'frame-id (list (cons 'raw frame-id) (cons 'formatted (number->string frame-id))))
        (cons 'frame-packet-count (list (cons 'raw frame-packet-count) (cons 'formatted (number->string frame-packet-count))))
        (cons 'v1-frame-index (list (cons 'raw v1-frame-index) (cons 'formatted (number->string v1-frame-index))))
        (cons 'tracker-id (list (cons 'raw tracker-id) (cons 'formatted (number->string tracker-id))))
        (cons 'v1-object-state (list (cons 'raw v1-object-state) (cons 'formatted (number->string v1-object-state))))
        (cons 'v1-reserved (list (cons 'raw v1-reserved) (cons 'formatted (fmt-bytes v1-reserved))))
        )))

    (catch (e)
      (err (str "PSN parse error: " e)))))

;; dissect-psn: parse PSN from bytevector
;; Returns (ok fields-alist) or (err message)