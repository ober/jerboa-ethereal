;; packet-ocp1.c
;; Dissector for Open Control Protocol OCP.1/AES70
;;
;; Copyright (c) 2021-2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ocp1.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ocp1.c

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
(def (dissect-ocp1 buffer)
  "Open Control Protocol (OCP.1/AES70)"
  (try
    (let* (
           (params-ono (unwrap (read-u32be buffer 0)))
           (params-blob-data (unwrap (slice buffer 0 1)))
           (params-bool (unwrap (read-u8 buffer 0)))
           (params-event-id (unwrap (read-u32be buffer 0)))
           (params-event-tree-level (unwrap (read-u16be buffer 0)))
           (params-event-index (unwrap (read-u16be buffer 2)))
           (params-method-id (unwrap (read-u32be buffer 2)))
           (params-method-tree-level (unwrap (read-u16be buffer 2)))
           (params-method-index (unwrap (read-u16be buffer 4)))
           (params-property-id (unwrap (read-u32be buffer 4)))
           (params-property-tree-level (unwrap (read-u16be buffer 4)))
           (params-property-index (unwrap (read-u16be buffer 6)))
           (params-class-version (unwrap (read-u16be buffer 6)))
           (params-libvoltype-id (unwrap (read-u32be buffer 6)))
           (params-libvol-id (unwrap (read-u32be buffer 6)))
           (params-time-interval (unwrap (read-u32be buffer 6)))
           (params-task-id (unwrap (read-u32be buffer 6)))
           (params-task-group-id (unwrap (read-u16be buffer 6)))
           (params-task-status-error-code (unwrap (read-u16be buffer 6)))
           (params-media-coding-scheme-id (unwrap (read-u16be buffer 6)))
           (params-devicestate (unwrap (read-u16be buffer 6)))
           (params-devicestate-oper (extract-bits params-devicestate 0x0 0))
           (params-devicestate-disabled (extract-bits params-devicestate 0x0 0))
           (params-devicestate-error (extract-bits params-devicestate 0x0 0))
           (params-devicestate-init (extract-bits params-devicestate 0x0 0))
           (params-devicestate-updating (extract-bits params-devicestate 0x0 0))
           (params (unwrap (slice buffer 10 1)))
           )

      (ok (list
        (cons 'params-ono (list (cons 'raw params-ono) (cons 'formatted (number->string params-ono))))
        (cons 'params-blob-data (list (cons 'raw params-blob-data) (cons 'formatted (fmt-bytes params-blob-data))))
        (cons 'params-bool (list (cons 'raw params-bool) (cons 'formatted (number->string params-bool))))
        (cons 'params-event-id (list (cons 'raw params-event-id) (cons 'formatted (number->string params-event-id))))
        (cons 'params-event-tree-level (list (cons 'raw params-event-tree-level) (cons 'formatted (number->string params-event-tree-level))))
        (cons 'params-event-index (list (cons 'raw params-event-index) (cons 'formatted (number->string params-event-index))))
        (cons 'params-method-id (list (cons 'raw params-method-id) (cons 'formatted (number->string params-method-id))))
        (cons 'params-method-tree-level (list (cons 'raw params-method-tree-level) (cons 'formatted (number->string params-method-tree-level))))
        (cons 'params-method-index (list (cons 'raw params-method-index) (cons 'formatted (number->string params-method-index))))
        (cons 'params-property-id (list (cons 'raw params-property-id) (cons 'formatted (number->string params-property-id))))
        (cons 'params-property-tree-level (list (cons 'raw params-property-tree-level) (cons 'formatted (number->string params-property-tree-level))))
        (cons 'params-property-index (list (cons 'raw params-property-index) (cons 'formatted (number->string params-property-index))))
        (cons 'params-class-version (list (cons 'raw params-class-version) (cons 'formatted (number->string params-class-version))))
        (cons 'params-libvoltype-id (list (cons 'raw params-libvoltype-id) (cons 'formatted (number->string params-libvoltype-id))))
        (cons 'params-libvol-id (list (cons 'raw params-libvol-id) (cons 'formatted (number->string params-libvol-id))))
        (cons 'params-time-interval (list (cons 'raw params-time-interval) (cons 'formatted (number->string params-time-interval))))
        (cons 'params-task-id (list (cons 'raw params-task-id) (cons 'formatted (number->string params-task-id))))
        (cons 'params-task-group-id (list (cons 'raw params-task-group-id) (cons 'formatted (number->string params-task-group-id))))
        (cons 'params-task-status-error-code (list (cons 'raw params-task-status-error-code) (cons 'formatted (number->string params-task-status-error-code))))
        (cons 'params-media-coding-scheme-id (list (cons 'raw params-media-coding-scheme-id) (cons 'formatted (number->string params-media-coding-scheme-id))))
        (cons 'params-devicestate (list (cons 'raw params-devicestate) (cons 'formatted (fmt-hex params-devicestate))))
        (cons 'params-devicestate-oper (list (cons 'raw params-devicestate-oper) (cons 'formatted (if (= params-devicestate-oper 0) "Not set" "Set"))))
        (cons 'params-devicestate-disabled (list (cons 'raw params-devicestate-disabled) (cons 'formatted (if (= params-devicestate-disabled 0) "Not set" "Set"))))
        (cons 'params-devicestate-error (list (cons 'raw params-devicestate-error) (cons 'formatted (if (= params-devicestate-error 0) "Not set" "Set"))))
        (cons 'params-devicestate-init (list (cons 'raw params-devicestate-init) (cons 'formatted (if (= params-devicestate-init 0) "Not set" "Set"))))
        (cons 'params-devicestate-updating (list (cons 'raw params-devicestate-updating) (cons 'formatted (if (= params-devicestate-updating 0) "Not set" "Set"))))
        (cons 'params (list (cons 'raw params) (cons 'formatted (fmt-bytes params))))
        )))

    (catch (e)
      (err (str "OCP1 parse error: " e)))))

;; dissect-ocp1: parse OCP1 from bytevector
;; Returns (ok fields-alist) or (err message)