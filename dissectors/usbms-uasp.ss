;; packet-usbms-uasp.c
;; Routines for USB Attached SCSI dissection
;; Copyright 2021, Aidan MacDonald <amachronic@protonmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/usbms-uasp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-usbms_uasp.c

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
(def (dissect-usbms-uasp buffer)
  "USB Attached SCSI"
  (try
    (let* (
           (tag-completed-frame (unwrap (read-u32be buffer 0)))
           (tag-data-sent-frame (unwrap (read-u32be buffer 0)))
           (tag-data-recv-frame (unwrap (read-u32be buffer 0)))
           (tag-write-ready-frame (unwrap (read-u32be buffer 0)))
           (tag-read-ready-frame (unwrap (read-u32be buffer 0)))
           (tag-started-frame (unwrap (read-u32be buffer 0)))
           (tag (unwrap (read-u16be buffer 2)))
           (taskmgmt-function (unwrap (read-u8 buffer 4)))
           (response-additional-info (unwrap (read-u24be buffer 4)))
           (sense-status-qualifier (unwrap (read-u16be buffer 4)))
           (cmd-task-attribute (unwrap (read-u8 buffer 4)))
           (cmd-command-priority (unwrap (read-u8 buffer 4)))
           (taskmgmt-tag-of-managed-task (unwrap (read-u16be buffer 6)))
           (cmd-additional-cdb-length (unwrap (read-u8 buffer 6)))
           (response-code (unwrap (read-u8 buffer 7)))
           (sense-length (unwrap (read-u16be buffer 14)))
           )

      (ok (list
        (cons 'tag-completed-frame (list (cons 'raw tag-completed-frame) (cons 'formatted (number->string tag-completed-frame))))
        (cons 'tag-data-sent-frame (list (cons 'raw tag-data-sent-frame) (cons 'formatted (number->string tag-data-sent-frame))))
        (cons 'tag-data-recv-frame (list (cons 'raw tag-data-recv-frame) (cons 'formatted (number->string tag-data-recv-frame))))
        (cons 'tag-write-ready-frame (list (cons 'raw tag-write-ready-frame) (cons 'formatted (number->string tag-write-ready-frame))))
        (cons 'tag-read-ready-frame (list (cons 'raw tag-read-ready-frame) (cons 'formatted (number->string tag-read-ready-frame))))
        (cons 'tag-started-frame (list (cons 'raw tag-started-frame) (cons 'formatted (number->string tag-started-frame))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (fmt-hex tag))))
        (cons 'taskmgmt-function (list (cons 'raw taskmgmt-function) (cons 'formatted (fmt-hex taskmgmt-function))))
        (cons 'response-additional-info (list (cons 'raw response-additional-info) (cons 'formatted (fmt-hex response-additional-info))))
        (cons 'sense-status-qualifier (list (cons 'raw sense-status-qualifier) (cons 'formatted (number->string sense-status-qualifier))))
        (cons 'cmd-task-attribute (list (cons 'raw cmd-task-attribute) (cons 'formatted (fmt-hex cmd-task-attribute))))
        (cons 'cmd-command-priority (list (cons 'raw cmd-command-priority) (cons 'formatted (number->string cmd-command-priority))))
        (cons 'taskmgmt-tag-of-managed-task (list (cons 'raw taskmgmt-tag-of-managed-task) (cons 'formatted (fmt-hex taskmgmt-tag-of-managed-task))))
        (cons 'cmd-additional-cdb-length (list (cons 'raw cmd-additional-cdb-length) (cons 'formatted (number->string cmd-additional-cdb-length))))
        (cons 'response-code (list (cons 'raw response-code) (cons 'formatted (fmt-hex response-code))))
        (cons 'sense-length (list (cons 'raw sense-length) (cons 'formatted (number->string sense-length))))
        )))

    (catch (e)
      (err (str "USBMS-UASP parse error: " e)))))

;; dissect-usbms-uasp: parse USBMS-UASP from bytevector
;; Returns (ok fields-alist) or (err message)