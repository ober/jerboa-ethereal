;; packet-canopen.c
;; Routines for CANopen dissection
;; Copyright 2011, Yegor Yefremov <yegorslists@googlemail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/canopen.ss
;; Auto-generated from wireshark/epan/dissectors/packet-canopen.c

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
(def (dissect-canopen buffer)
  "CANopen"
  (try
    (let* (
           (node-id (unwrap (read-u32be buffer 0)))
           (function-code (unwrap (read-u32be buffer 0)))
           (cob-id (unwrap (read-u32be buffer 0)))
           (sdo-cmd (unwrap (read-u8 buffer 0)))
           (lss-addr-vendor (unwrap (read-u32be buffer 0)))
           (nmt-ctrl-node-id (unwrap (read-u8 buffer 0)))
           (nmt-guard-toggle (unwrap (read-u8 buffer 0)))
           (sync-counter (unwrap (read-u8 buffer 0)))
           (time-stamp-ms (unwrap (read-u32be buffer 0)))
           (sdo-sub-idx (unwrap (read-u8 buffer 2)))
           (sdo-cmd-block-ackseq (unwrap (read-u8 buffer 2)))
           (sdo-cmd-block-blksize (unwrap (read-u8 buffer 2)))
           (sdo-cmd-block-pst (unwrap (read-u8 buffer 2)))
           (sdo-data (unwrap (slice buffer 2 1)))
           (lss-addr-product (unwrap (read-u32be buffer 4)))
           (time-stamp-days (unwrap (read-u16be buffer 4)))
           (em-err-reg (unwrap (read-u8 buffer 6)))
           (em-err-reg-ge (extract-bits em-err-reg 0x1 0))
           (em-err-reg-cu (extract-bits em-err-reg 0x2 1))
           (em-err-reg-vo (extract-bits em-err-reg 0x4 2))
           (em-err-reg-te (extract-bits em-err-reg 0x8 3))
           (em-err-reg-co (extract-bits em-err-reg 0x10 4))
           (em-err-reg-de (extract-bits em-err-reg 0x20 5))
           (em-err-reg-re (extract-bits em-err-reg 0x40 6))
           (em-err-reg-ma (extract-bits em-err-reg 0x80 7))
           (em-err-field (unwrap (slice buffer 6 5)))
           (pdo-data (unwrap (slice buffer 6 1)))
           (pdo-data-string (unwrap (slice buffer 6 1)))
           (lss-addr-revision (unwrap (read-u32be buffer 8)))
           (lss-addr-serial (unwrap (read-u32be buffer 12)))
           (lss-bt-tbl-selector (unwrap (read-u8 buffer 16)))
           (lss-abt-delay (unwrap (read-u16be buffer 16)))
           (lss-fastscan-id (unwrap (read-u32be buffer 22)))
           (lss-fastscan-check (unwrap (read-u8 buffer 26)))
           (lss-spec-err (unwrap (read-u8 buffer 26)))
           (lss-nid (unwrap (read-u8 buffer 30)))
           (reserved (unwrap (slice buffer 30 1)))
           )

      (ok (list
        (cons 'node-id (list (cons 'raw node-id) (cons 'formatted (fmt-hex node-id))))
        (cons 'function-code (list (cons 'raw function-code) (cons 'formatted (fmt-hex function-code))))
        (cons 'cob-id (list (cons 'raw cob-id) (cons 'formatted (fmt-hex cob-id))))
        (cons 'sdo-cmd (list (cons 'raw sdo-cmd) (cons 'formatted (fmt-hex sdo-cmd))))
        (cons 'lss-addr-vendor (list (cons 'raw lss-addr-vendor) (cons 'formatted (fmt-hex lss-addr-vendor))))
        (cons 'nmt-ctrl-node-id (list (cons 'raw nmt-ctrl-node-id) (cons 'formatted (fmt-hex nmt-ctrl-node-id))))
        (cons 'nmt-guard-toggle (list (cons 'raw nmt-guard-toggle) (cons 'formatted (number->string nmt-guard-toggle))))
        (cons 'sync-counter (list (cons 'raw sync-counter) (cons 'formatted (number->string sync-counter))))
        (cons 'time-stamp-ms (list (cons 'raw time-stamp-ms) (cons 'formatted (number->string time-stamp-ms))))
        (cons 'sdo-sub-idx (list (cons 'raw sdo-sub-idx) (cons 'formatted (fmt-hex sdo-sub-idx))))
        (cons 'sdo-cmd-block-ackseq (list (cons 'raw sdo-cmd-block-ackseq) (cons 'formatted (number->string sdo-cmd-block-ackseq))))
        (cons 'sdo-cmd-block-blksize (list (cons 'raw sdo-cmd-block-blksize) (cons 'formatted (number->string sdo-cmd-block-blksize))))
        (cons 'sdo-cmd-block-pst (list (cons 'raw sdo-cmd-block-pst) (cons 'formatted (number->string sdo-cmd-block-pst))))
        (cons 'sdo-data (list (cons 'raw sdo-data) (cons 'formatted (fmt-bytes sdo-data))))
        (cons 'lss-addr-product (list (cons 'raw lss-addr-product) (cons 'formatted (fmt-hex lss-addr-product))))
        (cons 'time-stamp-days (list (cons 'raw time-stamp-days) (cons 'formatted (number->string time-stamp-days))))
        (cons 'em-err-reg (list (cons 'raw em-err-reg) (cons 'formatted (fmt-hex em-err-reg))))
        (cons 'em-err-reg-ge (list (cons 'raw em-err-reg-ge) (cons 'formatted (if (= em-err-reg-ge 0) "Not set" "Set"))))
        (cons 'em-err-reg-cu (list (cons 'raw em-err-reg-cu) (cons 'formatted (if (= em-err-reg-cu 0) "Not set" "Set"))))
        (cons 'em-err-reg-vo (list (cons 'raw em-err-reg-vo) (cons 'formatted (if (= em-err-reg-vo 0) "Not set" "Set"))))
        (cons 'em-err-reg-te (list (cons 'raw em-err-reg-te) (cons 'formatted (if (= em-err-reg-te 0) "Not set" "Set"))))
        (cons 'em-err-reg-co (list (cons 'raw em-err-reg-co) (cons 'formatted (if (= em-err-reg-co 0) "Not set" "Set"))))
        (cons 'em-err-reg-de (list (cons 'raw em-err-reg-de) (cons 'formatted (if (= em-err-reg-de 0) "Not set" "Set"))))
        (cons 'em-err-reg-re (list (cons 'raw em-err-reg-re) (cons 'formatted (if (= em-err-reg-re 0) "Not set" "Set"))))
        (cons 'em-err-reg-ma (list (cons 'raw em-err-reg-ma) (cons 'formatted (if (= em-err-reg-ma 0) "Not set" "Set"))))
        (cons 'em-err-field (list (cons 'raw em-err-field) (cons 'formatted (fmt-bytes em-err-field))))
        (cons 'pdo-data (list (cons 'raw pdo-data) (cons 'formatted (fmt-bytes pdo-data))))
        (cons 'pdo-data-string (list (cons 'raw pdo-data-string) (cons 'formatted (utf8->string pdo-data-string))))
        (cons 'lss-addr-revision (list (cons 'raw lss-addr-revision) (cons 'formatted (fmt-hex lss-addr-revision))))
        (cons 'lss-addr-serial (list (cons 'raw lss-addr-serial) (cons 'formatted (fmt-hex lss-addr-serial))))
        (cons 'lss-bt-tbl-selector (list (cons 'raw lss-bt-tbl-selector) (cons 'formatted (fmt-hex lss-bt-tbl-selector))))
        (cons 'lss-abt-delay (list (cons 'raw lss-abt-delay) (cons 'formatted (number->string lss-abt-delay))))
        (cons 'lss-fastscan-id (list (cons 'raw lss-fastscan-id) (cons 'formatted (fmt-hex lss-fastscan-id))))
        (cons 'lss-fastscan-check (list (cons 'raw lss-fastscan-check) (cons 'formatted (fmt-hex lss-fastscan-check))))
        (cons 'lss-spec-err (list (cons 'raw lss-spec-err) (cons 'formatted (fmt-hex lss-spec-err))))
        (cons 'lss-nid (list (cons 'raw lss-nid) (cons 'formatted (fmt-hex lss-nid))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        )))

    (catch (e)
      (err (str "CANOPEN parse error: " e)))))

;; dissect-canopen: parse CANOPEN from bytevector
;; Returns (ok fields-alist) or (err message)