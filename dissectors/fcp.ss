;; packet-fcp.c
;; Routines for Fibre Channel Protocol for SCSI (FCP)
;; Copyright 2001, Dinesh G Dutt <ddutt@cisco.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcp.c

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
(def (dissect-fcp buffer)
  "Fibre Channel Protocol for SCSI"
  (try
    (let* (
           (singlelun (unwrap (read-u8 buffer 0)))
           (taskmgmt (unwrap (read-u8 buffer 0)))
           (mgmt-flags-obsolete (extract-bits taskmgmt 0x80 7))
           (mgmt-flags-clear-aca (extract-bits taskmgmt 0x40 6))
           (mgmt-flags-target-reset (extract-bits taskmgmt 0x20 5))
           (mgmt-flags-lu-reset (extract-bits taskmgmt 0x10 4))
           (mgmt-flags-rsvd (extract-bits taskmgmt 0x8 3))
           (mgmt-flags-clear-task-set (extract-bits taskmgmt 0x4 2))
           (mgmt-flags-abort-task-set (extract-bits taskmgmt 0x2 1))
           (rspflags (unwrap (read-u8 buffer 0)))
           (rsp-flags-bidi (extract-bits rspflags 0x80 7))
           (rsp-flags-bidi-rru (extract-bits rspflags 0x40 6))
           (rsp-flags-bidi-rro (extract-bits rspflags 0x20 5))
           (rsp-flags-conf-req (extract-bits rspflags 0x10 4))
           (rsp-flags-resid-under (extract-bits rspflags 0x8 3))
           (rsp-flags-resid-over (extract-bits rspflags 0x4 2))
           (rsp-flags-sns-vld (extract-bits rspflags 0x2 1))
           (rsp-flags-res-vld (extract-bits rspflags 0x1 0))
           (multilun (unwrap (slice buffer 0 8)))
           (crn (unwrap (read-u8 buffer 0)))
           (addlcdblen (unwrap (read-u8 buffer 0)))
           (rddata (unwrap (read-u8 buffer 0)))
           (wrdata (unwrap (read-u8 buffer 0)))
           (burstlen (unwrap (read-u32be buffer 0)))
           (srr-ox-id (unwrap (read-u16be buffer 4)))
           (srr-rx-id (unwrap (read-u16be buffer 6)))
           (retry-delay-timer (unwrap (read-u16be buffer 8)))
           (r-ctl (unwrap (read-u8 buffer 12)))
           (resid (unwrap (read-u32be buffer 12)))
           (snslen (unwrap (read-u32be buffer 16)))
           (rsplen (unwrap (read-u32be buffer 20)))
           (bidir-resid (unwrap (read-u32be buffer 24)))
           )

      (ok (list
        (cons 'singlelun (list (cons 'raw singlelun) (cons 'formatted (fmt-hex singlelun))))
        (cons 'taskmgmt (list (cons 'raw taskmgmt) (cons 'formatted (fmt-hex taskmgmt))))
        (cons 'mgmt-flags-obsolete (list (cons 'raw mgmt-flags-obsolete) (cons 'formatted (if (= mgmt-flags-obsolete 0) "Not set" "Set"))))
        (cons 'mgmt-flags-clear-aca (list (cons 'raw mgmt-flags-clear-aca) (cons 'formatted (if (= mgmt-flags-clear-aca 0) "Not set" "Set"))))
        (cons 'mgmt-flags-target-reset (list (cons 'raw mgmt-flags-target-reset) (cons 'formatted (if (= mgmt-flags-target-reset 0) "Not set" "Set"))))
        (cons 'mgmt-flags-lu-reset (list (cons 'raw mgmt-flags-lu-reset) (cons 'formatted (if (= mgmt-flags-lu-reset 0) "Not set" "Set"))))
        (cons 'mgmt-flags-rsvd (list (cons 'raw mgmt-flags-rsvd) (cons 'formatted (if (= mgmt-flags-rsvd 0) "Not set" "Set"))))
        (cons 'mgmt-flags-clear-task-set (list (cons 'raw mgmt-flags-clear-task-set) (cons 'formatted (if (= mgmt-flags-clear-task-set 0) "Not set" "Set"))))
        (cons 'mgmt-flags-abort-task-set (list (cons 'raw mgmt-flags-abort-task-set) (cons 'formatted (if (= mgmt-flags-abort-task-set 0) "Not set" "Set"))))
        (cons 'rspflags (list (cons 'raw rspflags) (cons 'formatted (fmt-hex rspflags))))
        (cons 'rsp-flags-bidi (list (cons 'raw rsp-flags-bidi) (cons 'formatted (if (= rsp-flags-bidi 0) "Not set" "Set"))))
        (cons 'rsp-flags-bidi-rru (list (cons 'raw rsp-flags-bidi-rru) (cons 'formatted (if (= rsp-flags-bidi-rru 0) "Not set" "Set"))))
        (cons 'rsp-flags-bidi-rro (list (cons 'raw rsp-flags-bidi-rro) (cons 'formatted (if (= rsp-flags-bidi-rro 0) "Not set" "Set"))))
        (cons 'rsp-flags-conf-req (list (cons 'raw rsp-flags-conf-req) (cons 'formatted (if (= rsp-flags-conf-req 0) "Not set" "Set"))))
        (cons 'rsp-flags-resid-under (list (cons 'raw rsp-flags-resid-under) (cons 'formatted (if (= rsp-flags-resid-under 0) "Not set" "Set"))))
        (cons 'rsp-flags-resid-over (list (cons 'raw rsp-flags-resid-over) (cons 'formatted (if (= rsp-flags-resid-over 0) "Not set" "Set"))))
        (cons 'rsp-flags-sns-vld (list (cons 'raw rsp-flags-sns-vld) (cons 'formatted (if (= rsp-flags-sns-vld 0) "Not set" "Set"))))
        (cons 'rsp-flags-res-vld (list (cons 'raw rsp-flags-res-vld) (cons 'formatted (if (= rsp-flags-res-vld 0) "Not set" "Set"))))
        (cons 'multilun (list (cons 'raw multilun) (cons 'formatted (fmt-bytes multilun))))
        (cons 'crn (list (cons 'raw crn) (cons 'formatted (number->string crn))))
        (cons 'addlcdblen (list (cons 'raw addlcdblen) (cons 'formatted (number->string addlcdblen))))
        (cons 'rddata (list (cons 'raw rddata) (cons 'formatted (number->string rddata))))
        (cons 'wrdata (list (cons 'raw wrdata) (cons 'formatted (number->string wrdata))))
        (cons 'burstlen (list (cons 'raw burstlen) (cons 'formatted (number->string burstlen))))
        (cons 'srr-ox-id (list (cons 'raw srr-ox-id) (cons 'formatted (fmt-hex srr-ox-id))))
        (cons 'srr-rx-id (list (cons 'raw srr-rx-id) (cons 'formatted (fmt-hex srr-rx-id))))
        (cons 'retry-delay-timer (list (cons 'raw retry-delay-timer) (cons 'formatted (number->string retry-delay-timer))))
        (cons 'r-ctl (list (cons 'raw r-ctl) (cons 'formatted (fmt-hex r-ctl))))
        (cons 'resid (list (cons 'raw resid) (cons 'formatted (number->string resid))))
        (cons 'snslen (list (cons 'raw snslen) (cons 'formatted (number->string snslen))))
        (cons 'rsplen (list (cons 'raw rsplen) (cons 'formatted (number->string rsplen))))
        (cons 'bidir-resid (list (cons 'raw bidir-resid) (cons 'formatted (number->string bidir-resid))))
        )))

    (catch (e)
      (err (str "FCP parse error: " e)))))

;; dissect-fcp: parse FCP from bytevector
;; Returns (ok fields-alist) or (err message)