;; packet-gsm_cbsp.c
;; Dissector for GSM / 3GPP TS 48.049 Cell Broadcast Service Protocol (CBSP)
;;
;; (C) 2018-2019 by Harald Welte <laforge@gnumonks.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/gsm-cbsp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_cbsp.c

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
(def (dissect-gsm-cbsp buffer)
  "3GPP/GSM Cell Broadcast Service Protocol"
  (try
    (let* (
           (user-info-length (unwrap (read-u8 buffer 0)))
           (cb-msg-page (unwrap (slice buffer 0 1)))
           (msg-len (unwrap (read-u24be buffer 0)))
           (ci (unwrap (read-u16be buffer 11)))
           (lac (unwrap (read-u16be buffer 18)))
           (num-bcast-compl (unwrap (read-u16be buffer 20)))
           (ie-len (unwrap (read-u8 buffer 22)))
           (old-serial-nr (unwrap (read-u16be buffer 22)))
           (new-serial-nr (unwrap (read-u16be buffer 22)))
           (num-bcast-req (unwrap (read-u16be buffer 22)))
           (dcs (unwrap (read-u8 buffer 22)))
           (msg-id (unwrap (read-u16be buffer 22)))
           (warn-type (unwrap (read-u8 buffer 22)))
           (num-of-pages (unwrap (read-u8 buffer 22)))
           (sched-period (unwrap (read-u8 buffer 22)))
           (num-of-res-slots (unwrap (read-u8 buffer 22)))
           (warning-period (unwrap (read-u8 buffer 22)))
           (keepalive-period (unwrap (read-u8 buffer 22)))
           (ie-payload (unwrap (slice buffer 22 1)))
           )

      (ok (list
        (cons 'user-info-length (list (cons 'raw user-info-length) (cons 'formatted (number->string user-info-length))))
        (cons 'cb-msg-page (list (cons 'raw cb-msg-page) (cons 'formatted (fmt-bytes cb-msg-page))))
        (cons 'msg-len (list (cons 'raw msg-len) (cons 'formatted (number->string msg-len))))
        (cons 'ci (list (cons 'raw ci) (cons 'formatted (fmt-hex ci))))
        (cons 'lac (list (cons 'raw lac) (cons 'formatted (fmt-hex lac))))
        (cons 'num-bcast-compl (list (cons 'raw num-bcast-compl) (cons 'formatted (number->string num-bcast-compl))))
        (cons 'ie-len (list (cons 'raw ie-len) (cons 'formatted (number->string ie-len))))
        (cons 'old-serial-nr (list (cons 'raw old-serial-nr) (cons 'formatted (fmt-hex old-serial-nr))))
        (cons 'new-serial-nr (list (cons 'raw new-serial-nr) (cons 'formatted (fmt-hex new-serial-nr))))
        (cons 'num-bcast-req (list (cons 'raw num-bcast-req) (cons 'formatted (number->string num-bcast-req))))
        (cons 'dcs (list (cons 'raw dcs) (cons 'formatted (fmt-hex dcs))))
        (cons 'msg-id (list (cons 'raw msg-id) (cons 'formatted (fmt-hex msg-id))))
        (cons 'warn-type (list (cons 'raw warn-type) (cons 'formatted (fmt-hex warn-type))))
        (cons 'num-of-pages (list (cons 'raw num-of-pages) (cons 'formatted (number->string num-of-pages))))
        (cons 'sched-period (list (cons 'raw sched-period) (cons 'formatted (number->string sched-period))))
        (cons 'num-of-res-slots (list (cons 'raw num-of-res-slots) (cons 'formatted (number->string num-of-res-slots))))
        (cons 'warning-period (list (cons 'raw warning-period) (cons 'formatted (number->string warning-period))))
        (cons 'keepalive-period (list (cons 'raw keepalive-period) (cons 'formatted (number->string keepalive-period))))
        (cons 'ie-payload (list (cons 'raw ie-payload) (cons 'formatted (fmt-bytes ie-payload))))
        )))

    (catch (e)
      (err (str "GSM-CBSP parse error: " e)))))

;; dissect-gsm-cbsp: parse GSM-CBSP from bytevector
;; Returns (ok fields-alist) or (err message)