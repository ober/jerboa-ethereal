;; packet-a21.c
;;
;; Routines for A21/s102 Message dissection
;; Copyright 2012, Joseph Chai <chaienzhao@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Ref: 3GPP2 A.S0008-C v4.0
;;

;; jerboa-ethereal/dissectors/a21.ss
;; Auto-generated from wireshark/epan/dissectors/packet-a21.c

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
(def (dissect-a21 buffer)
  "A21 Protocol"
  (try
    (let* (
           (3G1X-parameters (unwrap (slice buffer 0 1)))
           (element-length (unwrap (read-u8 buffer 0)))
           (corr-id-corr-value (unwrap (read-u32be buffer 0)))
           (mn-id-msid-value (unwrap (read-u8 buffer 0)))
           (mn-id-odd-even-indicator (unwrap (read-u8 buffer 0)))
           (mn-id-identity-digit-1 (unwrap (read-u8 buffer 0)))
           (mn-id-esn (unwrap (read-u8 buffer 0)))
           (reserved (unwrap (read-u8 buffer 0)))
           (msg-tran-ctrl-paging-msg (unwrap (read-u8 buffer 0)))
           (msg-tran-ctrl-simul-xmit-with-next (unwrap (read-u8 buffer 0)))
           (msg-tran-ctrl-ackrequired (unwrap (read-u8 buffer 0)))
           (msg-tran-ctrl-3GXLogicalChannel (unwrap (read-u8 buffer 0)))
           (msg-tran-ctrl-protocol-revision (unwrap (read-u8 buffer 0)))
           (1x-lac-en-pdu (unwrap (read-u24be buffer 0)))
           (pilot-list-num-of-pilots (unwrap (read-u8 buffer 0)))
           (channel-record-length (unwrap (read-u8 buffer 0)))
           (ch-rec-ch-num (unwrap (read-u16be buffer 0)))
           (msc-id (unwrap (read-u24be buffer 0)))
           (auth-chall-para-rand-value (unwrap (read-u32be buffer 0)))
           (mob-sub-info-record-length (unwrap (read-u8 buffer 0)))
           (mob-sub-info-re-con-all-band-inc (unwrap (read-u8 buffer 0)))
           (mob-sub-info-re-con-curr-band-sub (unwrap (read-u8 buffer 0)))
           (mob-sub-info-re-band-class (unwrap (read-u8 buffer 0)))
           (mob-sub-info-re-con-all-sub-band-inc (unwrap (read-u8 buffer 0)))
           (mob-sub-info-re-sub-cls-len (unwrap (read-u8 buffer 0)))
           (mob-sub-info-record-content (unwrap (slice buffer 0 1)))
           (gcsna-status-reserved (unwrap (read-u8 buffer 0)))
           (gcsna-status-priority-incl (unwrap (read-u8 buffer 0)))
           (gcsna-status-gec (unwrap (read-u8 buffer 0)))
           (gcsna-status-status-incl (unwrap (read-u8 buffer 0)))
           (gcsna-status-call-priority (unwrap (read-u8 buffer 0)))
           (mscid-market-id (unwrap (read-u16be buffer 0)))
           (mscid-switch-number (unwrap (read-u8 buffer 2)))
           (gcsna-pdu-length (unwrap (read-u16be buffer 2)))
           (cell-id (unwrap (read-u16be buffer 3)))
           (reference-cell-id-cell (unwrap (read-u16be buffer 3)))
           (reference-cell-id-sector (unwrap (read-u8 buffer 3)))
           (sector (unwrap (read-u8 buffer 4)))
           (hrpd-sector-id-len (unwrap (read-u8 buffer 5)))
           (ch-hrpd-sector-id (unwrap (read-u8 buffer 6)))
           (ch-reference-pilot (unwrap (read-u8 buffer 6)))
           (ch-pilot-pn (unwrap (read-u16be buffer 6)))
           (ch-pilot-pn-phase (unwrap (read-u16be buffer 6)))
           (ch-pilot-strength (unwrap (read-u8 buffer 8)))
           (ch-pilot-ow-delay (unwrap (read-u16be buffer 9)))
           )

      (ok (list
        (cons '3G1X-parameters (list (cons 'raw 3G1X-parameters) (cons 'formatted (fmt-bytes 3G1X-parameters))))
        (cons 'element-length (list (cons 'raw element-length) (cons 'formatted (number->string element-length))))
        (cons 'corr-id-corr-value (list (cons 'raw corr-id-corr-value) (cons 'formatted (number->string corr-id-corr-value))))
        (cons 'mn-id-msid-value (list (cons 'raw mn-id-msid-value) (cons 'formatted (number->string mn-id-msid-value))))
        (cons 'mn-id-odd-even-indicator (list (cons 'raw mn-id-odd-even-indicator) (cons 'formatted (number->string mn-id-odd-even-indicator))))
        (cons 'mn-id-identity-digit-1 (list (cons 'raw mn-id-identity-digit-1) (cons 'formatted (number->string mn-id-identity-digit-1))))
        (cons 'mn-id-esn (list (cons 'raw mn-id-esn) (cons 'formatted (number->string mn-id-esn))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'msg-tran-ctrl-paging-msg (list (cons 'raw msg-tran-ctrl-paging-msg) (cons 'formatted (number->string msg-tran-ctrl-paging-msg))))
        (cons 'msg-tran-ctrl-simul-xmit-with-next (list (cons 'raw msg-tran-ctrl-simul-xmit-with-next) (cons 'formatted (number->string msg-tran-ctrl-simul-xmit-with-next))))
        (cons 'msg-tran-ctrl-ackrequired (list (cons 'raw msg-tran-ctrl-ackrequired) (cons 'formatted (number->string msg-tran-ctrl-ackrequired))))
        (cons 'msg-tran-ctrl-3GXLogicalChannel (list (cons 'raw msg-tran-ctrl-3GXLogicalChannel) (cons 'formatted (number->string msg-tran-ctrl-3GXLogicalChannel))))
        (cons 'msg-tran-ctrl-protocol-revision (list (cons 'raw msg-tran-ctrl-protocol-revision) (cons 'formatted (number->string msg-tran-ctrl-protocol-revision))))
        (cons '1x-lac-en-pdu (list (cons 'raw 1x-lac-en-pdu) (cons 'formatted (number->string 1x-lac-en-pdu))))
        (cons 'pilot-list-num-of-pilots (list (cons 'raw pilot-list-num-of-pilots) (cons 'formatted (number->string pilot-list-num-of-pilots))))
        (cons 'channel-record-length (list (cons 'raw channel-record-length) (cons 'formatted (number->string channel-record-length))))
        (cons 'ch-rec-ch-num (list (cons 'raw ch-rec-ch-num) (cons 'formatted (number->string ch-rec-ch-num))))
        (cons 'msc-id (list (cons 'raw msc-id) (cons 'formatted (number->string msc-id))))
        (cons 'auth-chall-para-rand-value (list (cons 'raw auth-chall-para-rand-value) (cons 'formatted (number->string auth-chall-para-rand-value))))
        (cons 'mob-sub-info-record-length (list (cons 'raw mob-sub-info-record-length) (cons 'formatted (number->string mob-sub-info-record-length))))
        (cons 'mob-sub-info-re-con-all-band-inc (list (cons 'raw mob-sub-info-re-con-all-band-inc) (cons 'formatted (number->string mob-sub-info-re-con-all-band-inc))))
        (cons 'mob-sub-info-re-con-curr-band-sub (list (cons 'raw mob-sub-info-re-con-curr-band-sub) (cons 'formatted (number->string mob-sub-info-re-con-curr-band-sub))))
        (cons 'mob-sub-info-re-band-class (list (cons 'raw mob-sub-info-re-band-class) (cons 'formatted (number->string mob-sub-info-re-band-class))))
        (cons 'mob-sub-info-re-con-all-sub-band-inc (list (cons 'raw mob-sub-info-re-con-all-sub-band-inc) (cons 'formatted (number->string mob-sub-info-re-con-all-sub-band-inc))))
        (cons 'mob-sub-info-re-sub-cls-len (list (cons 'raw mob-sub-info-re-sub-cls-len) (cons 'formatted (number->string mob-sub-info-re-sub-cls-len))))
        (cons 'mob-sub-info-record-content (list (cons 'raw mob-sub-info-record-content) (cons 'formatted (fmt-bytes mob-sub-info-record-content))))
        (cons 'gcsna-status-reserved (list (cons 'raw gcsna-status-reserved) (cons 'formatted (number->string gcsna-status-reserved))))
        (cons 'gcsna-status-priority-incl (list (cons 'raw gcsna-status-priority-incl) (cons 'formatted (number->string gcsna-status-priority-incl))))
        (cons 'gcsna-status-gec (list (cons 'raw gcsna-status-gec) (cons 'formatted (number->string gcsna-status-gec))))
        (cons 'gcsna-status-status-incl (list (cons 'raw gcsna-status-status-incl) (cons 'formatted (number->string gcsna-status-status-incl))))
        (cons 'gcsna-status-call-priority (list (cons 'raw gcsna-status-call-priority) (cons 'formatted (number->string gcsna-status-call-priority))))
        (cons 'mscid-market-id (list (cons 'raw mscid-market-id) (cons 'formatted (number->string mscid-market-id))))
        (cons 'mscid-switch-number (list (cons 'raw mscid-switch-number) (cons 'formatted (number->string mscid-switch-number))))
        (cons 'gcsna-pdu-length (list (cons 'raw gcsna-pdu-length) (cons 'formatted (number->string gcsna-pdu-length))))
        (cons 'cell-id (list (cons 'raw cell-id) (cons 'formatted (number->string cell-id))))
        (cons 'reference-cell-id-cell (list (cons 'raw reference-cell-id-cell) (cons 'formatted (number->string reference-cell-id-cell))))
        (cons 'reference-cell-id-sector (list (cons 'raw reference-cell-id-sector) (cons 'formatted (number->string reference-cell-id-sector))))
        (cons 'sector (list (cons 'raw sector) (cons 'formatted (number->string sector))))
        (cons 'hrpd-sector-id-len (list (cons 'raw hrpd-sector-id-len) (cons 'formatted (number->string hrpd-sector-id-len))))
        (cons 'ch-hrpd-sector-id (list (cons 'raw ch-hrpd-sector-id) (cons 'formatted (fmt-hex ch-hrpd-sector-id))))
        (cons 'ch-reference-pilot (list (cons 'raw ch-reference-pilot) (cons 'formatted (number->string ch-reference-pilot))))
        (cons 'ch-pilot-pn (list (cons 'raw ch-pilot-pn) (cons 'formatted (number->string ch-pilot-pn))))
        (cons 'ch-pilot-pn-phase (list (cons 'raw ch-pilot-pn-phase) (cons 'formatted (number->string ch-pilot-pn-phase))))
        (cons 'ch-pilot-strength (list (cons 'raw ch-pilot-strength) (cons 'formatted (number->string ch-pilot-strength))))
        (cons 'ch-pilot-ow-delay (list (cons 'raw ch-pilot-ow-delay) (cons 'formatted (number->string ch-pilot-ow-delay))))
        )))

    (catch (e)
      (err (str "A21 parse error: " e)))))

;; dissect-a21: parse A21 from bytevector
;; Returns (ok fields-alist) or (err message)