;; packet-gsm_gsup.c
;; Dissector for Osmocom Generic Subscriber Update Protocol (GSUP)
;;
;; (C) 2017-2018 by Harald Welte <laforge@gnumonks.org>
;; Contributions by sysmocom - s.f.m.c. GmbH
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-gsup.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_gsup.c

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
(def (dissect-gsm-gsup buffer)
  "Osmocom General Subscriber Update Protocol"
  (try
    (let* (
           (source-name (unwrap (slice buffer 0 1)))
           (source-name-text (unwrap (slice buffer 0 1)))
           (destination-name (unwrap (slice buffer 0 1)))
           (destination-name-text (unwrap (slice buffer 0 1)))
           (ie-len (unwrap (read-u8 buffer 0)))
           (rand (unwrap (slice buffer 0 1)))
           (sres (unwrap (slice buffer 0 1)))
           (kc (unwrap (slice buffer 0 1)))
           (ik (unwrap (slice buffer 0 1)))
           (ck (unwrap (slice buffer 0 1)))
           (autn (unwrap (slice buffer 0 1)))
           (auts (unwrap (slice buffer 0 1)))
           (res (unwrap (slice buffer 0 1)))
           (ie-payload (unwrap (slice buffer 0 1)))
           (apn (unwrap (slice buffer 0 1)))
           (pdp-context-id (unwrap (read-u8 buffer 0)))
           (charg-char (unwrap (slice buffer 0 1)))
           (cause (unwrap (read-u8 buffer 0)))
           (session-id (unwrap (read-u32be buffer 0)))
           (sm-rp-mr (unwrap (read-u8 buffer 0)))
           (sm-rp-cause (unwrap (read-u8 buffer 0)))
           (sm-rp-mms (unwrap (read-u8 buffer 0)))
           (num-vectors-req (unwrap (read-u8 buffer 0)))
           (pdp-addr-v4 (unwrap (read-u32be buffer 0)))
           (pdp-addr-v6 (unwrap (slice buffer 0 16)))
           )

      (ok (list
        (cons 'source-name (list (cons 'raw source-name) (cons 'formatted (fmt-bytes source-name))))
        (cons 'source-name-text (list (cons 'raw source-name-text) (cons 'formatted (utf8->string source-name-text))))
        (cons 'destination-name (list (cons 'raw destination-name) (cons 'formatted (fmt-bytes destination-name))))
        (cons 'destination-name-text (list (cons 'raw destination-name-text) (cons 'formatted (utf8->string destination-name-text))))
        (cons 'ie-len (list (cons 'raw ie-len) (cons 'formatted (number->string ie-len))))
        (cons 'rand (list (cons 'raw rand) (cons 'formatted (fmt-bytes rand))))
        (cons 'sres (list (cons 'raw sres) (cons 'formatted (fmt-bytes sres))))
        (cons 'kc (list (cons 'raw kc) (cons 'formatted (fmt-bytes kc))))
        (cons 'ik (list (cons 'raw ik) (cons 'formatted (fmt-bytes ik))))
        (cons 'ck (list (cons 'raw ck) (cons 'formatted (fmt-bytes ck))))
        (cons 'autn (list (cons 'raw autn) (cons 'formatted (fmt-bytes autn))))
        (cons 'auts (list (cons 'raw auts) (cons 'formatted (fmt-bytes auts))))
        (cons 'res (list (cons 'raw res) (cons 'formatted (fmt-bytes res))))
        (cons 'ie-payload (list (cons 'raw ie-payload) (cons 'formatted (fmt-bytes ie-payload))))
        (cons 'apn (list (cons 'raw apn) (cons 'formatted (utf8->string apn))))
        (cons 'pdp-context-id (list (cons 'raw pdp-context-id) (cons 'formatted (number->string pdp-context-id))))
        (cons 'charg-char (list (cons 'raw charg-char) (cons 'formatted (utf8->string charg-char))))
        (cons 'cause (list (cons 'raw cause) (cons 'formatted (fmt-hex cause))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        (cons 'sm-rp-mr (list (cons 'raw sm-rp-mr) (cons 'formatted (fmt-hex sm-rp-mr))))
        (cons 'sm-rp-cause (list (cons 'raw sm-rp-cause) (cons 'formatted (fmt-hex sm-rp-cause))))
        (cons 'sm-rp-mms (list (cons 'raw sm-rp-mms) (cons 'formatted (number->string sm-rp-mms))))
        (cons 'num-vectors-req (list (cons 'raw num-vectors-req) (cons 'formatted (number->string num-vectors-req))))
        (cons 'pdp-addr-v4 (list (cons 'raw pdp-addr-v4) (cons 'formatted (fmt-ipv4 pdp-addr-v4))))
        (cons 'pdp-addr-v6 (list (cons 'raw pdp-addr-v6) (cons 'formatted (fmt-ipv6-address pdp-addr-v6))))
        )))

    (catch (e)
      (err (str "GSM-GSUP parse error: " e)))))

;; dissect-gsm-gsup: parse GSM-GSUP from bytevector
;; Returns (ok fields-alist) or (err message)