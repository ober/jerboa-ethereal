;; packet-gsm_abis_pgsl.c
;; Routines for packet dissection of Ericsson GSM A-bis P-GSL
;; Copyright 2010-2016 by Harald Welte <laforge@gnumonks.org>
;;
;; P-GSL is an Ericsson-specific packetized version of replacing PCU-CCU
;; TRAU frames on 8k/16k E1 sub-slots with a paketized frame format
;; which can be transported over LAPD on a SuperChannel (E1 timeslot
;; bundle) or L2TP.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-abis-pgsl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_abis_pgsl.c

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
(def (dissect-gsm-abis-pgsl buffer)
  "GSM A-bis P-GSL"
  (try
    (let* (
           (ab-acc-delay (unwrap (read-u16be buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (afnd (unwrap (read-u24be buffer 3)))
           (ack-ind (unwrap (read-u8 buffer 6)))
           (timing-offset (unwrap (read-u8 buffer 6)))
           (ir-tfi (unwrap (read-u8 buffer 8)))
           (tn-bitmap (unwrap (read-u8 buffer 8)))
           (codec-delay (unwrap (read-u8 buffer 13)))
           (codec-parity (unwrap (read-u8 buffer 13)))
           (codec-bqm (unwrap (read-u8 buffer 13)))
           (codec-mean-bep (unwrap (read-u8 buffer 13)))
           (codec-cv-bep (unwrap (read-u8 buffer 13)))
           (codec-q (unwrap (read-u8 buffer 13)))
           (codec-q1 (unwrap (read-u8 buffer 13)))
           (codec-q2 (unwrap (read-u8 buffer 13)))
           (afnu (unwrap (read-u24be buffer 17)))
           )

      (ok (list
        (cons 'ab-acc-delay (list (cons 'raw ab-acc-delay) (cons 'formatted (number->string ab-acc-delay))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'afnd (list (cons 'raw afnd) (cons 'formatted (number->string afnd))))
        (cons 'ack-ind (list (cons 'raw ack-ind) (cons 'formatted (number->string ack-ind))))
        (cons 'timing-offset (list (cons 'raw timing-offset) (cons 'formatted (number->string timing-offset))))
        (cons 'ir-tfi (list (cons 'raw ir-tfi) (cons 'formatted (number->string ir-tfi))))
        (cons 'tn-bitmap (list (cons 'raw tn-bitmap) (cons 'formatted (fmt-hex tn-bitmap))))
        (cons 'codec-delay (list (cons 'raw codec-delay) (cons 'formatted (number->string codec-delay))))
        (cons 'codec-parity (list (cons 'raw codec-parity) (cons 'formatted (number->string codec-parity))))
        (cons 'codec-bqm (list (cons 'raw codec-bqm) (cons 'formatted (number->string codec-bqm))))
        (cons 'codec-mean-bep (list (cons 'raw codec-mean-bep) (cons 'formatted (number->string codec-mean-bep))))
        (cons 'codec-cv-bep (list (cons 'raw codec-cv-bep) (cons 'formatted (number->string codec-cv-bep))))
        (cons 'codec-q (list (cons 'raw codec-q) (cons 'formatted (if (= codec-q 0) "Good" "Bad"))))
        (cons 'codec-q1 (list (cons 'raw codec-q1) (cons 'formatted (if (= codec-q1 0) "Good" "Bad"))))
        (cons 'codec-q2 (list (cons 'raw codec-q2) (cons 'formatted (if (= codec-q2 0) "Good" "Bad"))))
        (cons 'afnu (list (cons 'raw afnu) (cons 'formatted (number->string afnu))))
        )))

    (catch (e)
      (err (str "GSM-ABIS-PGSL parse error: " e)))))

;; dissect-gsm-abis-pgsl: parse GSM-ABIS-PGSL from bytevector
;; Returns (ok fields-alist) or (err message)