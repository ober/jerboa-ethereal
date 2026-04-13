;; packet-gsm_abis_tfp.c
;; Routines for packet dissection of Ericsson GSM A-bis TFP
;; (Traffic Forwarding Protocol)
;; Copyright 2010-2016 by Harald Welte <laforge@gnumonks.org>
;;
;; TFP is an Ericsson-specific packetized version of replacing TRAU
;; frames on 8k/16k E1 sub-slots with a paketized frame format which
;; can be transported over LAPD on a SuperChannel (E1 timeslot bundle)
;; or L2TP.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-abis-tfp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_abis_tfp.c

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
(def (dissect-gsm-abis-tfp buffer)
  "GSM A-bis TFP"
  (try
    (let* (
           (hdr-seq-nr (unwrap (read-u16be buffer 0)))
           (hdr-delay-info (unwrap (read-u16be buffer 0)))
           (hdr-s (unwrap (read-u8 buffer 0)))
           (hdr-m (unwrap (read-u8 buffer 0)))
           (hdr-atsr (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'hdr-seq-nr (list (cons 'raw hdr-seq-nr) (cons 'formatted (number->string hdr-seq-nr))))
        (cons 'hdr-delay-info (list (cons 'raw hdr-delay-info) (cons 'formatted (number->string hdr-delay-info))))
        (cons 'hdr-s (list (cons 'raw hdr-s) (cons 'formatted (number->string hdr-s))))
        (cons 'hdr-m (list (cons 'raw hdr-m) (cons 'formatted (number->string hdr-m))))
        (cons 'hdr-atsr (list (cons 'raw hdr-atsr) (cons 'formatted (number->string hdr-atsr))))
        )))

    (catch (e)
      (err (str "GSM-ABIS-TFP parse error: " e)))))

;; dissect-gsm-abis-tfp: parse GSM-ABIS-TFP from bytevector
;; Returns (ok fields-alist) or (err message)