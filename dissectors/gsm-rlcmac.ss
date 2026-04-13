;; packet-gsm_rlcmac.c
;; Routines for GSM RLC MAC control plane message dissection in wireshark.
;; TS 44.060 and 24.008
;; By Vincent Helfre, based on original code by Jari Sassi
;; with the gracious authorization of STE
;; Copyright (c) 2011 ST-Ericsson
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-rlcmac.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_rlcmac.c

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
(def (dissect-gsm-rlcmac buffer)
  "Radio Link Control, Medium Access Control, 3GPP TS44.060"
  (try
    (let* (
           (hf-tlli (unwrap (read-u32be buffer 0)))
           (rrbp (unwrap (read-u8 buffer 2)))
           (p (unwrap (read-u8 buffer 4)))
           (hf-usf (unwrap (read-u8 buffer 5)))
           (hf-fbi (unwrap (read-u8 buffer 6)))
           (hf-ti (unwrap (read-u8 buffer 6)))
           (hf-e (unwrap (read-u8 buffer 7)))
           (tfi (unwrap (read-u8 buffer 8)))
           (ctrl-rbsn (unwrap (read-u8 buffer 8)))
           (ctrl-rti (unwrap (read-u8 buffer 9)))
           (ctrl-fs (unwrap (read-u8 buffer 14)))
           (ctrl-ac (unwrap (read-u8 buffer 15)))
           (ctrl-d (unwrap (read-u8 buffer 23)))
           )

      (ok (list
        (cons 'hf-tlli (list (cons 'raw hf-tlli) (cons 'formatted (fmt-hex hf-tlli))))
        (cons 'rrbp (list (cons 'raw rrbp) (cons 'formatted (number->string rrbp))))
        (cons 'p (list (cons 'raw p) (cons 'formatted (if (= p 0) "RRBP field is not valid" "RRBP field is valid"))))
        (cons 'hf-usf (list (cons 'raw hf-usf) (cons 'formatted (number->string hf-usf))))
        (cons 'hf-fbi (list (cons 'raw hf-fbi) (cons 'formatted (if (= hf-fbi 0) "Current Block is not last RLC data block in TBF" "Current Block is last RLC data block in TBF"))))
        (cons 'hf-ti (list (cons 'raw hf-ti) (cons 'formatted (if (= hf-ti 0) "TLLI/G-RNTI field is not present" "TLLI/G-RNTI field is present"))))
        (cons 'hf-e (list (cons 'raw hf-e) (cons 'formatted (if (= hf-e 0) "Extension octet follows immediately" "No extension octet follows"))))
        (cons 'tfi (list (cons 'raw tfi) (cons 'formatted (number->string tfi))))
        (cons 'ctrl-rbsn (list (cons 'raw ctrl-rbsn) (cons 'formatted (number->string ctrl-rbsn))))
        (cons 'ctrl-rti (list (cons 'raw ctrl-rti) (cons 'formatted (number->string ctrl-rti))))
        (cons 'ctrl-fs (list (cons 'raw ctrl-fs) (cons 'formatted (if (= ctrl-fs 0) "Current block does not contain the final segment of an RLC/MAC control message" "Current block contains the final segment of an RLC/MAC control message"))))
        (cons 'ctrl-ac (list (cons 'raw ctrl-ac) (cons 'formatted (if (= ctrl-ac 0) "TFI/D octet is not present" "TFI/D octet is present"))))
        (cons 'ctrl-d (list (cons 'raw ctrl-d) (cons 'formatted (if (= ctrl-d 0) "TFI field identifies an uplink TBF" "TFI field identifies a downlink TBF"))))
        )))

    (catch (e)
      (err (str "GSM-RLCMAC parse error: " e)))))

;; dissect-gsm-rlcmac: parse GSM-RLCMAC from bytevector
;; Returns (ok fields-alist) or (err message)