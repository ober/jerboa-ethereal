;; packet-umts_mac.c
;; Routines for UMTS MAC (3GPP TS 25.321) disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/umts-mac.ss
;; Auto-generated from wireshark/epan/dissectors/packet-umts_mac.c

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
(def (dissect-umts-mac buffer)
  "MAC"
  (try
    (let* (
           (channel-hsdsch (unwrap (read-u16be buffer 0)))
           (macdflowd-id (unwrap (read-u16be buffer 0)))
           (trch-id (unwrap (read-u16be buffer 0)))
           (ct (unwrap (read-u8 buffer 0)))
           (lch-id (unwrap (read-u16be buffer 0)))
           (crnti-urnti-match-frame (unwrap (read-u32be buffer 0)))
           (resolved-urnti (unwrap (read-u32be buffer 0)))
           (edch-type2-ss-interpretation (unwrap (read-u8 buffer 0)))
           (crnti (unwrap (read-u16be buffer 4)))
           )

      (ok (list
        (cons 'channel-hsdsch (list (cons 'raw channel-hsdsch) (cons 'formatted (number->string channel-hsdsch))))
        (cons 'macdflowd-id (list (cons 'raw macdflowd-id) (cons 'formatted (number->string macdflowd-id))))
        (cons 'trch-id (list (cons 'raw trch-id) (cons 'formatted (number->string trch-id))))
        (cons 'ct (list (cons 'raw ct) (cons 'formatted (fmt-hex ct))))
        (cons 'lch-id (list (cons 'raw lch-id) (cons 'formatted (number->string lch-id))))
        (cons 'crnti-urnti-match-frame (list (cons 'raw crnti-urnti-match-frame) (cons 'formatted (number->string crnti-urnti-match-frame))))
        (cons 'resolved-urnti (list (cons 'raw resolved-urnti) (cons 'formatted (fmt-hex resolved-urnti))))
        (cons 'edch-type2-ss-interpretation (list (cons 'raw edch-type2-ss-interpretation) (cons 'formatted (fmt-hex edch-type2-ss-interpretation))))
        (cons 'crnti (list (cons 'raw crnti) (cons 'formatted (fmt-hex crnti))))
        )))

    (catch (e)
      (err (str "UMTS-MAC parse error: " e)))))

;; dissect-umts-mac: parse UMTS-MAC from bytevector
;; Returns (ok fields-alist) or (err message)