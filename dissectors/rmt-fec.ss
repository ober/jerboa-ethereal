;; packet-rmt-fec.c
;; Reliable Multicast Transport (RMT)
;; FEC Building Block dissector
;; Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
;;
;; Forward Error Correction (ALC):
;; -------------------------------
;;
;; The goal of the FEC building block is to describe functionality
;; directly related to FEC codes that is common to all reliable content
;; delivery IP multicast protocols, and to leave out any additional
;; functionality that is specific to particular protocols.
;;
;; References:
;; RFC 3452, Forward Error Correction Building Block
;; RFC 3695, Compact Forward Error Correction (FEC) Schemes
;; Simple XOR, Reed-Solomon, and Parity Check Matrix-based FEC Schemes draft-peltotalo-rmt-bb-fec-supp-xor-pcm-rs-00
;; IANA RMT FEC parameters (http://www.iana.org/assignments/rmt-fec-parameters)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rmt-fec.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rmt_fec.c
;; RFC 3452

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
(def (dissect-rmt-fec buffer)
  "Forward Error Correction (FEC)"
  (try
    (let* (
           (transfer-length (unwrap (read-u64be buffer 0)))
           (id (unwrap (read-u16be buffer 0)))
           (encoding-symbol-length (unwrap (read-u32be buffer 0)))
           (num-blocks (unwrap (read-u16be buffer 0)))
           (num-subblocks (unwrap (read-u16be buffer 0)))
           (alignment (unwrap (read-u8 buffer 0)))
           (max-source-block-length (unwrap (read-u32be buffer 0)))
           (max-number-encoding-symbols (unwrap (read-u32be buffer 0)))
           (with-mask (unwrap (read-u32be buffer 12)))
           (hf-sbn (unwrap (read-u32be buffer 20)))
           (hf-sbl (unwrap (read-u32be buffer 20)))
           (hf-esi (unwrap (read-u32be buffer 20)))
           )

      (ok (list
        (cons 'transfer-length (list (cons 'raw transfer-length) (cons 'formatted (number->string transfer-length))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'encoding-symbol-length (list (cons 'raw encoding-symbol-length) (cons 'formatted (number->string encoding-symbol-length))))
        (cons 'num-blocks (list (cons 'raw num-blocks) (cons 'formatted (number->string num-blocks))))
        (cons 'num-subblocks (list (cons 'raw num-subblocks) (cons 'formatted (number->string num-subblocks))))
        (cons 'alignment (list (cons 'raw alignment) (cons 'formatted (number->string alignment))))
        (cons 'max-source-block-length (list (cons 'raw max-source-block-length) (cons 'formatted (number->string max-source-block-length))))
        (cons 'max-number-encoding-symbols (list (cons 'raw max-number-encoding-symbols) (cons 'formatted (number->string max-number-encoding-symbols))))
        (cons 'with-mask (list (cons 'raw with-mask) (cons 'formatted (number->string with-mask))))
        (cons 'hf-sbn (list (cons 'raw hf-sbn) (cons 'formatted (number->string hf-sbn))))
        (cons 'hf-sbl (list (cons 'raw hf-sbl) (cons 'formatted (number->string hf-sbl))))
        (cons 'hf-esi (list (cons 'raw hf-esi) (cons 'formatted (fmt-hex hf-esi))))
        )))

    (catch (e)
      (err (str "RMT-FEC parse error: " e)))))

;; dissect-rmt-fec: parse RMT-FEC from bytevector
;; Returns (ok fields-alist) or (err message)