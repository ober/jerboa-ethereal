;; packet-cisco-fp-mim.c
;; Routines for analyzing Cisco FabricPath MiM (MAC-in-MAA) packets
;; Copyright 2011, Leonard Tracy <letracy@cisco.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cisco-fp-mim.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cisco_fp_mim.c

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
(def (dissect-cisco-fp-mim buffer)
  "Cisco FabricPath"
  (try
    (let* (
           (hf-ul (unwrap (read-u8 buffer 0)))
           (hf-swid (unwrap (read-u24be buffer 0)))
           (hf-sswid (unwrap (read-u8 buffer 0)))
           (hf-lid (unwrap (read-u16be buffer 0)))
           (hmac-mc (unwrap (slice buffer 0 6)))
           (1ad-priority (unwrap (read-u16be buffer 4)))
           (1ad-cfi (unwrap (read-u16be buffer 4)))
           (1ad-svid (unwrap (read-u16be buffer 4)))
           (hf-ftag (unwrap (read-u16be buffer 8)))
           (hf-ttl (unwrap (read-u16be buffer 8)))
           (hf-eid (unwrap (read-u24be buffer 10)))
           )

      (ok (list
        (cons 'hf-ul (list (cons 'raw hf-ul) (cons 'formatted (if (= hf-ul 0) "Globally unique address (factory default)" "Locally administered address (this is NOT the factory default)"))))
        (cons 'hf-swid (list (cons 'raw hf-swid) (cons 'formatted (number->string hf-swid))))
        (cons 'hf-sswid (list (cons 'raw hf-sswid) (cons 'formatted (number->string hf-sswid))))
        (cons 'hf-lid (list (cons 'raw hf-lid) (cons 'formatted (number->string hf-lid))))
        (cons 'hmac-mc (list (cons 'raw hmac-mc) (cons 'formatted (fmt-mac hmac-mc))))
        (cons '1ad-priority (list (cons 'raw 1ad-priority) (cons 'formatted (number->string 1ad-priority))))
        (cons '1ad-cfi (list (cons 'raw 1ad-cfi) (cons 'formatted (number->string 1ad-cfi))))
        (cons '1ad-svid (list (cons 'raw 1ad-svid) (cons 'formatted (number->string 1ad-svid))))
        (cons 'hf-ftag (list (cons 'raw hf-ftag) (cons 'formatted (number->string hf-ftag))))
        (cons 'hf-ttl (list (cons 'raw hf-ttl) (cons 'formatted (number->string hf-ttl))))
        (cons 'hf-eid (list (cons 'raw hf-eid) (cons 'formatted (number->string hf-eid))))
        )))

    (catch (e)
      (err (str "CISCO-FP-MIM parse error: " e)))))

;; dissect-cisco-fp-mim: parse CISCO-FP-MIM from bytevector
;; Returns (ok fields-alist) or (err message)