;; packet-ieee8021ah.c
;; Routines for 802.1ah ethernet header disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ieee8021ah.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ieee8021ah.c

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
(def (dissect-ieee8021ah buffer)
  "IEEE 802.1ah"
  (try
    (let* (
           (res2 (unwrap (read-u32be buffer 0)))
           (res1 (unwrap (read-u32be buffer 0)))
           (nca (unwrap (read-u32be buffer 0)))
           (drop (unwrap (read-u32be buffer 0)))
           (svid (unwrap (read-u16be buffer 0)))
           (id (unwrap (read-u16be buffer 0)))
           (cfi (unwrap (read-u16be buffer 0)))
           (priority (unwrap (read-u16be buffer 0)))
           (isid (unwrap (read-u32be buffer 1)))
           (c-daddr (unwrap (slice buffer 4 6)))
           (c-saddr (unwrap (slice buffer 10 6)))
           )

      (ok (list
        (cons 'res2 (list (cons 'raw res2) (cons 'formatted (number->string res2))))
        (cons 'res1 (list (cons 'raw res1) (cons 'formatted (number->string res1))))
        (cons 'nca (list (cons 'raw nca) (cons 'formatted (number->string nca))))
        (cons 'drop (list (cons 'raw drop) (cons 'formatted (number->string drop))))
        (cons 'svid (list (cons 'raw svid) (cons 'formatted (number->string svid))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'cfi (list (cons 'raw cfi) (cons 'formatted (number->string cfi))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (number->string priority))))
        (cons 'isid (list (cons 'raw isid) (cons 'formatted (number->string isid))))
        (cons 'c-daddr (list (cons 'raw c-daddr) (cons 'formatted (fmt-mac c-daddr))))
        (cons 'c-saddr (list (cons 'raw c-saddr) (cons 'formatted (fmt-mac c-saddr))))
        )))

    (catch (e)
      (err (str "IEEE8021AH parse error: " e)))))

;; dissect-ieee8021ah: parse IEEE8021AH from bytevector
;; Returns (ok fields-alist) or (err message)