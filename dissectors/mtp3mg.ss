;; packet-mtp3mg.c
;; Routines for Message Transfer Part Level 3 Management and Test dissection
;;
;; It is (hopefully) compliant to:
;; ANSI T1.111.4-1996
;; ITU-T Q.704 7/1996
;; ITU-T Q.707 7/1996 and ANSI T1.111.7-1996 (for SLT message formats)
;; portions of ITU-T Q.2210 7/1996 (for XCO/XCA message formats)
;; GF 001-9001 (Chinese ITU variant)
;; JT-Q704, JT-Q707v2, and NTT-Q704 (Japan)
;;
;; Note that the division of the Japan SLS into the SLC and A/B bit is not
;; done.
;;
;; Copyright 2003, Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-mtp3.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mtp3mg.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mtp3mg.c

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
(def (dissect-mtp3mg buffer)
  "Message Transfer Part Level 3 Management"
  (try
    (let* (
           (japan-spare (unwrap (read-u8 buffer 0)))
           (test-length (unwrap (read-u8 buffer 0)))
           (test-ansi-slc (unwrap (read-u8 buffer 0)))
           (japan-apc (unwrap (read-u16be buffer 0)))
           (dlc-itu-link (unwrap (read-u16be buffer 0)))
           (dlc-ansi-link (unwrap (read-u24be buffer 0)))
           (dlc-ansi-slc (unwrap (read-u24be buffer 0)))
           (mim-ansi-slc (unwrap (read-u8 buffer 0)))
           (tfc-itu-status (unwrap (read-u16be buffer 0)))
           (itu-apc (unwrap (read-u16be buffer 0)))
           (eco-ansi-slc (unwrap (read-u8 buffer 0)))
           (cbd-itu-cbc (unwrap (read-u8 buffer 0)))
           (cbd-japan-cbc (unwrap (read-u8 buffer 0)))
           (cbd-ansi-cbc (unwrap (read-u16be buffer 0)))
           (cbd-ansi-slc (unwrap (read-u16be buffer 0)))
           (xco-itu-fsn (unwrap (read-u24be buffer 0)))
           (xco-ansi-fsn (unwrap (read-u32be buffer 0)))
           (xco-ansi-slc (unwrap (read-u32be buffer 0)))
           (coo-itu-fsn (unwrap (read-u8 buffer 0)))
           (coo-ansi-fsn (unwrap (read-u16be buffer 0)))
           (coo-ansi-slc (unwrap (read-u16be buffer 0)))
           (tfm-japan-spare (unwrap (read-u16be buffer 0)))
           (rsm-japan-spare (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'japan-spare (list (cons 'raw japan-spare) (cons 'formatted (fmt-hex japan-spare))))
        (cons 'test-length (list (cons 'raw test-length) (cons 'formatted (number->string test-length))))
        (cons 'test-ansi-slc (list (cons 'raw test-ansi-slc) (cons 'formatted (number->string test-ansi-slc))))
        (cons 'japan-apc (list (cons 'raw japan-apc) (cons 'formatted (number->string japan-apc))))
        (cons 'dlc-itu-link (list (cons 'raw dlc-itu-link) (cons 'formatted (number->string dlc-itu-link))))
        (cons 'dlc-ansi-link (list (cons 'raw dlc-ansi-link) (cons 'formatted (number->string dlc-ansi-link))))
        (cons 'dlc-ansi-slc (list (cons 'raw dlc-ansi-slc) (cons 'formatted (number->string dlc-ansi-slc))))
        (cons 'mim-ansi-slc (list (cons 'raw mim-ansi-slc) (cons 'formatted (number->string mim-ansi-slc))))
        (cons 'tfc-itu-status (list (cons 'raw tfc-itu-status) (cons 'formatted (number->string tfc-itu-status))))
        (cons 'itu-apc (list (cons 'raw itu-apc) (cons 'formatted (number->string itu-apc))))
        (cons 'eco-ansi-slc (list (cons 'raw eco-ansi-slc) (cons 'formatted (number->string eco-ansi-slc))))
        (cons 'cbd-itu-cbc (list (cons 'raw cbd-itu-cbc) (cons 'formatted (number->string cbd-itu-cbc))))
        (cons 'cbd-japan-cbc (list (cons 'raw cbd-japan-cbc) (cons 'formatted (number->string cbd-japan-cbc))))
        (cons 'cbd-ansi-cbc (list (cons 'raw cbd-ansi-cbc) (cons 'formatted (number->string cbd-ansi-cbc))))
        (cons 'cbd-ansi-slc (list (cons 'raw cbd-ansi-slc) (cons 'formatted (number->string cbd-ansi-slc))))
        (cons 'xco-itu-fsn (list (cons 'raw xco-itu-fsn) (cons 'formatted (number->string xco-itu-fsn))))
        (cons 'xco-ansi-fsn (list (cons 'raw xco-ansi-fsn) (cons 'formatted (number->string xco-ansi-fsn))))
        (cons 'xco-ansi-slc (list (cons 'raw xco-ansi-slc) (cons 'formatted (number->string xco-ansi-slc))))
        (cons 'coo-itu-fsn (list (cons 'raw coo-itu-fsn) (cons 'formatted (number->string coo-itu-fsn))))
        (cons 'coo-ansi-fsn (list (cons 'raw coo-ansi-fsn) (cons 'formatted (number->string coo-ansi-fsn))))
        (cons 'coo-ansi-slc (list (cons 'raw coo-ansi-slc) (cons 'formatted (number->string coo-ansi-slc))))
        (cons 'tfm-japan-spare (list (cons 'raw tfm-japan-spare) (cons 'formatted (number->string tfm-japan-spare))))
        (cons 'rsm-japan-spare (list (cons 'raw rsm-japan-spare) (cons 'formatted (number->string rsm-japan-spare))))
        )))

    (catch (e)
      (err (str "MTP3MG parse error: " e)))))

;; dissect-mtp3mg: parse MTP3MG from bytevector
;; Returns (ok fields-alist) or (err message)