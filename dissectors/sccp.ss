;; packet-sccp.c
;; Routines for Signalling Connection Control Part (SCCP) dissection
;;
;; It is hopefully compliant to:
;; ANSI T1.112.3-2001
;; ITU-T Q.713 7/1996
;; YDN 038-1997 (Chinese ITU variant)
;; JT-Q713 and NTT-Q713 (Japan)
;;
;; Note that Japan-specific GTT is incomplete; in particular, the specific
;; TTs that are defined in TTC and NTT are not decoded in detail.
;;
;; Copyright 2002, Jeff Morriss <jeff.morriss.ws [AT] gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-m2pa.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sccp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sccp.c

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
(def (dissect-sccp buffer)
  "Signalling Connection Control Part"
  (try
    (let* (
           (assoc-msg (unwrap (read-u32be buffer 0)))
           (assoc-id (unwrap (read-u32be buffer 0)))
           (importance (unwrap (read-u8 buffer 0)))
           (hop-counter (unwrap (read-u8 buffer 0)))
           (segmentation-remaining (unwrap (read-u8 buffer 0)))
           (credit (unwrap (read-u8 buffer 0)))
           (sequencing-segmenting-ssn (unwrap (read-u8 buffer 0)))
           (rsn (unwrap (read-u8 buffer 0)))
           (class (unwrap (read-u8 buffer 0)))
           (gt-digits (unwrap (slice buffer 0 1)))
           (slr (unwrap (read-u24be buffer 0)))
           (lr (unwrap (read-u24be buffer 0)))
           (dlr (unwrap (read-u24be buffer 0)))
           (unknown-parameter (unwrap (slice buffer 0 1)))
           (linked-dissector (unwrap (slice buffer 0 1)))
           (ansi-isni-counter (unwrap (read-u8 buffer 0)))
           (ansi-isni-netspec (unwrap (read-u8 buffer 0)))
           (ansi-isni-network (unwrap (read-u8 buffer 0)))
           (ansi-isni-cluster (unwrap (read-u8 buffer 0)))
           (param-length (unwrap (read-u16be buffer 0)))
           (segmentation-slr (unwrap (read-u24be buffer 1)))
           )

      (ok (list
        (cons 'assoc-msg (list (cons 'raw assoc-msg) (cons 'formatted (number->string assoc-msg))))
        (cons 'assoc-id (list (cons 'raw assoc-id) (cons 'formatted (number->string assoc-id))))
        (cons 'importance (list (cons 'raw importance) (cons 'formatted (fmt-hex importance))))
        (cons 'hop-counter (list (cons 'raw hop-counter) (cons 'formatted (fmt-hex hop-counter))))
        (cons 'segmentation-remaining (list (cons 'raw segmentation-remaining) (cons 'formatted (fmt-hex segmentation-remaining))))
        (cons 'credit (list (cons 'raw credit) (cons 'formatted (fmt-hex credit))))
        (cons 'sequencing-segmenting-ssn (list (cons 'raw sequencing-segmenting-ssn) (cons 'formatted (fmt-hex sequencing-segmenting-ssn))))
        (cons 'rsn (list (cons 'raw rsn) (cons 'formatted (fmt-hex rsn))))
        (cons 'class (list (cons 'raw class) (cons 'formatted (fmt-hex class))))
        (cons 'gt-digits (list (cons 'raw gt-digits) (cons 'formatted (utf8->string gt-digits))))
        (cons 'slr (list (cons 'raw slr) (cons 'formatted (fmt-hex slr))))
        (cons 'lr (list (cons 'raw lr) (cons 'formatted (fmt-hex lr))))
        (cons 'dlr (list (cons 'raw dlr) (cons 'formatted (fmt-hex dlr))))
        (cons 'unknown-parameter (list (cons 'raw unknown-parameter) (cons 'formatted (fmt-bytes unknown-parameter))))
        (cons 'linked-dissector (list (cons 'raw linked-dissector) (cons 'formatted (utf8->string linked-dissector))))
        (cons 'ansi-isni-counter (list (cons 'raw ansi-isni-counter) (cons 'formatted (number->string ansi-isni-counter))))
        (cons 'ansi-isni-netspec (list (cons 'raw ansi-isni-netspec) (cons 'formatted (fmt-hex ansi-isni-netspec))))
        (cons 'ansi-isni-network (list (cons 'raw ansi-isni-network) (cons 'formatted (number->string ansi-isni-network))))
        (cons 'ansi-isni-cluster (list (cons 'raw ansi-isni-cluster) (cons 'formatted (number->string ansi-isni-cluster))))
        (cons 'param-length (list (cons 'raw param-length) (cons 'formatted (number->string param-length))))
        (cons 'segmentation-slr (list (cons 'raw segmentation-slr) (cons 'formatted (fmt-hex segmentation-slr))))
        )))

    (catch (e)
      (err (str "SCCP parse error: " e)))))

;; dissect-sccp: parse SCCP from bytevector
;; Returns (ok fields-alist) or (err message)