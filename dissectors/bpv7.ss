;; packet-bpv7.c
;; Routines for Bundle Protocol Version 7 dissection
;; References:
;; RFC 9171: https://www.rfc-editor.org/rfc/rfc9171.html
;; https://www.ietf.org/archive/id/draft-ietf-dtn-ipn-update-14.html
;;
;; Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: LGPL-2.1-or-later
;;

;; jerboa-ethereal/dissectors/bpv7.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bpv7.c
;; RFC 9171

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
(def (dissect-bpv7 buffer)
  "DTN Bundle Protocol Version 7"
  (try
    (let* (
           (dst-ipn-srv (unwrap (read-u64be buffer 0)))
           (dst-dtn-srv (unwrap (slice buffer 0 1)))
           (srcdst-uri (unwrap (slice buffer 0 1)))
           (ipn-fqnn (unwrap (read-u64be buffer 0)))
           (ipn-altform (unwrap (slice buffer 0 1)))
           (ipn-node (unwrap (read-u64be buffer 0)))
           (dtn-serv (unwrap (slice buffer 0 1)))
           (dtn-wkssp (unwrap (slice buffer 0 1)))
           (break (unwrap (slice buffer 0 1)))
           (rep (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'dst-ipn-srv (list (cons 'raw dst-ipn-srv) (cons 'formatted (number->string dst-ipn-srv))))
        (cons 'dst-dtn-srv (list (cons 'raw dst-dtn-srv) (cons 'formatted (utf8->string dst-dtn-srv))))
        (cons 'srcdst-uri (list (cons 'raw srcdst-uri) (cons 'formatted (utf8->string srcdst-uri))))
        (cons 'ipn-fqnn (list (cons 'raw ipn-fqnn) (cons 'formatted (number->string ipn-fqnn))))
        (cons 'ipn-altform (list (cons 'raw ipn-altform) (cons 'formatted (utf8->string ipn-altform))))
        (cons 'ipn-node (list (cons 'raw ipn-node) (cons 'formatted (number->string ipn-node))))
        (cons 'dtn-serv (list (cons 'raw dtn-serv) (cons 'formatted (utf8->string dtn-serv))))
        (cons 'dtn-wkssp (list (cons 'raw dtn-wkssp) (cons 'formatted (utf8->string dtn-wkssp))))
        (cons 'break (list (cons 'raw break) (cons 'formatted (fmt-bytes break))))
        (cons 'rep (list (cons 'raw rep) (cons 'formatted (fmt-bytes rep))))
        )))

    (catch (e)
      (err (str "BPV7 parse error: " e)))))

;; dissect-bpv7: parse BPV7 from bytevector
;; Returns (ok fields-alist) or (err message)