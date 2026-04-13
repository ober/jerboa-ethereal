;; packet-mc-nmf.c
;; Routines for .NET Message Framing Protocol (MC-NMF) dissection
;; Copyright 2017-2020, Uli Heilmeier <uh@heilmeier.eu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wieshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mc-nmf.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mc_nmf.c

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
(def (dissect-mc-nmf buffer)
  ".NET Message Framing Protocol"
  (try
    (let* (
           (nmf-major-version (unwrap (read-u8 buffer 1)))
           (nmf-minor-version (unwrap (read-u8 buffer 2)))
           (nmf-via-length (unwrap (read-u32be buffer 4)))
           (nmf-via (unwrap (slice buffer 4 1)))
           (nmf-encoding-length (unwrap (read-u32be buffer 5)))
           (nmf-encoding-type (unwrap (slice buffer 5 1)))
           (nmf-chunk-length (unwrap (read-u32be buffer 5)))
           (nmf-chunk (unwrap (slice buffer 5 1)))
           (nmf-terminator (unwrap (slice buffer 5 1)))
           (nmf-payload-length (unwrap (read-u32be buffer 6)))
           (nmf-payload (unwrap (slice buffer 6 1)))
           (nmf-fault-length (unwrap (read-u32be buffer 6)))
           (nmf-fault (unwrap (slice buffer 6 1)))
           (nmf-upgrade-length (unwrap (read-u32be buffer 6)))
           (nmf-upgrade (unwrap (slice buffer 6 1)))
           )

      (ok (list
        (cons 'nmf-major-version (list (cons 'raw nmf-major-version) (cons 'formatted (number->string nmf-major-version))))
        (cons 'nmf-minor-version (list (cons 'raw nmf-minor-version) (cons 'formatted (number->string nmf-minor-version))))
        (cons 'nmf-via-length (list (cons 'raw nmf-via-length) (cons 'formatted (number->string nmf-via-length))))
        (cons 'nmf-via (list (cons 'raw nmf-via) (cons 'formatted (utf8->string nmf-via))))
        (cons 'nmf-encoding-length (list (cons 'raw nmf-encoding-length) (cons 'formatted (number->string nmf-encoding-length))))
        (cons 'nmf-encoding-type (list (cons 'raw nmf-encoding-type) (cons 'formatted (utf8->string nmf-encoding-type))))
        (cons 'nmf-chunk-length (list (cons 'raw nmf-chunk-length) (cons 'formatted (number->string nmf-chunk-length))))
        (cons 'nmf-chunk (list (cons 'raw nmf-chunk) (cons 'formatted (fmt-bytes nmf-chunk))))
        (cons 'nmf-terminator (list (cons 'raw nmf-terminator) (cons 'formatted (fmt-bytes nmf-terminator))))
        (cons 'nmf-payload-length (list (cons 'raw nmf-payload-length) (cons 'formatted (number->string nmf-payload-length))))
        (cons 'nmf-payload (list (cons 'raw nmf-payload) (cons 'formatted (fmt-bytes nmf-payload))))
        (cons 'nmf-fault-length (list (cons 'raw nmf-fault-length) (cons 'formatted (number->string nmf-fault-length))))
        (cons 'nmf-fault (list (cons 'raw nmf-fault) (cons 'formatted (utf8->string nmf-fault))))
        (cons 'nmf-upgrade-length (list (cons 'raw nmf-upgrade-length) (cons 'formatted (number->string nmf-upgrade-length))))
        (cons 'nmf-upgrade (list (cons 'raw nmf-upgrade) (cons 'formatted (utf8->string nmf-upgrade))))
        )))

    (catch (e)
      (err (str "MC-NMF parse error: " e)))))

;; dissect-mc-nmf: parse MC-NMF from bytevector
;; Returns (ok fields-alist) or (err message)