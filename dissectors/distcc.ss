;; packet-distcc.c
;; Routines for distcc dissection
;; Copyright 2003, Brad Hards <bradh@frogmouth.net>
;; Copyright 2003, Ronnie Sahlberg, added TCP desegmentation.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/distcc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-distcc.c

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
(def (dissect-distcc buffer)
  "Distcc Distributed Compiler"
  (try
    (let* (
           (version (unwrap (read-u32be buffer 0)))
           (stat (unwrap (read-u32be buffer 0)))
           (argc (unwrap (read-u32be buffer 0)))
           (argv (unwrap (slice buffer 0 1)))
           (serr (unwrap (slice buffer 0 1)))
           (sout (unwrap (slice buffer 0 1)))
           (doti-source (unwrap (slice buffer 0 1)))
           (doto-object (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'stat (list (cons 'raw stat) (cons 'formatted (number->string stat))))
        (cons 'argc (list (cons 'raw argc) (cons 'formatted (number->string argc))))
        (cons 'argv (list (cons 'raw argv) (cons 'formatted (utf8->string argv))))
        (cons 'serr (list (cons 'raw serr) (cons 'formatted (utf8->string serr))))
        (cons 'sout (list (cons 'raw sout) (cons 'formatted (utf8->string sout))))
        (cons 'doti-source (list (cons 'raw doti-source) (cons 'formatted (utf8->string doti-source))))
        (cons 'doto-object (list (cons 'raw doto-object) (cons 'formatted (fmt-bytes doto-object))))
        )))

    (catch (e)
      (err (str "DISTCC parse error: " e)))))

;; dissect-distcc: parse DISTCC from bytevector
;; Returns (ok fields-alist) or (err message)