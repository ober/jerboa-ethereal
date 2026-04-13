;; packet-lsc.c
;; Routines for Pegasus LSC packet disassembly
;; Copyright 2006, Sean Sheedy <seansh@users.sourceforge.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lsc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lsc.c

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
(def (dissect-lsc buffer)
  "Pegasus Lightweight Stream Control"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (trans-id (unwrap (read-u8 buffer 1)))
           (stream-handle (unwrap (read-u32be buffer 4)))
           (current-npt (unwrap (read-u32be buffer 8)))
           (start-npt (unwrap (read-u32be buffer 8)))
           (stop-npt (unwrap (read-u32be buffer 8)))
           (scale-num (unwrap (read-u16be buffer 12)))
           (scale-denom (unwrap (read-u16be buffer 14)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'trans-id (list (cons 'raw trans-id) (cons 'formatted (number->string trans-id))))
        (cons 'stream-handle (list (cons 'raw stream-handle) (cons 'formatted (number->string stream-handle))))
        (cons 'current-npt (list (cons 'raw current-npt) (cons 'formatted (number->string current-npt))))
        (cons 'start-npt (list (cons 'raw start-npt) (cons 'formatted (number->string start-npt))))
        (cons 'stop-npt (list (cons 'raw stop-npt) (cons 'formatted (number->string stop-npt))))
        (cons 'scale-num (list (cons 'raw scale-num) (cons 'formatted (number->string scale-num))))
        (cons 'scale-denom (list (cons 'raw scale-denom) (cons 'formatted (number->string scale-denom))))
        )))

    (catch (e)
      (err (str "LSC parse error: " e)))))

;; dissect-lsc: parse LSC from bytevector
;; Returns (ok fields-alist) or (err message)