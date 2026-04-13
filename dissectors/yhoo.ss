;; packet-yhoo.c
;; Routines for yahoo messenger packet dissection
;; Copyright 1999, Nathan Neulinger <nneul@umr.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-tftp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/yhoo.ss
;; Auto-generated from wireshark/epan/dissectors/packet-yhoo.c

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
(def (dissect-yhoo buffer)
  "Yahoo Messenger Protocol"
  (try
    (let* (
           (len (unwrap (read-u32be buffer 8)))
           (connection-id (unwrap (read-u32be buffer 16)))
           (magic-id (unwrap (read-u32be buffer 20)))
           (unknown1 (unwrap (read-u32be buffer 24)))
           (nick1 (unwrap (slice buffer 32 36)))
           (nick2 (unwrap (slice buffer 68 36)))
           (version (unwrap (slice buffer 104 8)))
           )

      (ok (list
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'connection-id (list (cons 'raw connection-id) (cons 'formatted (fmt-hex connection-id))))
        (cons 'magic-id (list (cons 'raw magic-id) (cons 'formatted (fmt-hex magic-id))))
        (cons 'unknown1 (list (cons 'raw unknown1) (cons 'formatted (fmt-hex unknown1))))
        (cons 'nick1 (list (cons 'raw nick1) (cons 'formatted (utf8->string nick1))))
        (cons 'nick2 (list (cons 'raw nick2) (cons 'formatted (utf8->string nick2))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (utf8->string version))))
        )))

    (catch (e)
      (err (str "YHOO parse error: " e)))))

;; dissect-yhoo: parse YHOO from bytevector
;; Returns (ok fields-alist) or (err message)