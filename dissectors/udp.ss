;; packet-udp.c
;; Routines for UDP/UDP-Lite packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Richard Sharpe, 13-Feb-1999, added dispatch table support and
;; support for tftp.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/udp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-udp.c

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
(def (dissect-udp buffer)
  "User Datagram Protocol"
  (try
    (let* (
           (proc-src-cmd (unwrap (slice buffer 0 1)))
           (proc-src-uname (unwrap (slice buffer 0 1)))
           (proc-src-pid (unwrap (read-u32be buffer 0)))
           (proc-src-uid (unwrap (read-u32be buffer 0)))
           (proc-dst-cmd (unwrap (slice buffer 0 1)))
           (proc-dst-uname (unwrap (slice buffer 0 1)))
           (proc-dst-pid (unwrap (read-u32be buffer 0)))
           (proc-dst-uid (unwrap (read-u32be buffer 0)))
           (stream-pnum (unwrap (read-u32be buffer 0)))
           (payload (unwrap (slice buffer 0 1)))
           (srcport (unwrap (read-u16be buffer 0)))
           (dstport (unwrap (read-u16be buffer 0)))
           (port (unwrap (read-u16be buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (checksum-coverage (unwrap (read-u16be buffer 0)))
           (checksum (unwrap (read-u16be buffer 0)))
           (checksum-calculated (unwrap (read-u16be buffer 0)))
           (stream (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'proc-src-cmd (list (cons 'raw proc-src-cmd) (cons 'formatted (utf8->string proc-src-cmd))))
        (cons 'proc-src-uname (list (cons 'raw proc-src-uname) (cons 'formatted (utf8->string proc-src-uname))))
        (cons 'proc-src-pid (list (cons 'raw proc-src-pid) (cons 'formatted (number->string proc-src-pid))))
        (cons 'proc-src-uid (list (cons 'raw proc-src-uid) (cons 'formatted (number->string proc-src-uid))))
        (cons 'proc-dst-cmd (list (cons 'raw proc-dst-cmd) (cons 'formatted (utf8->string proc-dst-cmd))))
        (cons 'proc-dst-uname (list (cons 'raw proc-dst-uname) (cons 'formatted (utf8->string proc-dst-uname))))
        (cons 'proc-dst-pid (list (cons 'raw proc-dst-pid) (cons 'formatted (number->string proc-dst-pid))))
        (cons 'proc-dst-uid (list (cons 'raw proc-dst-uid) (cons 'formatted (number->string proc-dst-uid))))
        (cons 'stream-pnum (list (cons 'raw stream-pnum) (cons 'formatted (number->string stream-pnum))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'srcport (list (cons 'raw srcport) (cons 'formatted (fmt-port srcport))))
        (cons 'dstport (list (cons 'raw dstport) (cons 'formatted (fmt-port dstport))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (fmt-port port))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'checksum-coverage (list (cons 'raw checksum-coverage) (cons 'formatted (number->string checksum-coverage))))
        (cons 'checksum (list (cons 'raw checksum) (cons 'formatted (fmt-hex checksum))))
        (cons 'checksum-calculated (list (cons 'raw checksum-calculated) (cons 'formatted (fmt-hex checksum-calculated))))
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        )))

    (catch (e)
      (err (str "UDP parse error: " e)))))

;; dissect-udp: parse UDP from bytevector
;; Returns (ok fields-alist) or (err message)