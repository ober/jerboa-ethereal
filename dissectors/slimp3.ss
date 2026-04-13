;; packet-slimp3.c
;; Routines for SliMP3 protocol dissection
;;
;; Ashok Narayanan <ashokn@cisco.com>
;;
;; Adds support for the data packet protocol for the SliMP3
;; See www.slimdevices.com for details.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/slimp3.ss
;; Auto-generated from wireshark/epan/dissectors/packet-slimp3.c

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
(def (dissect-slimp3 buffer)
  "SliMP3 Communication Protocol"
  (try
    (let* (
           (uptime (unwrap (read-u32be buffer 0)))
           (code-bits (unwrap (read-u8 buffer 0)))
           (infrared (unwrap (read-u32be buffer 0)))
           (display-string (unwrap (read-u16be buffer 0)))
           (display-unknown (unwrap (read-u16be buffer 0)))
           (device-id (unwrap (read-u8 buffer 0)))
           (fw-rev (unwrap (read-u8 buffer 0)))
           (data-req-offset (unwrap (read-u16be buffer 0)))
           (data-length (unwrap (slice buffer 0 1)))
           (data-offset (unwrap (read-u16be buffer 0)))
           (data-write-pointer (unwrap (read-u16be buffer 0)))
           (data-sequence (unwrap (read-u16be buffer 0)))
           (disc-rsp-server-ip (unwrap (read-u32be buffer 0)))
           (disc-rsp-server-port (unwrap (read-u16be buffer 0)))
           (data-ack-write-pointer (unwrap (read-u16be buffer 0)))
           (data-ack-read-pointer (unwrap (read-u16be buffer 0)))
           (data-ack-sequence (unwrap (read-u16be buffer 0)))
           (data-data (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'uptime (list (cons 'raw uptime) (cons 'formatted (number->string uptime))))
        (cons 'code-bits (list (cons 'raw code-bits) (cons 'formatted (number->string code-bits))))
        (cons 'infrared (list (cons 'raw infrared) (cons 'formatted (fmt-hex infrared))))
        (cons 'display-string (list (cons 'raw display-string) (cons 'formatted (number->string display-string))))
        (cons 'display-unknown (list (cons 'raw display-unknown) (cons 'formatted (fmt-hex display-unknown))))
        (cons 'device-id (list (cons 'raw device-id) (cons 'formatted (number->string device-id))))
        (cons 'fw-rev (list (cons 'raw fw-rev) (cons 'formatted (fmt-hex fw-rev))))
        (cons 'data-req-offset (list (cons 'raw data-req-offset) (cons 'formatted (number->string data-req-offset))))
        (cons 'data-length (list (cons 'raw data-length) (cons 'formatted (fmt-bytes data-length))))
        (cons 'data-offset (list (cons 'raw data-offset) (cons 'formatted (number->string data-offset))))
        (cons 'data-write-pointer (list (cons 'raw data-write-pointer) (cons 'formatted (number->string data-write-pointer))))
        (cons 'data-sequence (list (cons 'raw data-sequence) (cons 'formatted (number->string data-sequence))))
        (cons 'disc-rsp-server-ip (list (cons 'raw disc-rsp-server-ip) (cons 'formatted (fmt-ipv4 disc-rsp-server-ip))))
        (cons 'disc-rsp-server-port (list (cons 'raw disc-rsp-server-port) (cons 'formatted (number->string disc-rsp-server-port))))
        (cons 'data-ack-write-pointer (list (cons 'raw data-ack-write-pointer) (cons 'formatted (number->string data-ack-write-pointer))))
        (cons 'data-ack-read-pointer (list (cons 'raw data-ack-read-pointer) (cons 'formatted (number->string data-ack-read-pointer))))
        (cons 'data-ack-sequence (list (cons 'raw data-ack-sequence) (cons 'formatted (number->string data-ack-sequence))))
        (cons 'data-data (list (cons 'raw data-data) (cons 'formatted (fmt-bytes data-data))))
        )))

    (catch (e)
      (err (str "SLIMP3 parse error: " e)))))

;; dissect-slimp3: parse SLIMP3 from bytevector
;; Returns (ok fields-alist) or (err message)