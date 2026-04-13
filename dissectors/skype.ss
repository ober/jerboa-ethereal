;; packet-skype.c
;; Routines for the disassembly of Skype
;;
;; Copyright 2009 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/skype.ss
;; Auto-generated from wireshark/epan/dissectors/packet-skype.c

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
(def (dissect-skype buffer)
  "SKYPE"
  (try
    (let* (
           (som-id (unwrap (read-u16be buffer 0)))
           (som-unk (unwrap (read-u8 buffer 2)))
           (unknown-0-unk1 (unwrap (slice buffer 3 1)))
           (payload-iv (unwrap (read-u32be buffer 3)))
           (payload-crc (unwrap (read-u32be buffer 7)))
           (payload-enc-data (unwrap (slice buffer 11 1)))
           (ffr-num (unwrap (read-u8 buffer 11)))
           (ffr-unk1 (unwrap (read-u32be buffer 12)))
           (ffr-iv (unwrap (read-u32be buffer 16)))
           (ffr-crc (unwrap (read-u32be buffer 20)))
           (ffr-enc-data (unwrap (slice buffer 24 1)))
           (natinfo-srcip (unwrap (read-u32be buffer 24)))
           (natinfo-dstip (unwrap (read-u32be buffer 28)))
           (natrequest-srcip (unwrap (read-u32be buffer 32)))
           (natrequest-dstip (unwrap (read-u32be buffer 36)))
           (audio-unk1 (unwrap (slice buffer 40 1)))
           (unknown-f-unk1 (unwrap (slice buffer 40 1)))
           (unknown-packet (unwrap (slice buffer 40 1)))
           )

      (ok (list
        (cons 'som-id (list (cons 'raw som-id) (cons 'formatted (fmt-hex som-id))))
        (cons 'som-unk (list (cons 'raw som-unk) (cons 'formatted (fmt-hex som-unk))))
        (cons 'unknown-0-unk1 (list (cons 'raw unknown-0-unk1) (cons 'formatted (fmt-bytes unknown-0-unk1))))
        (cons 'payload-iv (list (cons 'raw payload-iv) (cons 'formatted (fmt-hex payload-iv))))
        (cons 'payload-crc (list (cons 'raw payload-crc) (cons 'formatted (fmt-hex payload-crc))))
        (cons 'payload-enc-data (list (cons 'raw payload-enc-data) (cons 'formatted (fmt-bytes payload-enc-data))))
        (cons 'ffr-num (list (cons 'raw ffr-num) (cons 'formatted (fmt-hex ffr-num))))
        (cons 'ffr-unk1 (list (cons 'raw ffr-unk1) (cons 'formatted (fmt-hex ffr-unk1))))
        (cons 'ffr-iv (list (cons 'raw ffr-iv) (cons 'formatted (fmt-hex ffr-iv))))
        (cons 'ffr-crc (list (cons 'raw ffr-crc) (cons 'formatted (fmt-hex ffr-crc))))
        (cons 'ffr-enc-data (list (cons 'raw ffr-enc-data) (cons 'formatted (fmt-bytes ffr-enc-data))))
        (cons 'natinfo-srcip (list (cons 'raw natinfo-srcip) (cons 'formatted (fmt-ipv4 natinfo-srcip))))
        (cons 'natinfo-dstip (list (cons 'raw natinfo-dstip) (cons 'formatted (fmt-hex natinfo-dstip))))
        (cons 'natrequest-srcip (list (cons 'raw natrequest-srcip) (cons 'formatted (fmt-ipv4 natrequest-srcip))))
        (cons 'natrequest-dstip (list (cons 'raw natrequest-dstip) (cons 'formatted (fmt-hex natrequest-dstip))))
        (cons 'audio-unk1 (list (cons 'raw audio-unk1) (cons 'formatted (fmt-bytes audio-unk1))))
        (cons 'unknown-f-unk1 (list (cons 'raw unknown-f-unk1) (cons 'formatted (fmt-bytes unknown-f-unk1))))
        (cons 'unknown-packet (list (cons 'raw unknown-packet) (cons 'formatted (fmt-bytes unknown-packet))))
        )))

    (catch (e)
      (err (str "SKYPE parse error: " e)))))

;; dissect-skype: parse SKYPE from bytevector
;; Returns (ok fields-alist) or (err message)