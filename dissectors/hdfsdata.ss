;; packet-hdfsdata.c
;; HDFS data Protocol and dissectors
;;
;; Copyright (c) 2011 by Isilon Systems.
;;
;; Author: Allison Obourn <aobourn@isilon.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hdfsdata.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hdfsdata.c

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
(def (dissect-hdfsdata buffer)
  "HDFSDATA Protocol"
  (try
    (let* (
           (pipelinestatus (unwrap (read-u8 buffer 0)))
           (status (unwrap (read-u16be buffer 0)))
           (end (unwrap (read-u32be buffer 0)))
           (checksumtype (unwrap (read-u8 buffer 0)))
           (chunksize (unwrap (read-u32be buffer 1)))
           (datalength (unwrap (read-u32be buffer 4)))
           (inblockoffset (unwrap (read-u64be buffer 8)))
           (datalen (unwrap (read-u32be buffer 25)))
           (crc32 (unwrap (read-u32be buffer 29)))
           (chunkoffset (unwrap (read-u64be buffer 36)))
           (packetsize (unwrap (read-u32be buffer 93)))
           (startoffset (unwrap (read-u64be buffer 97)))
           (seqnum (unwrap (read-u64be buffer 105)))
           (last (unwrap (read-u8 buffer 113)))
           (chunklength (unwrap (read-u32be buffer 114)))
           (crc64 (unwrap (read-u64be buffer 118)))
           )

      (ok (list
        (cons 'pipelinestatus (list (cons 'raw pipelinestatus) (cons 'formatted (number->string pipelinestatus))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (number->string status))))
        (cons 'end (list (cons 'raw end) (cons 'formatted (number->string end))))
        (cons 'checksumtype (list (cons 'raw checksumtype) (cons 'formatted (number->string checksumtype))))
        (cons 'chunksize (list (cons 'raw chunksize) (cons 'formatted (number->string chunksize))))
        (cons 'datalength (list (cons 'raw datalength) (cons 'formatted (number->string datalength))))
        (cons 'inblockoffset (list (cons 'raw inblockoffset) (cons 'formatted (number->string inblockoffset))))
        (cons 'datalen (list (cons 'raw datalen) (cons 'formatted (number->string datalen))))
        (cons 'crc32 (list (cons 'raw crc32) (cons 'formatted (number->string crc32))))
        (cons 'chunkoffset (list (cons 'raw chunkoffset) (cons 'formatted (number->string chunkoffset))))
        (cons 'packetsize (list (cons 'raw packetsize) (cons 'formatted (number->string packetsize))))
        (cons 'startoffset (list (cons 'raw startoffset) (cons 'formatted (number->string startoffset))))
        (cons 'seqnum (list (cons 'raw seqnum) (cons 'formatted (number->string seqnum))))
        (cons 'last (list (cons 'raw last) (cons 'formatted (number->string last))))
        (cons 'chunklength (list (cons 'raw chunklength) (cons 'formatted (number->string chunklength))))
        (cons 'crc64 (list (cons 'raw crc64) (cons 'formatted (number->string crc64))))
        )))

    (catch (e)
      (err (str "HDFSDATA parse error: " e)))))

;; dissect-hdfsdata: parse HDFSDATA from bytevector
;; Returns (ok fields-alist) or (err message)