;; packet-nmea0183.c
;; Routines for NMEA 0183 protocol dissection
;; Copyright 2024 Casper Meijn <casper@meijn.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nmea0183.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nmea0183.c

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
(def (dissect-nmea0183 buffer)
  "NMEA 0183 protocol"
  (try
    (let* (
           (unknown-field (unwrap (slice buffer 0 1)))
           (talker-id (unwrap (slice buffer 1 2)))
           (sentence-prefix (unwrap (slice buffer 2 6)))
           (sentence-id (unwrap (slice buffer 3 3)))
           (bin-version (unwrap (read-u16be buffer 6)))
           (checksum (unwrap (slice buffer 8 2)))
           (checksum-calculated (unwrap (read-u8 buffer 8)))
           (bin-srcid (unwrap (slice buffer 8 6)))
           (bin-dstid (unwrap (slice buffer 14 6)))
           (bin-blockid (unwrap (read-u32be buffer 22)))
           (bin-seqnum (unwrap (read-u32be buffer 26)))
           (bin-max-seqnum (unwrap (read-u32be buffer 30)))
           (bin-file-descriptor (unwrap (slice buffer 34 1)))
           (bin-file-descriptor-len (unwrap (read-u32be buffer 34)))
           (bin-file-length (unwrap (read-u32be buffer 38)))
           (bin-stat-of-acquisition (unwrap (read-u16be buffer 42)))
           (bin-device (unwrap (read-u8 buffer 44)))
           (bin-channel (unwrap (read-u8 buffer 44)))
           (bin-type-len (unwrap (read-u8 buffer 44)))
           (bin-data-type (unwrap (slice buffer 44 1)))
           (bin-status-and-info (unwrap (slice buffer 44 1)))
           (bin-data (unwrap (slice buffer 44 1)))
           )

      (ok (list
        (cons 'unknown-field (list (cons 'raw unknown-field) (cons 'formatted (utf8->string unknown-field))))
        (cons 'talker-id (list (cons 'raw talker-id) (cons 'formatted (utf8->string talker-id))))
        (cons 'sentence-prefix (list (cons 'raw sentence-prefix) (cons 'formatted (utf8->string sentence-prefix))))
        (cons 'sentence-id (list (cons 'raw sentence-id) (cons 'formatted (utf8->string sentence-id))))
        (cons 'bin-version (list (cons 'raw bin-version) (cons 'formatted (number->string bin-version))))
        (cons 'checksum (list (cons 'raw checksum) (cons 'formatted (utf8->string checksum))))
        (cons 'checksum-calculated (list (cons 'raw checksum-calculated) (cons 'formatted (fmt-hex checksum-calculated))))
        (cons 'bin-srcid (list (cons 'raw bin-srcid) (cons 'formatted (utf8->string bin-srcid))))
        (cons 'bin-dstid (list (cons 'raw bin-dstid) (cons 'formatted (utf8->string bin-dstid))))
        (cons 'bin-blockid (list (cons 'raw bin-blockid) (cons 'formatted (number->string bin-blockid))))
        (cons 'bin-seqnum (list (cons 'raw bin-seqnum) (cons 'formatted (number->string bin-seqnum))))
        (cons 'bin-max-seqnum (list (cons 'raw bin-max-seqnum) (cons 'formatted (number->string bin-max-seqnum))))
        (cons 'bin-file-descriptor (list (cons 'raw bin-file-descriptor) (cons 'formatted (utf8->string bin-file-descriptor))))
        (cons 'bin-file-descriptor-len (list (cons 'raw bin-file-descriptor-len) (cons 'formatted (number->string bin-file-descriptor-len))))
        (cons 'bin-file-length (list (cons 'raw bin-file-length) (cons 'formatted (number->string bin-file-length))))
        (cons 'bin-stat-of-acquisition (list (cons 'raw bin-stat-of-acquisition) (cons 'formatted (number->string bin-stat-of-acquisition))))
        (cons 'bin-device (list (cons 'raw bin-device) (cons 'formatted (fmt-hex bin-device))))
        (cons 'bin-channel (list (cons 'raw bin-channel) (cons 'formatted (fmt-hex bin-channel))))
        (cons 'bin-type-len (list (cons 'raw bin-type-len) (cons 'formatted (number->string bin-type-len))))
        (cons 'bin-data-type (list (cons 'raw bin-data-type) (cons 'formatted (utf8->string bin-data-type))))
        (cons 'bin-status-and-info (list (cons 'raw bin-status-and-info) (cons 'formatted (utf8->string bin-status-and-info))))
        (cons 'bin-data (list (cons 'raw bin-data) (cons 'formatted (fmt-bytes bin-data))))
        )))

    (catch (e)
      (err (str "NMEA0183 parse error: " e)))))

;; dissect-nmea0183: parse NMEA0183 from bytevector
;; Returns (ok fields-alist) or (err message)