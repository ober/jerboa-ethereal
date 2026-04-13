;; packet-ccsds.c
;; Routines for CCSDS dissection
;; Copyright 2000, Scott Hovis scott.hovis@ums.msfc.nasa.gov
;; Enhanced 2008, Matt Dunkle Matthew.L.Dunkle@nasa.gov
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ccsds.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ccsds.c

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
(def (dissect-ccsds buffer)
  "CCSDS"
  (try
    (let* (
           (header-flags (unwrap (read-u16be buffer 0)))
           (version (extract-bits header-flags 0x0 0))
           (secheader (extract-bits header-flags 0x0 0))
           (apid (extract-bits header-flags 0x0 0))
           (seqnum (unwrap (read-u16be buffer 2)))
           (length (unwrap (read-u16be buffer 4)))
           (coarse-time (unwrap (read-u32be buffer 6)))
           (fine-time (unwrap (read-u8 buffer 10)))
           (embedded-time (unwrap (slice buffer 10 5)))
           (timeid (unwrap (read-u8 buffer 10)))
           (checkword-flag (unwrap (read-u8 buffer 10)))
           (zoe (unwrap (read-u8 buffer 10)))
           (packet-type-unused (unwrap (read-u8 buffer 10)))
           (vid (unwrap (read-u16be buffer 10)))
           (dcc (unwrap (read-u16be buffer 12)))
           (spare1 (unwrap (read-u8 buffer 14)))
           (spare2 (unwrap (read-u16be buffer 14)))
           (format-version-id (unwrap (read-u16be buffer 14)))
           (spare3 (unwrap (read-u8 buffer 16)))
           (frame-id (unwrap (read-u8 buffer 16)))
           (user-data (unwrap (slice buffer 16 1)))
           (checkword (unwrap (read-u16be buffer 16)))
           (checkword-good (unwrap (read-u8 buffer 16)))
           (checkword-bad (unwrap (read-u8 buffer 16)))
           )

      (ok (list
        (cons 'header-flags (list (cons 'raw header-flags) (cons 'formatted (fmt-hex header-flags))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (if (= version 0) "Not set" "Set"))))
        (cons 'secheader (list (cons 'raw secheader) (cons 'formatted (if (= secheader 0) "Not set" "Set"))))
        (cons 'apid (list (cons 'raw apid) (cons 'formatted (if (= apid 0) "Not set" "Set"))))
        (cons 'seqnum (list (cons 'raw seqnum) (cons 'formatted (number->string seqnum))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'coarse-time (list (cons 'raw coarse-time) (cons 'formatted (number->string coarse-time))))
        (cons 'fine-time (list (cons 'raw fine-time) (cons 'formatted (number->string fine-time))))
        (cons 'embedded-time (list (cons 'raw embedded-time) (cons 'formatted (utf8->string embedded-time))))
        (cons 'timeid (list (cons 'raw timeid) (cons 'formatted (number->string timeid))))
        (cons 'checkword-flag (list (cons 'raw checkword-flag) (cons 'formatted (number->string checkword-flag))))
        (cons 'zoe (list (cons 'raw zoe) (cons 'formatted (number->string zoe))))
        (cons 'packet-type-unused (list (cons 'raw packet-type-unused) (cons 'formatted (number->string packet-type-unused))))
        (cons 'vid (list (cons 'raw vid) (cons 'formatted (number->string vid))))
        (cons 'dcc (list (cons 'raw dcc) (cons 'formatted (number->string dcc))))
        (cons 'spare1 (list (cons 'raw spare1) (cons 'formatted (number->string spare1))))
        (cons 'spare2 (list (cons 'raw spare2) (cons 'formatted (number->string spare2))))
        (cons 'format-version-id (list (cons 'raw format-version-id) (cons 'formatted (number->string format-version-id))))
        (cons 'spare3 (list (cons 'raw spare3) (cons 'formatted (number->string spare3))))
        (cons 'frame-id (list (cons 'raw frame-id) (cons 'formatted (number->string frame-id))))
        (cons 'user-data (list (cons 'raw user-data) (cons 'formatted (fmt-bytes user-data))))
        (cons 'checkword (list (cons 'raw checkword) (cons 'formatted (fmt-hex checkword))))
        (cons 'checkword-good (list (cons 'raw checkword-good) (cons 'formatted (number->string checkword-good))))
        (cons 'checkword-bad (list (cons 'raw checkword-bad) (cons 'formatted (number->string checkword-bad))))
        )))

    (catch (e)
      (err (str "CCSDS parse error: " e)))))

;; dissect-ccsds: parse CCSDS from bytevector
;; Returns (ok fields-alist) or (err message)