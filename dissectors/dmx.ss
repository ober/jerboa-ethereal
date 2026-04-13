;; packet-dmx.c
;; DMX packet disassembly.
;;
;; This dissector is written by
;;
;; Erwin Rol <erwin@erwinrol.com>
;; Copyright 2012 Erwin Rol
;;
;; Wireshark - Network traffic analyzer
;; Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dmx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dmx.c

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
(def (dissect-dmx buffer)
  "DMX"
  (try
    (let* (
           (chan-output-data-filter (unwrap (slice buffer 0 1)))
           (sip-byte-count (unwrap (read-u8 buffer 0)))
           (sip-control-bit-field (unwrap (read-u8 buffer 0)))
           (sip-prev-packet-checksum (unwrap (read-u16be buffer 0)))
           (test-data (unwrap (slice buffer 0 1)))
           (test-data-good (unwrap (read-u8 buffer 0)))
           (test-data-bad (unwrap (read-u8 buffer 0)))
           (text-page-nr (unwrap (read-u8 buffer 0)))
           (text-line-len (unwrap (read-u8 buffer 0)))
           (text-string (unwrap (slice buffer 0 1)))
           (sip-seq-nr (unwrap (read-u8 buffer 2)))
           (sip-dmx-universe-nr (unwrap (read-u8 buffer 2)))
           (sip-dmx-proc-level (unwrap (read-u8 buffer 2)))
           (sip-dmx-software-version (unwrap (read-u8 buffer 2)))
           (sip-dmx-packet-len (unwrap (read-u16be buffer 2)))
           (sip-dmx-nr-packets (unwrap (read-u16be buffer 4)))
           (sip-reserved (unwrap (slice buffer 16 1)))
           (sip-trailer (unwrap (slice buffer 17 1)))
           )

      (ok (list
        (cons 'chan-output-data-filter (list (cons 'raw chan-output-data-filter) (cons 'formatted (fmt-bytes chan-output-data-filter))))
        (cons 'sip-byte-count (list (cons 'raw sip-byte-count) (cons 'formatted (number->string sip-byte-count))))
        (cons 'sip-control-bit-field (list (cons 'raw sip-control-bit-field) (cons 'formatted (fmt-hex sip-control-bit-field))))
        (cons 'sip-prev-packet-checksum (list (cons 'raw sip-prev-packet-checksum) (cons 'formatted (fmt-hex sip-prev-packet-checksum))))
        (cons 'test-data (list (cons 'raw test-data) (cons 'formatted (fmt-bytes test-data))))
        (cons 'test-data-good (list (cons 'raw test-data-good) (cons 'formatted (number->string test-data-good))))
        (cons 'test-data-bad (list (cons 'raw test-data-bad) (cons 'formatted (number->string test-data-bad))))
        (cons 'text-page-nr (list (cons 'raw text-page-nr) (cons 'formatted (number->string text-page-nr))))
        (cons 'text-line-len (list (cons 'raw text-line-len) (cons 'formatted (number->string text-line-len))))
        (cons 'text-string (list (cons 'raw text-string) (cons 'formatted (utf8->string text-string))))
        (cons 'sip-seq-nr (list (cons 'raw sip-seq-nr) (cons 'formatted (number->string sip-seq-nr))))
        (cons 'sip-dmx-universe-nr (list (cons 'raw sip-dmx-universe-nr) (cons 'formatted (number->string sip-dmx-universe-nr))))
        (cons 'sip-dmx-proc-level (list (cons 'raw sip-dmx-proc-level) (cons 'formatted (number->string sip-dmx-proc-level))))
        (cons 'sip-dmx-software-version (list (cons 'raw sip-dmx-software-version) (cons 'formatted (fmt-hex sip-dmx-software-version))))
        (cons 'sip-dmx-packet-len (list (cons 'raw sip-dmx-packet-len) (cons 'formatted (fmt-hex sip-dmx-packet-len))))
        (cons 'sip-dmx-nr-packets (list (cons 'raw sip-dmx-nr-packets) (cons 'formatted (number->string sip-dmx-nr-packets))))
        (cons 'sip-reserved (list (cons 'raw sip-reserved) (cons 'formatted (fmt-bytes sip-reserved))))
        (cons 'sip-trailer (list (cons 'raw sip-trailer) (cons 'formatted (fmt-bytes sip-trailer))))
        )))

    (catch (e)
      (err (str "DMX parse error: " e)))))

;; dissect-dmx: parse DMX from bytevector
;; Returns (ok fields-alist) or (err message)