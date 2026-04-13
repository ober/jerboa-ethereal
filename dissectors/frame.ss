;; packet-frame.c
;;
;; Top-most dissector. Decides dissector based on Wiretap Encapsulation Type.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 2000 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/frame.ss
;; Auto-generated from wireshark/epan/dissectors/packet-frame.c

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
(def (dissect-frame buffer)
  "Frame"
  (try
    (let* (
           (color-filter-text (unwrap (slice buffer 0 1)))
           (color-filter-name (unwrap (slice buffer 0 1)))
           (protocols (unwrap (slice buffer 0 1)))
           (cb-copy-allowed (unwrap (read-u8 buffer 0)))
           (cb-pen (unwrap (read-u32be buffer 0)))
           (file-off (unwrap (read-u64be buffer 0)))
           (link-number (unwrap (read-u16be buffer 0)))
           (ignored (unwrap (read-u8 buffer 0)))
           (marked (unwrap (read-u8 buffer 0)))
           (md5-hash (unwrap (slice buffer 0 1)))
           (drop-count (unwrap (read-u64be buffer 0)))
           (capture-len (unwrap (read-u32be buffer 0)))
           (len (unwrap (read-u32be buffer 0)))
           (number (unwrap (read-u32be buffer 0)))
           (wtap-encap (unwrap (read-u16be buffer 0)))
           (verdict (unwrap (slice buffer 0 1)))
           (packet-id (unwrap (read-u64be buffer 0)))
           (pack-flags (unwrap (read-u32be buffer 0)))
           (hash (unwrap (slice buffer 0 1)))
           (interface-queue (unwrap (read-u32be buffer 0)))
           (interface-description (unwrap (slice buffer 0 1)))
           (interface-name (unwrap (slice buffer 0 1)))
           (interface-id (unwrap (read-u32be buffer 0)))
           (section-number (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'color-filter-text (list (cons 'raw color-filter-text) (cons 'formatted (utf8->string color-filter-text))))
        (cons 'color-filter-name (list (cons 'raw color-filter-name) (cons 'formatted (utf8->string color-filter-name))))
        (cons 'protocols (list (cons 'raw protocols) (cons 'formatted (utf8->string protocols))))
        (cons 'cb-copy-allowed (list (cons 'raw cb-copy-allowed) (cons 'formatted (if (= cb-copy-allowed 0) "False" "True"))))
        (cons 'cb-pen (list (cons 'raw cb-pen) (cons 'formatted (number->string cb-pen))))
        (cons 'file-off (list (cons 'raw file-off) (cons 'formatted (number->string file-off))))
        (cons 'link-number (list (cons 'raw link-number) (cons 'formatted (number->string link-number))))
        (cons 'ignored (list (cons 'raw ignored) (cons 'formatted (number->string ignored))))
        (cons 'marked (list (cons 'raw marked) (cons 'formatted (number->string marked))))
        (cons 'md5-hash (list (cons 'raw md5-hash) (cons 'formatted (utf8->string md5-hash))))
        (cons 'drop-count (list (cons 'raw drop-count) (cons 'formatted (number->string drop-count))))
        (cons 'capture-len (list (cons 'raw capture-len) (cons 'formatted (number->string capture-len))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'number (list (cons 'raw number) (cons 'formatted (number->string number))))
        (cons 'wtap-encap (list (cons 'raw wtap-encap) (cons 'formatted (number->string wtap-encap))))
        (cons 'verdict (list (cons 'raw verdict) (cons 'formatted (utf8->string verdict))))
        (cons 'packet-id (list (cons 'raw packet-id) (cons 'formatted (number->string packet-id))))
        (cons 'pack-flags (list (cons 'raw pack-flags) (cons 'formatted (fmt-hex pack-flags))))
        (cons 'hash (list (cons 'raw hash) (cons 'formatted (utf8->string hash))))
        (cons 'interface-queue (list (cons 'raw interface-queue) (cons 'formatted (number->string interface-queue))))
        (cons 'interface-description (list (cons 'raw interface-description) (cons 'formatted (utf8->string interface-description))))
        (cons 'interface-name (list (cons 'raw interface-name) (cons 'formatted (utf8->string interface-name))))
        (cons 'interface-id (list (cons 'raw interface-id) (cons 'formatted (number->string interface-id))))
        (cons 'section-number (list (cons 'raw section-number) (cons 'formatted (number->string section-number))))
        )))

    (catch (e)
      (err (str "FRAME parse error: " e)))))

;; dissect-frame: parse FRAME from bytevector
;; Returns (ok fields-alist) or (err message)