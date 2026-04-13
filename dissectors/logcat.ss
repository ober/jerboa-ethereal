;; packet-logcat.c
;; Routines for Android Logcat binary format v1 and v2
;;
;; Copyright 2014, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/logcat.ss
;; Auto-generated from wireshark/epan/dissectors/packet-logcat.c

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
(def (dissect-logcat buffer)
  "Android Logcat"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (padding (unwrap (read-u16be buffer 2)))
           (header-size (unwrap (read-u16be buffer 2)))
           (pid (unwrap (read-u32be buffer 4)))
           (tid (unwrap (read-u32be buffer 8)))
           (timestamp-seconds (unwrap (read-u32be buffer 12)))
           (timestamp-nanoseconds (unwrap (read-u32be buffer 16)))
           (euid (unwrap (read-u32be buffer 20)))
           (tag (unwrap (slice buffer 25 1)))
           (log (unwrap (slice buffer 25 1)))
           (version (unwrap (read-u8 buffer 26)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-hex padding))))
        (cons 'header-size (list (cons 'raw header-size) (cons 'formatted (fmt-hex header-size))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (number->string pid))))
        (cons 'tid (list (cons 'raw tid) (cons 'formatted (number->string tid))))
        (cons 'timestamp-seconds (list (cons 'raw timestamp-seconds) (cons 'formatted (number->string timestamp-seconds))))
        (cons 'timestamp-nanoseconds (list (cons 'raw timestamp-nanoseconds) (cons 'formatted (number->string timestamp-nanoseconds))))
        (cons 'euid (list (cons 'raw euid) (cons 'formatted (number->string euid))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (utf8->string tag))))
        (cons 'log (list (cons 'raw log) (cons 'formatted (utf8->string log))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        )))

    (catch (e)
      (err (str "LOGCAT parse error: " e)))))

;; dissect-logcat: parse LOGCAT from bytevector
;; Returns (ok fields-alist) or (err message)