;; packet-adb_service.c
;; Routines for Android Debug Bridge Services
;;
;; Copyright 2014 Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/adb-service.ss
;; Auto-generated from wireshark/epan/dissectors/packet-adb_service.c

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
(def (dissect-adb-service buffer)
  "Android Debug Bridge Service"
  (try
    (let* (
           (hf-devices (unwrap (slice buffer 0 1)))
           (version (unwrap (read-u32be buffer 0)))
           (depth (unwrap (read-u32be buffer 4)))
           (size (unwrap (read-u32be buffer 8)))
           (width (unwrap (read-u32be buffer 12)))
           (height (unwrap (read-u32be buffer 16)))
           (red-offset (unwrap (read-u32be buffer 20)))
           (red-length (unwrap (read-u32be buffer 24)))
           (blue-offset (unwrap (read-u32be buffer 28)))
           (blue-length (unwrap (read-u32be buffer 32)))
           (green-offset (unwrap (read-u32be buffer 36)))
           (green-length (unwrap (read-u32be buffer 40)))
           (alpha-offset (unwrap (read-u32be buffer 44)))
           (alpha-length (unwrap (read-u32be buffer 48)))
           (blue-5 (unwrap (read-u16be buffer 53)))
           (green-6 (unwrap (read-u16be buffer 53)))
           (red-5 (unwrap (read-u16be buffer 53)))
           (hf-pids (unwrap (slice buffer 59 1)))
           (hf-stdin (unwrap (slice buffer 65 1)))
           (hf-stdout (unwrap (slice buffer 65 1)))
           (hf-data (unwrap (slice buffer 65 1)))
           (hf-result (unwrap (slice buffer 65 1)))
           (hf-service (unwrap (slice buffer 66 1)))
           )

      (ok (list
        (cons 'hf-devices (list (cons 'raw hf-devices) (cons 'formatted (utf8->string hf-devices))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'depth (list (cons 'raw depth) (cons 'formatted (number->string depth))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'width (list (cons 'raw width) (cons 'formatted (number->string width))))
        (cons 'height (list (cons 'raw height) (cons 'formatted (number->string height))))
        (cons 'red-offset (list (cons 'raw red-offset) (cons 'formatted (number->string red-offset))))
        (cons 'red-length (list (cons 'raw red-length) (cons 'formatted (number->string red-length))))
        (cons 'blue-offset (list (cons 'raw blue-offset) (cons 'formatted (number->string blue-offset))))
        (cons 'blue-length (list (cons 'raw blue-length) (cons 'formatted (number->string blue-length))))
        (cons 'green-offset (list (cons 'raw green-offset) (cons 'formatted (number->string green-offset))))
        (cons 'green-length (list (cons 'raw green-length) (cons 'formatted (number->string green-length))))
        (cons 'alpha-offset (list (cons 'raw alpha-offset) (cons 'formatted (number->string alpha-offset))))
        (cons 'alpha-length (list (cons 'raw alpha-length) (cons 'formatted (number->string alpha-length))))
        (cons 'blue-5 (list (cons 'raw blue-5) (cons 'formatted (number->string blue-5))))
        (cons 'green-6 (list (cons 'raw green-6) (cons 'formatted (number->string green-6))))
        (cons 'red-5 (list (cons 'raw red-5) (cons 'formatted (number->string red-5))))
        (cons 'hf-pids (list (cons 'raw hf-pids) (cons 'formatted (utf8->string hf-pids))))
        (cons 'hf-stdin (list (cons 'raw hf-stdin) (cons 'formatted (utf8->string hf-stdin))))
        (cons 'hf-stdout (list (cons 'raw hf-stdout) (cons 'formatted (utf8->string hf-stdout))))
        (cons 'hf-data (list (cons 'raw hf-data) (cons 'formatted (fmt-bytes hf-data))))
        (cons 'hf-result (list (cons 'raw hf-result) (cons 'formatted (utf8->string hf-result))))
        (cons 'hf-service (list (cons 'raw hf-service) (cons 'formatted (utf8->string hf-service))))
        )))

    (catch (e)
      (err (str "ADB-SERVICE parse error: " e)))))

;; dissect-adb-service: parse ADB-SERVICE from bytevector
;; Returns (ok fields-alist) or (err message)