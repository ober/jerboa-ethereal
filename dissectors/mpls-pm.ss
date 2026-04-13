;; packet-mpls-pm.c
;;
;; Routines for MPLS delay and loss measurement: it should conform
;; to RFC 6374.  'PM' stands for Performance Measurement.
;;
;; Copyright 2012 _FF_
;;
;; Francesco Fondelli <francesco dot fondelli, gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mpls-pm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mpls_pm.c
;; RFC 6374

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
(def (dissect-mpls-pm buffer)
  "MPLS Direct Loss Measurement (DLM)"
  (try
    (let* (
           (pm-counter1 (unwrap (read-u64be buffer 0)))
           (pm-counter2 (unwrap (read-u64be buffer 0)))
           (pm-counter3 (unwrap (read-u64be buffer 0)))
           (pm-counter4 (unwrap (read-u64be buffer 0)))
           (pm-timestamp1-q-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp1-q-seq (unwrap (read-u64be buffer 0)))
           (pm-timestamp1-unk (unwrap (read-u64be buffer 0)))
           (pm-timestamp2-q-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp2-q-seq (unwrap (read-u64be buffer 0)))
           (pm-timestamp2-unk (unwrap (read-u64be buffer 0)))
           (pm-timestamp3-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp4-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp1-r-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp1-r-seq (unwrap (read-u64be buffer 0)))
           (pm-timestamp2-r-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp2-r-seq (unwrap (read-u64be buffer 0)))
           (pm-timestamp3-r-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp3-r-seq (unwrap (read-u64be buffer 0)))
           (pm-timestamp3-unk (unwrap (read-u64be buffer 0)))
           (pm-timestamp4-r-null (unwrap (read-u64be buffer 0)))
           (pm-timestamp4-r-seq (unwrap (read-u64be buffer 0)))
           (pm-timestamp4-unk (unwrap (read-u64be buffer 0)))
           (pm-version (unwrap (read-u8 buffer 0)))
           (pm-flags (unwrap (read-u8 buffer 0)))
           (pm-flags-r (unwrap (read-u8 buffer 0)))
           (pm-flags-t (unwrap (read-u8 buffer 0)))
           (pm-flags-res (unwrap (read-u8 buffer 0)))
           (pm-length (unwrap (read-u16be buffer 2)))
           (pm-dflags (unwrap (read-u8 buffer 4)))
           (pm-dflags-x (unwrap (read-u8 buffer 4)))
           (pm-dflags-b (unwrap (read-u8 buffer 4)))
           (pm-dflags-res (unwrap (read-u8 buffer 4)))
           (pm-session-id (unwrap (read-u32be buffer 8)))
           (pm-origin-timestamp-null (unwrap (read-u64be buffer 12)))
           (pm-origin-timestamp-seq (unwrap (read-u64be buffer 12)))
           (pm-origin-timestamp-unk (unwrap (read-u64be buffer 12)))
           )

      (ok (list
        (cons 'pm-counter1 (list (cons 'raw pm-counter1) (cons 'formatted (number->string pm-counter1))))
        (cons 'pm-counter2 (list (cons 'raw pm-counter2) (cons 'formatted (number->string pm-counter2))))
        (cons 'pm-counter3 (list (cons 'raw pm-counter3) (cons 'formatted (number->string pm-counter3))))
        (cons 'pm-counter4 (list (cons 'raw pm-counter4) (cons 'formatted (number->string pm-counter4))))
        (cons 'pm-timestamp1-q-null (list (cons 'raw pm-timestamp1-q-null) (cons 'formatted (number->string pm-timestamp1-q-null))))
        (cons 'pm-timestamp1-q-seq (list (cons 'raw pm-timestamp1-q-seq) (cons 'formatted (number->string pm-timestamp1-q-seq))))
        (cons 'pm-timestamp1-unk (list (cons 'raw pm-timestamp1-unk) (cons 'formatted (number->string pm-timestamp1-unk))))
        (cons 'pm-timestamp2-q-null (list (cons 'raw pm-timestamp2-q-null) (cons 'formatted (number->string pm-timestamp2-q-null))))
        (cons 'pm-timestamp2-q-seq (list (cons 'raw pm-timestamp2-q-seq) (cons 'formatted (number->string pm-timestamp2-q-seq))))
        (cons 'pm-timestamp2-unk (list (cons 'raw pm-timestamp2-unk) (cons 'formatted (number->string pm-timestamp2-unk))))
        (cons 'pm-timestamp3-null (list (cons 'raw pm-timestamp3-null) (cons 'formatted (number->string pm-timestamp3-null))))
        (cons 'pm-timestamp4-null (list (cons 'raw pm-timestamp4-null) (cons 'formatted (number->string pm-timestamp4-null))))
        (cons 'pm-timestamp1-r-null (list (cons 'raw pm-timestamp1-r-null) (cons 'formatted (number->string pm-timestamp1-r-null))))
        (cons 'pm-timestamp1-r-seq (list (cons 'raw pm-timestamp1-r-seq) (cons 'formatted (number->string pm-timestamp1-r-seq))))
        (cons 'pm-timestamp2-r-null (list (cons 'raw pm-timestamp2-r-null) (cons 'formatted (number->string pm-timestamp2-r-null))))
        (cons 'pm-timestamp2-r-seq (list (cons 'raw pm-timestamp2-r-seq) (cons 'formatted (number->string pm-timestamp2-r-seq))))
        (cons 'pm-timestamp3-r-null (list (cons 'raw pm-timestamp3-r-null) (cons 'formatted (number->string pm-timestamp3-r-null))))
        (cons 'pm-timestamp3-r-seq (list (cons 'raw pm-timestamp3-r-seq) (cons 'formatted (number->string pm-timestamp3-r-seq))))
        (cons 'pm-timestamp3-unk (list (cons 'raw pm-timestamp3-unk) (cons 'formatted (number->string pm-timestamp3-unk))))
        (cons 'pm-timestamp4-r-null (list (cons 'raw pm-timestamp4-r-null) (cons 'formatted (number->string pm-timestamp4-r-null))))
        (cons 'pm-timestamp4-r-seq (list (cons 'raw pm-timestamp4-r-seq) (cons 'formatted (number->string pm-timestamp4-r-seq))))
        (cons 'pm-timestamp4-unk (list (cons 'raw pm-timestamp4-unk) (cons 'formatted (number->string pm-timestamp4-unk))))
        (cons 'pm-version (list (cons 'raw pm-version) (cons 'formatted (number->string pm-version))))
        (cons 'pm-flags (list (cons 'raw pm-flags) (cons 'formatted (fmt-hex pm-flags))))
        (cons 'pm-flags-r (list (cons 'raw pm-flags-r) (cons 'formatted (if (= pm-flags-r 0) "False" "True"))))
        (cons 'pm-flags-t (list (cons 'raw pm-flags-t) (cons 'formatted (if (= pm-flags-t 0) "False" "True"))))
        (cons 'pm-flags-res (list (cons 'raw pm-flags-res) (cons 'formatted (if (= pm-flags-res 0) "False" "True"))))
        (cons 'pm-length (list (cons 'raw pm-length) (cons 'formatted (number->string pm-length))))
        (cons 'pm-dflags (list (cons 'raw pm-dflags) (cons 'formatted (fmt-hex pm-dflags))))
        (cons 'pm-dflags-x (list (cons 'raw pm-dflags-x) (cons 'formatted (if (= pm-dflags-x 0) "False" "True"))))
        (cons 'pm-dflags-b (list (cons 'raw pm-dflags-b) (cons 'formatted (if (= pm-dflags-b 0) "False" "True"))))
        (cons 'pm-dflags-res (list (cons 'raw pm-dflags-res) (cons 'formatted (number->string pm-dflags-res))))
        (cons 'pm-session-id (list (cons 'raw pm-session-id) (cons 'formatted (number->string pm-session-id))))
        (cons 'pm-origin-timestamp-null (list (cons 'raw pm-origin-timestamp-null) (cons 'formatted (number->string pm-origin-timestamp-null))))
        (cons 'pm-origin-timestamp-seq (list (cons 'raw pm-origin-timestamp-seq) (cons 'formatted (number->string pm-origin-timestamp-seq))))
        (cons 'pm-origin-timestamp-unk (list (cons 'raw pm-origin-timestamp-unk) (cons 'formatted (number->string pm-origin-timestamp-unk))))
        )))

    (catch (e)
      (err (str "MPLS-PM parse error: " e)))))

;; dissect-mpls-pm: parse MPLS-PM from bytevector
;; Returns (ok fields-alist) or (err message)