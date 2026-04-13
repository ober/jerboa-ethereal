;; packet-dpauxmon.c
;; Routines for DisplayPort AUX-Channel monitor dissection
;; Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dpauxmon.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dpauxmon.c

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
(def (dissect-dpauxmon buffer)
  "DPAUXMON DisplayPort AUX channel monitor"
  (try
    (let* (
           (hf-inputs (unwrap (read-u8 buffer 1)))
           (hf-hpd (extract-bits hf-inputs 0x1 0))
           (hf-in0 (extract-bits hf-inputs 0x2 1))
           (hf-in1 (extract-bits hf-inputs 0x4 2))
           (hf-in2 (extract-bits hf-inputs 0x8 3))
           )

      (ok (list
        (cons 'hf-inputs (list (cons 'raw hf-inputs) (cons 'formatted (fmt-hex hf-inputs))))
        (cons 'hf-hpd (list (cons 'raw hf-hpd) (cons 'formatted (if (= hf-hpd 0) "Not set" "Set"))))
        (cons 'hf-in0 (list (cons 'raw hf-in0) (cons 'formatted (if (= hf-in0 0) "Not set" "Set"))))
        (cons 'hf-in1 (list (cons 'raw hf-in1) (cons 'formatted (if (= hf-in1 0) "Not set" "Set"))))
        (cons 'hf-in2 (list (cons 'raw hf-in2) (cons 'formatted (if (= hf-in2 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "DPAUXMON parse error: " e)))))

;; dissect-dpauxmon: parse DPAUXMON from bytevector
;; Returns (ok fields-alist) or (err message)