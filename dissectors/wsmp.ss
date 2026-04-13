;; packet-wsmp.c
;; Routines for WAVE Short Message  dissection (WSMP)
;; Copyright 2013, Savari Networks (http://www.savarinetworks.com) (email: smooney@savarinetworks.com)
;; Based on packet-wsmp.c implemented by
;; Arada Systems (http://www.aradasystems.com) (email: siva@aradasystems.com)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; Ref IEEE 1609.3
;;

;; jerboa-ethereal/dissectors/wsmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wsmp.c

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
(def (dissect-wsmp buffer)
  "Wave Short Message Protocol(IEEE P1609.3)"
  (try
    (let* (
           (wave-ie-data (unwrap (slice buffer 0 1)))
           (version (unwrap (read-u8 buffer 0)))
           (channel (unwrap (read-u8 buffer 0)))
           (rate (unwrap (read-u8 buffer 0)))
           (txpower (unwrap (read-u8 buffer 0)))
           (wsmlength (unwrap (read-u16be buffer 0)))
           (WSMP-S-data (unwrap (read-u8 buffer 2)))
           )

      (ok (list
        (cons 'wave-ie-data (list (cons 'raw wave-ie-data) (cons 'formatted (fmt-bytes wave-ie-data))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (number->string channel))))
        (cons 'rate (list (cons 'raw rate) (cons 'formatted (number->string rate))))
        (cons 'txpower (list (cons 'raw txpower) (cons 'formatted (number->string txpower))))
        (cons 'wsmlength (list (cons 'raw wsmlength) (cons 'formatted (number->string wsmlength))))
        (cons 'WSMP-S-data (list (cons 'raw WSMP-S-data) (cons 'formatted (fmt-hex WSMP-S-data))))
        )))

    (catch (e)
      (err (str "WSMP parse error: " e)))))

;; dissect-wsmp: parse WSMP from bytevector
;; Returns (ok fields-alist) or (err message)