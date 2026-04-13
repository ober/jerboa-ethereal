;; packet-tzsp.c
;;
;; Copyright 2002, Tazmen Technologies Inc
;;
;; Tazmen Sniffer Protocol for encapsulating the packets across a network
;; from a remote packet sniffer. TZSP can encapsulate any other protocol.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tzsp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tzsp.c

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
(def (dissect-tzsp buffer)
  "Tazmen Sniffer Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (name (unwrap (slice buffer 0 1)))
           (location (unwrap (slice buffer 0 1)))
           (info (unwrap (slice buffer 0 1)))
           (id (unwrap (read-u32be buffer 0)))
           (hf-signal (unwrap (read-u8 buffer 0)))
           (hf-silence (unwrap (read-u8 buffer 0)))
           (hf-time (unwrap (read-u32be buffer 0)))
           (hf-sensormac (unwrap (slice buffer 0 6)))
           (hf-unknown (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'location (list (cons 'raw location) (cons 'formatted (utf8->string location))))
        (cons 'info (list (cons 'raw info) (cons 'formatted (utf8->string info))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'hf-signal (list (cons 'raw hf-signal) (cons 'formatted (number->string hf-signal))))
        (cons 'hf-silence (list (cons 'raw hf-silence) (cons 'formatted (number->string hf-silence))))
        (cons 'hf-time (list (cons 'raw hf-time) (cons 'formatted (fmt-hex hf-time))))
        (cons 'hf-sensormac (list (cons 'raw hf-sensormac) (cons 'formatted (fmt-mac hf-sensormac))))
        (cons 'hf-unknown (list (cons 'raw hf-unknown) (cons 'formatted (fmt-bytes hf-unknown))))
        )))

    (catch (e)
      (err (str "TZSP parse error: " e)))))

;; dissect-tzsp: parse TZSP from bytevector
;; Returns (ok fields-alist) or (err message)