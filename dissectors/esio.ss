;; packet-esio.c
;; Routines for Ether-S-I/O dissection (from Saia Burgess Controls AG )
;; Copyright 2010, Christian Durrer <christian.durrer@sensemail.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/esio.ss
;; Auto-generated from wireshark/epan/dissectors/packet-esio.c

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
(def (dissect-esio buffer)
  "SAIA Ether-S-I/O protocol"
  (try
    (let* (
           (version (unwrap (read-u16be buffer 6)))
           (length (unwrap (read-u16be buffer 8)))
           (transaction-id (unwrap (read-u16be buffer 10)))
           (tlg-id (unwrap (read-u32be buffer 12)))
           (data-nbr (unwrap (read-u8 buffer 20)))
           (data-flags (unwrap (read-u8 buffer 21)))
           (data-transfer-id (unwrap (read-u32be buffer 22)))
           (data-dest-id (unwrap (read-u32be buffer 26)))
           (data-length (unwrap (read-u16be buffer 30)))
           (data (unwrap (read-u8 buffer 32)))
           (sts-size (unwrap (read-u16be buffer 33)))
           (src-stn-id (unwrap (read-u32be buffer 33)))
           (rio-sts (unwrap (read-u8 buffer 33)))
           (rio-tlgs-lost (unwrap (read-u8 buffer 33)))
           (rio-diag (unwrap (read-u8 buffer 33)))
           (rio-flags (unwrap (read-u8 buffer 33)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'transaction-id (list (cons 'raw transaction-id) (cons 'formatted (number->string transaction-id))))
        (cons 'tlg-id (list (cons 'raw tlg-id) (cons 'formatted (number->string tlg-id))))
        (cons 'data-nbr (list (cons 'raw data-nbr) (cons 'formatted (number->string data-nbr))))
        (cons 'data-flags (list (cons 'raw data-flags) (cons 'formatted (fmt-hex data-flags))))
        (cons 'data-transfer-id (list (cons 'raw data-transfer-id) (cons 'formatted (number->string data-transfer-id))))
        (cons 'data-dest-id (list (cons 'raw data-dest-id) (cons 'formatted (number->string data-dest-id))))
        (cons 'data-length (list (cons 'raw data-length) (cons 'formatted (number->string data-length))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (number->string data))))
        (cons 'sts-size (list (cons 'raw sts-size) (cons 'formatted (number->string sts-size))))
        (cons 'src-stn-id (list (cons 'raw src-stn-id) (cons 'formatted (number->string src-stn-id))))
        (cons 'rio-sts (list (cons 'raw rio-sts) (cons 'formatted (number->string rio-sts))))
        (cons 'rio-tlgs-lost (list (cons 'raw rio-tlgs-lost) (cons 'formatted (number->string rio-tlgs-lost))))
        (cons 'rio-diag (list (cons 'raw rio-diag) (cons 'formatted (number->string rio-diag))))
        (cons 'rio-flags (list (cons 'raw rio-flags) (cons 'formatted (fmt-hex rio-flags))))
        )))

    (catch (e)
      (err (str "ESIO parse error: " e)))))

;; dissect-esio: parse ESIO from bytevector
;; Returns (ok fields-alist) or (err message)