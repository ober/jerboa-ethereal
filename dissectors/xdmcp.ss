;; packet-xdmcp.c
;; Routines for XDMCP message dissection
;; Copyright 2002, Pasi Eronen <pasi.eronen@nixu.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/xdmcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-xdmcp.c

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
(def (dissect-xdmcp buffer)
  "X Display Manager Control Protocol"
  (try
    (let* (
           (version (unwrap (read-u16be buffer 0)))
           (length (unwrap (read-u16be buffer 4)))
           (client-address-ipv4 (unwrap (read-u32be buffer 6)))
           (client-address-ipv6 (unwrap (slice buffer 12 16)))
           (client-port-u16 (unwrap (read-u16be buffer 30)))
           (display-number (unwrap (read-u16be buffer 56)))
           (session-running (unwrap (read-u8 buffer 62)))
           (session-id (unwrap (read-u32be buffer 62)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'client-address-ipv4 (list (cons 'raw client-address-ipv4) (cons 'formatted (fmt-ipv4 client-address-ipv4))))
        (cons 'client-address-ipv6 (list (cons 'raw client-address-ipv6) (cons 'formatted (fmt-ipv6-address client-address-ipv6))))
        (cons 'client-port-u16 (list (cons 'raw client-port-u16) (cons 'formatted (number->string client-port-u16))))
        (cons 'display-number (list (cons 'raw display-number) (cons 'formatted (number->string display-number))))
        (cons 'session-running (list (cons 'raw session-running) (cons 'formatted (number->string session-running))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        )))

    (catch (e)
      (err (str "XDMCP parse error: " e)))))

;; dissect-xdmcp: parse XDMCP from bytevector
;; Returns (ok fields-alist) or (err message)