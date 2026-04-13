;; packet-iapp.c
;; Routines for IAPP dissection
;; Copyright 2002, Alfred Arnold <aarnold@elsa.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iapp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iapp.c

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
(def (dissect-iapp buffer)
  "Inter-Access-Point Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (cap-forwarding (unwrap (read-u8 buffer 0)))
           (cap-wep (unwrap (read-u8 buffer 0)))
           (auth-status (unwrap (read-u8 buffer 0)))
           (auth-string (unwrap (slice buffer 0 1)))
           (auth-uint (unwrap (read-u32be buffer 0)))
           (auth-ipaddr (unwrap (read-u32be buffer 0)))
           (auth-trailer (unwrap (slice buffer 0 1)))
           (pdu-ssid (unwrap (slice buffer 0 1)))
           (pdu-bytes (unwrap (slice buffer 0 1)))
           (pdu-uint (unwrap (read-u32be buffer 0)))
           (pdu-oui-ident (unwrap (read-u24be buffer 0)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'cap-forwarding (list (cons 'raw cap-forwarding) (cons 'formatted (if (= cap-forwarding 0) "False" "True"))))
        (cons 'cap-wep (list (cons 'raw cap-wep) (cons 'formatted (if (= cap-wep 0) "False" "True"))))
        (cons 'auth-status (list (cons 'raw auth-status) (cons 'formatted (number->string auth-status))))
        (cons 'auth-string (list (cons 'raw auth-string) (cons 'formatted (utf8->string auth-string))))
        (cons 'auth-uint (list (cons 'raw auth-uint) (cons 'formatted (number->string auth-uint))))
        (cons 'auth-ipaddr (list (cons 'raw auth-ipaddr) (cons 'formatted (fmt-ipv4 auth-ipaddr))))
        (cons 'auth-trailer (list (cons 'raw auth-trailer) (cons 'formatted (fmt-bytes auth-trailer))))
        (cons 'pdu-ssid (list (cons 'raw pdu-ssid) (cons 'formatted (utf8->string pdu-ssid))))
        (cons 'pdu-bytes (list (cons 'raw pdu-bytes) (cons 'formatted (fmt-bytes pdu-bytes))))
        (cons 'pdu-uint (list (cons 'raw pdu-uint) (cons 'formatted (number->string pdu-uint))))
        (cons 'pdu-oui-ident (list (cons 'raw pdu-oui-ident) (cons 'formatted (number->string pdu-oui-ident))))
        )))

    (catch (e)
      (err (str "IAPP parse error: " e)))))

;; dissect-iapp: parse IAPP from bytevector
;; Returns (ok fields-alist) or (err message)