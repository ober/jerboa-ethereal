;; packet-nbipx.c
;; Routines for NetBIOS over IPX packet disassembly
;; Gilbert Ramirez <gram@alumni.rice.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nbipx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nbipx.c

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
(def (dissect-nbipx buffer)
  "NetBIOS over IPX"
  (try
    (let* (
           (name-flags-group (unwrap (read-u8 buffer 32)))
           (name-flags-in-use (unwrap (read-u8 buffer 32)))
           (name-flags-registered (unwrap (read-u8 buffer 32)))
           (name-flags-duplicated (unwrap (read-u8 buffer 32)))
           (name-flags-deregistered (unwrap (read-u8 buffer 32)))
           (session-src-conn-id (unwrap (read-u16be buffer 36)))
           (session-dest-conn-id (unwrap (read-u16be buffer 38)))
           (session-send-seq-number (unwrap (read-u16be buffer 40)))
           (session-total-data-length (unwrap (read-u16be buffer 42)))
           (session-offset (unwrap (read-u16be buffer 44)))
           (session-data-length (unwrap (read-u16be buffer 46)))
           (session-recv-seq-number (unwrap (read-u16be buffer 48)))
           (session-bytes-received (unwrap (read-u16be buffer 50)))
           (name-flags (unwrap (read-u8 buffer 52)))
           )

      (ok (list
        (cons 'name-flags-group (list (cons 'raw name-flags-group) (cons 'formatted (if (= name-flags-group 0) "False" "True"))))
        (cons 'name-flags-in-use (list (cons 'raw name-flags-in-use) (cons 'formatted (if (= name-flags-in-use 0) "False" "True"))))
        (cons 'name-flags-registered (list (cons 'raw name-flags-registered) (cons 'formatted (if (= name-flags-registered 0) "False" "True"))))
        (cons 'name-flags-duplicated (list (cons 'raw name-flags-duplicated) (cons 'formatted (if (= name-flags-duplicated 0) "False" "True"))))
        (cons 'name-flags-deregistered (list (cons 'raw name-flags-deregistered) (cons 'formatted (if (= name-flags-deregistered 0) "False" "True"))))
        (cons 'session-src-conn-id (list (cons 'raw session-src-conn-id) (cons 'formatted (fmt-hex session-src-conn-id))))
        (cons 'session-dest-conn-id (list (cons 'raw session-dest-conn-id) (cons 'formatted (fmt-hex session-dest-conn-id))))
        (cons 'session-send-seq-number (list (cons 'raw session-send-seq-number) (cons 'formatted (number->string session-send-seq-number))))
        (cons 'session-total-data-length (list (cons 'raw session-total-data-length) (cons 'formatted (number->string session-total-data-length))))
        (cons 'session-offset (list (cons 'raw session-offset) (cons 'formatted (number->string session-offset))))
        (cons 'session-data-length (list (cons 'raw session-data-length) (cons 'formatted (number->string session-data-length))))
        (cons 'session-recv-seq-number (list (cons 'raw session-recv-seq-number) (cons 'formatted (number->string session-recv-seq-number))))
        (cons 'session-bytes-received (list (cons 'raw session-bytes-received) (cons 'formatted (number->string session-bytes-received))))
        (cons 'name-flags (list (cons 'raw name-flags) (cons 'formatted (fmt-hex name-flags))))
        )))

    (catch (e)
      (err (str "NBIPX parse error: " e)))))

;; dissect-nbipx: parse NBIPX from bytevector
;; Returns (ok fields-alist) or (err message)