;; packet-kismet.c
;; Routines for kismet packet dissection
;; Copyright 2006, Krzysztof Burghardt <krzysztof@burghardt.pl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-pop.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/kismet.ss
;; Auto-generated from wireshark/epan/dissectors/packet-kismet.c

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
(def (dissect-kismet buffer)
  "Kismet Client/Server Protocol"
  (try
    (let* (
           (response (unwrap (read-u8 buffer 0)))
           (request (unwrap (read-u8 buffer 0)))
           (version (unwrap (slice buffer 0 1)))
           (start-time (unwrap (slice buffer 0 1)))
           (server-name (unwrap (slice buffer 0 1)))
           (build-revision (unwrap (slice buffer 0 1)))
           (unknown-field (unwrap (slice buffer 0 1)))
           (extended-version-string (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'response (list (cons 'raw response) (cons 'formatted (number->string response))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (number->string request))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (utf8->string version))))
        (cons 'start-time (list (cons 'raw start-time) (cons 'formatted (utf8->string start-time))))
        (cons 'server-name (list (cons 'raw server-name) (cons 'formatted (utf8->string server-name))))
        (cons 'build-revision (list (cons 'raw build-revision) (cons 'formatted (utf8->string build-revision))))
        (cons 'unknown-field (list (cons 'raw unknown-field) (cons 'formatted (utf8->string unknown-field))))
        (cons 'extended-version-string (list (cons 'raw extended-version-string) (cons 'formatted (utf8->string extended-version-string))))
        )))

    (catch (e)
      (err (str "KISMET parse error: " e)))))

;; dissect-kismet: parse KISMET from bytevector
;; Returns (ok fields-alist) or (err message)