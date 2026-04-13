;; packet-dtcp-ip.c
;; Routines for DTCP-IP dissection
;; (Digital Transmission Content Protection over IP)
;;
;; Copyright 2012, Martin Kaiser <martin@kaiser.cx>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dtcp-ip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dtcp_ip.c

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
(def (dissect-dtcp-ip buffer)
  "Digital Transmission Content Protection over IP"
  (try
    (let* (
           (ip-length (unwrap (read-u16be buffer 0)))
           (ip-ctype (unwrap (read-u8 buffer 2)))
           (ip-category (unwrap (read-u8 buffer 2)))
           (ip-ake-id (unwrap (read-u8 buffer 2)))
           (ip-ake-procedure (unwrap (read-u8 buffer 2)))
           (ip-ake-proc-full (extract-bits ip-ake-procedure 0x4 2))
           (ip-ake-proc-ex-full (extract-bits ip-ake-procedure 0x8 3))
           (ip-subfct-dep (unwrap (read-u8 buffer 2)))
           (ip-ake-label (unwrap (read-u8 buffer 2)))
           (ip-number (unwrap (read-u8 buffer 2)))
           (ip-ake-info (unwrap (slice buffer 2 1)))
           (ip-type (unwrap (read-u8 buffer 3)))
           )

      (ok (list
        (cons 'ip-length (list (cons 'raw ip-length) (cons 'formatted (number->string ip-length))))
        (cons 'ip-ctype (list (cons 'raw ip-ctype) (cons 'formatted (fmt-hex ip-ctype))))
        (cons 'ip-category (list (cons 'raw ip-category) (cons 'formatted (fmt-hex ip-category))))
        (cons 'ip-ake-id (list (cons 'raw ip-ake-id) (cons 'formatted (fmt-hex ip-ake-id))))
        (cons 'ip-ake-procedure (list (cons 'raw ip-ake-procedure) (cons 'formatted (fmt-hex ip-ake-procedure))))
        (cons 'ip-ake-proc-full (list (cons 'raw ip-ake-proc-full) (cons 'formatted (if (= ip-ake-proc-full 0) "Not set" "Set"))))
        (cons 'ip-ake-proc-ex-full (list (cons 'raw ip-ake-proc-ex-full) (cons 'formatted (if (= ip-ake-proc-ex-full 0) "Not set" "Set"))))
        (cons 'ip-subfct-dep (list (cons 'raw ip-subfct-dep) (cons 'formatted (fmt-hex ip-subfct-dep))))
        (cons 'ip-ake-label (list (cons 'raw ip-ake-label) (cons 'formatted (fmt-hex ip-ake-label))))
        (cons 'ip-number (list (cons 'raw ip-number) (cons 'formatted (fmt-hex ip-number))))
        (cons 'ip-ake-info (list (cons 'raw ip-ake-info) (cons 'formatted (fmt-bytes ip-ake-info))))
        (cons 'ip-type (list (cons 'raw ip-type) (cons 'formatted (fmt-hex ip-type))))
        )))

    (catch (e)
      (err (str "DTCP-IP parse error: " e)))))

;; dissect-dtcp-ip: parse DTCP-IP from bytevector
;; Returns (ok fields-alist) or (err message)