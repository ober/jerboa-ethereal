;; packet-amp.c
;; Routines for Asynchronous management Protocol dissection
;; Copyright 2018, Krishnamurthy Mayya (krishnamurthymayya@gmail.com)
;; Updated to CBOR encoding: Keith Scott, 2019 (kscott@mitre.org)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/amp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-amp.c

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
(def (dissect-amp buffer)
  "AMP"
  (try
    (let* (
           (message-header (unwrap (read-u8 buffer 1)))
           (reserved (extract-bits message-header 0x0 0))
           (acl (extract-bits message-header 0x0 0))
           (nack (extract-bits message-header 0x0 0))
           (ack (extract-bits message-header 0x0 0))
           (value (unwrap (read-u8 buffer 2)))
           (ari-flags (unwrap (read-u8 buffer 2)))
           (nickname (extract-bits ari-flags 0x0 0))
           (parameters (extract-bits ari-flags 0x0 0))
           (issuer (extract-bits ari-flags 0x0 0))
           (tag (extract-bits ari-flags 0x0 0))
           (tnvc-flags (unwrap (read-u8 buffer 3)))
           (tnvc-reserved (extract-bits tnvc-flags 0x0 0))
           (tnvc-mixed (extract-bits tnvc-flags 0x0 0))
           (tnvc-typed (extract-bits tnvc-flags 0x0 0))
           (tnvc-name (extract-bits tnvc-flags 0x0 0))
           (tnvc-values (extract-bits tnvc-flags 0x0 0))
           (cbor-header (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'message-header (list (cons 'raw message-header) (cons 'formatted (number->string message-header))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (if (= reserved 0) "Not set" "Set"))))
        (cons 'acl (list (cons 'raw acl) (cons 'formatted (if (= acl 0) "Not set" "Set"))))
        (cons 'nack (list (cons 'raw nack) (cons 'formatted (if (= nack 0) "Not set" "Set"))))
        (cons 'ack (list (cons 'raw ack) (cons 'formatted (if (= ack 0) "Not set" "Set"))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (number->string value))))
        (cons 'ari-flags (list (cons 'raw ari-flags) (cons 'formatted (number->string ari-flags))))
        (cons 'nickname (list (cons 'raw nickname) (cons 'formatted (if (= nickname 0) "Not set" "Set"))))
        (cons 'parameters (list (cons 'raw parameters) (cons 'formatted (if (= parameters 0) "Not set" "Set"))))
        (cons 'issuer (list (cons 'raw issuer) (cons 'formatted (if (= issuer 0) "Not set" "Set"))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (if (= tag 0) "Not set" "Set"))))
        (cons 'tnvc-flags (list (cons 'raw tnvc-flags) (cons 'formatted (number->string tnvc-flags))))
        (cons 'tnvc-reserved (list (cons 'raw tnvc-reserved) (cons 'formatted (if (= tnvc-reserved 0) "Not set" "Set"))))
        (cons 'tnvc-mixed (list (cons 'raw tnvc-mixed) (cons 'formatted (if (= tnvc-mixed 0) "Not set" "Set"))))
        (cons 'tnvc-typed (list (cons 'raw tnvc-typed) (cons 'formatted (if (= tnvc-typed 0) "Not set" "Set"))))
        (cons 'tnvc-name (list (cons 'raw tnvc-name) (cons 'formatted (if (= tnvc-name 0) "Not set" "Set"))))
        (cons 'tnvc-values (list (cons 'raw tnvc-values) (cons 'formatted (if (= tnvc-values 0) "Not set" "Set"))))
        (cons 'cbor-header (list (cons 'raw cbor-header) (cons 'formatted (fmt-hex cbor-header))))
        )))

    (catch (e)
      (err (str "AMP parse error: " e)))))

;; dissect-amp: parse AMP from bytevector
;; Returns (ok fields-alist) or (err message)