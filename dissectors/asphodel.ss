;; packet-asphodel.c
;; Routines for Asphodel dissection
;; Copyright 2018, Greg Schwendimann <gregs@suprocktech.com>
;; Copyright 2020, Jeffrey Nichols <jsnichols@suprocktech.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: BSD-2-Clause
;;

;; jerboa-ethereal/dissectors/asphodel.ss
;; Auto-generated from wireshark/epan/dissectors/packet-asphodel.c

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
(def (dissect-asphodel buffer)
  "Asphodel"
  (try
    (let* (
           (tcp-version (unwrap (read-u8 buffer 0)))
           (connected (unwrap (read-u8 buffer 1)))
           (max-incoming-param-length (unwrap (read-u16be buffer 2)))
           (max-outgoing-param-length (unwrap (read-u16be buffer 4)))
           (stream-packet-length (unwrap (read-u16be buffer 6)))
           (protocol-type-bootloader (unwrap (read-u8 buffer 8)))
           (protocol-type-remote (unwrap (read-u8 buffer 8)))
           (protocol-type-radio (unwrap (read-u8 buffer 8)))
           (protocol-type-rf-power (unwrap (read-u8 buffer 8)))
           (protocol-type (unwrap (read-u8 buffer 8)))
           (serial-number (unwrap (slice buffer 9 1)))
           (board-rev (unwrap (read-u8 buffer 9)))
           (board-type (unwrap (slice buffer 10 1)))
           (build-info (unwrap (slice buffer 10 1)))
           (build-date (unwrap (slice buffer 10 1)))
           (user-tag1 (unwrap (slice buffer 10 1)))
           (user-tag2 (unwrap (slice buffer 10 1)))
           (remote-max-incoming-param-length (unwrap (read-u16be buffer 10)))
           (remote-max-outgoing-param-length (unwrap (read-u16be buffer 10)))
           (remote-stream-packet-length (unwrap (read-u16be buffer 10)))
           )

      (ok (list
        (cons 'tcp-version (list (cons 'raw tcp-version) (cons 'formatted (number->string tcp-version))))
        (cons 'connected (list (cons 'raw connected) (cons 'formatted (number->string connected))))
        (cons 'max-incoming-param-length (list (cons 'raw max-incoming-param-length) (cons 'formatted (number->string max-incoming-param-length))))
        (cons 'max-outgoing-param-length (list (cons 'raw max-outgoing-param-length) (cons 'formatted (number->string max-outgoing-param-length))))
        (cons 'stream-packet-length (list (cons 'raw stream-packet-length) (cons 'formatted (number->string stream-packet-length))))
        (cons 'protocol-type-bootloader (list (cons 'raw protocol-type-bootloader) (cons 'formatted (if (= protocol-type-bootloader 0) "False" "True"))))
        (cons 'protocol-type-remote (list (cons 'raw protocol-type-remote) (cons 'formatted (if (= protocol-type-remote 0) "False" "True"))))
        (cons 'protocol-type-radio (list (cons 'raw protocol-type-radio) (cons 'formatted (if (= protocol-type-radio 0) "False" "True"))))
        (cons 'protocol-type-rf-power (list (cons 'raw protocol-type-rf-power) (cons 'formatted (if (= protocol-type-rf-power 0) "False" "True"))))
        (cons 'protocol-type (list (cons 'raw protocol-type) (cons 'formatted (fmt-hex protocol-type))))
        (cons 'serial-number (list (cons 'raw serial-number) (cons 'formatted (utf8->string serial-number))))
        (cons 'board-rev (list (cons 'raw board-rev) (cons 'formatted (number->string board-rev))))
        (cons 'board-type (list (cons 'raw board-type) (cons 'formatted (utf8->string board-type))))
        (cons 'build-info (list (cons 'raw build-info) (cons 'formatted (utf8->string build-info))))
        (cons 'build-date (list (cons 'raw build-date) (cons 'formatted (utf8->string build-date))))
        (cons 'user-tag1 (list (cons 'raw user-tag1) (cons 'formatted (utf8->string user-tag1))))
        (cons 'user-tag2 (list (cons 'raw user-tag2) (cons 'formatted (utf8->string user-tag2))))
        (cons 'remote-max-incoming-param-length (list (cons 'raw remote-max-incoming-param-length) (cons 'formatted (number->string remote-max-incoming-param-length))))
        (cons 'remote-max-outgoing-param-length (list (cons 'raw remote-max-outgoing-param-length) (cons 'formatted (number->string remote-max-outgoing-param-length))))
        (cons 'remote-stream-packet-length (list (cons 'raw remote-stream-packet-length) (cons 'formatted (number->string remote-stream-packet-length))))
        )))

    (catch (e)
      (err (str "ASPHODEL parse error: " e)))))

;; dissect-asphodel: parse ASPHODEL from bytevector
;; Returns (ok fields-alist) or (err message)