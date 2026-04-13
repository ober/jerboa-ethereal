;; packet-ssh.c
;; Routines for ssh packet dissection
;;
;; Huagang XIE <huagang@intruvert.com>
;; Kees Cook <kees@outflux.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-mysql.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; Note:  support SSH v1 and v2  now.
;;
;;

;; jerboa-ethereal/dissectors/ssh.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ssh.c
;; RFC 4250

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
(def (dissect-ssh buffer)
  "SSH Protocol"
  (try
    (let* (
           (direction (unwrap (read-u8 buffer 0)))
           (pk-blob-name-length (unwrap (read-u32be buffer 0)))
           (pty-term-mode-value (unwrap (read-u32be buffer 1)))
           (pk-blob-name (unwrap (slice buffer 4 1)))
           (blob-data (unwrap (slice buffer 4 1)))
           (mpint-length (unwrap (read-u32be buffer 5)))
           (seq-num (unwrap (read-u32be buffer 6)))
           (hostkey-type (unwrap (slice buffer 25 1)))
           (hostkey-data (unwrap (slice buffer 25 1)))
           (hostsig-type (unwrap (slice buffer 37 1)))
           (hostsig-data-length (unwrap (read-u32be buffer 37)))
           (hostsig-data (unwrap (slice buffer 41 1)))
           (padding-length (unwrap (read-u8 buffer 45)))
           (payload (unwrap (slice buffer 47 1)))
           (padding-string (unwrap (slice buffer 47 1)))
           (dh-gex-min (unwrap (read-u32be buffer 53)))
           (dh-gex-nbits (unwrap (read-u32be buffer 57)))
           (dh-gex-max (unwrap (read-u32be buffer 61)))
           (hybrid-blob-client-len (unwrap (read-u32be buffer 67)))
           (hybrid-blob-server-len (unwrap (read-u32be buffer 71)))
           (packet-length (unwrap (read-u32be buffer 75)))
           (packet-length-encrypted (unwrap (slice buffer 75 4)))
           (encrypted-packet (unwrap (slice buffer 75 1)))
           (protocol (unwrap (slice buffer 75 1)))
           (cookie (unwrap (slice buffer 75 16)))
           (first-kex-packet-follows (unwrap (read-u8 buffer 91)))
           (kex-reserved (unwrap (slice buffer 92 4)))
           (kex-hassh-algo (unwrap (slice buffer 96 1)))
           (kex-hassh (unwrap (slice buffer 96 1)))
           (kex-hasshserver-algo (unwrap (slice buffer 96 1)))
           (kex-hasshserver (unwrap (slice buffer 96 1)))
           (segment-data (unwrap (slice buffer 102 1)))
           )

      (ok (list
        (cons 'direction (list (cons 'raw direction) (cons 'formatted (if (= direction 0) "False" "True"))))
        (cons 'pk-blob-name-length (list (cons 'raw pk-blob-name-length) (cons 'formatted (number->string pk-blob-name-length))))
        (cons 'pty-term-mode-value (list (cons 'raw pty-term-mode-value) (cons 'formatted (number->string pty-term-mode-value))))
        (cons 'pk-blob-name (list (cons 'raw pk-blob-name) (cons 'formatted (utf8->string pk-blob-name))))
        (cons 'blob-data (list (cons 'raw blob-data) (cons 'formatted (fmt-bytes blob-data))))
        (cons 'mpint-length (list (cons 'raw mpint-length) (cons 'formatted (number->string mpint-length))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'hostkey-type (list (cons 'raw hostkey-type) (cons 'formatted (utf8->string hostkey-type))))
        (cons 'hostkey-data (list (cons 'raw hostkey-data) (cons 'formatted (fmt-bytes hostkey-data))))
        (cons 'hostsig-type (list (cons 'raw hostsig-type) (cons 'formatted (utf8->string hostsig-type))))
        (cons 'hostsig-data-length (list (cons 'raw hostsig-data-length) (cons 'formatted (number->string hostsig-data-length))))
        (cons 'hostsig-data (list (cons 'raw hostsig-data) (cons 'formatted (fmt-bytes hostsig-data))))
        (cons 'padding-length (list (cons 'raw padding-length) (cons 'formatted (number->string padding-length))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'padding-string (list (cons 'raw padding-string) (cons 'formatted (fmt-bytes padding-string))))
        (cons 'dh-gex-min (list (cons 'raw dh-gex-min) (cons 'formatted (number->string dh-gex-min))))
        (cons 'dh-gex-nbits (list (cons 'raw dh-gex-nbits) (cons 'formatted (number->string dh-gex-nbits))))
        (cons 'dh-gex-max (list (cons 'raw dh-gex-max) (cons 'formatted (number->string dh-gex-max))))
        (cons 'hybrid-blob-client-len (list (cons 'raw hybrid-blob-client-len) (cons 'formatted (number->string hybrid-blob-client-len))))
        (cons 'hybrid-blob-server-len (list (cons 'raw hybrid-blob-server-len) (cons 'formatted (number->string hybrid-blob-server-len))))
        (cons 'packet-length (list (cons 'raw packet-length) (cons 'formatted (number->string packet-length))))
        (cons 'packet-length-encrypted (list (cons 'raw packet-length-encrypted) (cons 'formatted (fmt-bytes packet-length-encrypted))))
        (cons 'encrypted-packet (list (cons 'raw encrypted-packet) (cons 'formatted (fmt-bytes encrypted-packet))))
        (cons 'protocol (list (cons 'raw protocol) (cons 'formatted (utf8->string protocol))))
        (cons 'cookie (list (cons 'raw cookie) (cons 'formatted (fmt-bytes cookie))))
        (cons 'first-kex-packet-follows (list (cons 'raw first-kex-packet-follows) (cons 'formatted (number->string first-kex-packet-follows))))
        (cons 'kex-reserved (list (cons 'raw kex-reserved) (cons 'formatted (fmt-bytes kex-reserved))))
        (cons 'kex-hassh-algo (list (cons 'raw kex-hassh-algo) (cons 'formatted (utf8->string kex-hassh-algo))))
        (cons 'kex-hassh (list (cons 'raw kex-hassh) (cons 'formatted (utf8->string kex-hassh))))
        (cons 'kex-hasshserver-algo (list (cons 'raw kex-hasshserver-algo) (cons 'formatted (utf8->string kex-hasshserver-algo))))
        (cons 'kex-hasshserver (list (cons 'raw kex-hasshserver) (cons 'formatted (utf8->string kex-hasshserver))))
        (cons 'segment-data (list (cons 'raw segment-data) (cons 'formatted (fmt-bytes segment-data))))
        )))

    (catch (e)
      (err (str "SSH parse error: " e)))))

;; dissect-ssh: parse SSH from bytevector
;; Returns (ok fields-alist) or (err message)