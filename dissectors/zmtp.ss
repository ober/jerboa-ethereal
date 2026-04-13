;; packet-zmtp.c
;; ZeroMQ Message Transport Protocol as described at https://rfc.zeromq.org/spec/23/
;; Martin Mathieson
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zmtp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zmtp.c

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
(def (dissect-zmtp buffer)
  "ZeroMQ Message Transport Protocol"
  (try
    (let* (
           (data (unwrap (slice buffer 0 1)))
           (data-text (unwrap (slice buffer 0 1)))
           (metadata-key (unwrap (slice buffer 0 1)))
           (signature (unwrap (slice buffer 1 10)))
           (metadata-value (unwrap (slice buffer 4 1)))
           (command-name-length (unwrap (read-u8 buffer 4)))
           (command-name (unwrap (slice buffer 4 1)))
           (version (unwrap (slice buffer 10 2)))
           (version-major (unwrap (read-u8 buffer 10)))
           (version-minor (unwrap (read-u8 buffer 10)))
           (mechanism (unwrap (slice buffer 10 20)))
           (as-server (unwrap (read-u8 buffer 10)))
           (filler (unwrap (slice buffer 10 1)))
           (username (unwrap (slice buffer 12 1)))
           (password (unwrap (slice buffer 12 1)))
           (curvezmq-version (unwrap (slice buffer 12 2)))
           (curvezmq-version-major (unwrap (read-u8 buffer 12)))
           (curvezmq-version-minor (unwrap (read-u8 buffer 12)))
           (padding (unwrap (slice buffer 12 70)))
           (length (unwrap (read-u64be buffer 18)))
           (curvezmq-publickey (unwrap (slice buffer 82 32)))
           (curvezmq-signature (unwrap (slice buffer 122 80)))
           (curvezmq-cookie (unwrap (slice buffer 346 96)))
           (curvezmq-nonce (unwrap (slice buffer 442 8)))
           (curvezmq-box (unwrap (slice buffer 450 1)))
           (error-reason (unwrap (slice buffer 450 1)))
           (ping-ttl (unwrap (read-u16be buffer 450)))
           (ping-context (unwrap (slice buffer 452 1)))
           )

      (ok (list
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'data-text (list (cons 'raw data-text) (cons 'formatted (utf8->string data-text))))
        (cons 'metadata-key (list (cons 'raw metadata-key) (cons 'formatted (utf8->string metadata-key))))
        (cons 'signature (list (cons 'raw signature) (cons 'formatted (fmt-bytes signature))))
        (cons 'metadata-value (list (cons 'raw metadata-value) (cons 'formatted (utf8->string metadata-value))))
        (cons 'command-name-length (list (cons 'raw command-name-length) (cons 'formatted (number->string command-name-length))))
        (cons 'command-name (list (cons 'raw command-name) (cons 'formatted (utf8->string command-name))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (utf8->string version))))
        (cons 'version-major (list (cons 'raw version-major) (cons 'formatted (number->string version-major))))
        (cons 'version-minor (list (cons 'raw version-minor) (cons 'formatted (number->string version-minor))))
        (cons 'mechanism (list (cons 'raw mechanism) (cons 'formatted (utf8->string mechanism))))
        (cons 'as-server (list (cons 'raw as-server) (cons 'formatted (if (= as-server 0) "False" "True"))))
        (cons 'filler (list (cons 'raw filler) (cons 'formatted (fmt-bytes filler))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'curvezmq-version (list (cons 'raw curvezmq-version) (cons 'formatted (utf8->string curvezmq-version))))
        (cons 'curvezmq-version-major (list (cons 'raw curvezmq-version-major) (cons 'formatted (number->string curvezmq-version-major))))
        (cons 'curvezmq-version-minor (list (cons 'raw curvezmq-version-minor) (cons 'formatted (number->string curvezmq-version-minor))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'curvezmq-publickey (list (cons 'raw curvezmq-publickey) (cons 'formatted (fmt-bytes curvezmq-publickey))))
        (cons 'curvezmq-signature (list (cons 'raw curvezmq-signature) (cons 'formatted (fmt-bytes curvezmq-signature))))
        (cons 'curvezmq-cookie (list (cons 'raw curvezmq-cookie) (cons 'formatted (fmt-bytes curvezmq-cookie))))
        (cons 'curvezmq-nonce (list (cons 'raw curvezmq-nonce) (cons 'formatted (fmt-bytes curvezmq-nonce))))
        (cons 'curvezmq-box (list (cons 'raw curvezmq-box) (cons 'formatted (fmt-bytes curvezmq-box))))
        (cons 'error-reason (list (cons 'raw error-reason) (cons 'formatted (utf8->string error-reason))))
        (cons 'ping-ttl (list (cons 'raw ping-ttl) (cons 'formatted (number->string ping-ttl))))
        (cons 'ping-context (list (cons 'raw ping-context) (cons 'formatted (utf8->string ping-context))))
        )))

    (catch (e)
      (err (str "ZMTP parse error: " e)))))

;; dissect-zmtp: parse ZMTP from bytevector
;; Returns (ok fields-alist) or (err message)