;; packet-proxy.c
;; Routines for HAPROXY PROXY (v1/v2) dissection
;; Copyright 2015, Alexis La Goutte (See AUTHORS)
;; Copyright 2019 Peter Wu <peter@lekensteyn.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/proxy.ss
;; Auto-generated from wireshark/epan/dissectors/packet-proxy.c

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
(def (dissect-proxy buffer)
  "PROXY Protocol"
  (try
    (let* (
           (magic (unwrap (slice buffer 0 12)))
           (tlv-length (unwrap (read-u16be buffer 1)))
           (tlv-value (unwrap (slice buffer 3 1)))
           (tlv-ssl-client (unwrap (read-u8 buffer 3)))
           (tlv-ssl-verify (unwrap (read-u32be buffer 4)))
           (proto (unwrap (slice buffer 5 1)))
           (tlv-ssl-version (unwrap (slice buffer 8 1)))
           (tlv-ssl-cn (unwrap (slice buffer 8 1)))
           (tlv-ssl-cipher (unwrap (slice buffer 8 1)))
           (tlv-ssl-sig-alg (unwrap (slice buffer 8 1)))
           (tlv-ssl-key-alg (unwrap (slice buffer 8 1)))
           (ver (unwrap (read-u8 buffer 12)))
           (version (unwrap (read-u8 buffer 12)))
           (protocol (unwrap (read-u8 buffer 13)))
           (len (unwrap (read-u16be buffer 14)))
           (src-ipv4 (unwrap (read-u32be buffer 16)))
           (dst-ipv4 (unwrap (read-u32be buffer 20)))
           (src-ipv6 (unwrap (slice buffer 28 16)))
           (dst-ipv6 (unwrap (slice buffer 44 16)))
           (srcport (unwrap (read-u16be buffer 60)))
           (dstport (unwrap (read-u16be buffer 62)))
           (src-unix (unwrap (slice buffer 64 108)))
           (dst-unix (unwrap (slice buffer 172 108)))
           (unknown (unwrap (slice buffer 280 1)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-bytes magic))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (number->string tlv-length))))
        (cons 'tlv-value (list (cons 'raw tlv-value) (cons 'formatted (fmt-bytes tlv-value))))
        (cons 'tlv-ssl-client (list (cons 'raw tlv-ssl-client) (cons 'formatted (fmt-hex tlv-ssl-client))))
        (cons 'tlv-ssl-verify (list (cons 'raw tlv-ssl-verify) (cons 'formatted (fmt-hex tlv-ssl-verify))))
        (cons 'proto (list (cons 'raw proto) (cons 'formatted (utf8->string proto))))
        (cons 'tlv-ssl-version (list (cons 'raw tlv-ssl-version) (cons 'formatted (utf8->string tlv-ssl-version))))
        (cons 'tlv-ssl-cn (list (cons 'raw tlv-ssl-cn) (cons 'formatted (utf8->string tlv-ssl-cn))))
        (cons 'tlv-ssl-cipher (list (cons 'raw tlv-ssl-cipher) (cons 'formatted (utf8->string tlv-ssl-cipher))))
        (cons 'tlv-ssl-sig-alg (list (cons 'raw tlv-ssl-sig-alg) (cons 'formatted (utf8->string tlv-ssl-sig-alg))))
        (cons 'tlv-ssl-key-alg (list (cons 'raw tlv-ssl-key-alg) (cons 'formatted (utf8->string tlv-ssl-key-alg))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'protocol (list (cons 'raw protocol) (cons 'formatted (fmt-hex protocol))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'src-ipv4 (list (cons 'raw src-ipv4) (cons 'formatted (fmt-ipv4 src-ipv4))))
        (cons 'dst-ipv4 (list (cons 'raw dst-ipv4) (cons 'formatted (fmt-ipv4 dst-ipv4))))
        (cons 'src-ipv6 (list (cons 'raw src-ipv6) (cons 'formatted (fmt-ipv6-address src-ipv6))))
        (cons 'dst-ipv6 (list (cons 'raw dst-ipv6) (cons 'formatted (fmt-ipv6-address dst-ipv6))))
        (cons 'srcport (list (cons 'raw srcport) (cons 'formatted (number->string srcport))))
        (cons 'dstport (list (cons 'raw dstport) (cons 'formatted (number->string dstport))))
        (cons 'src-unix (list (cons 'raw src-unix) (cons 'formatted (fmt-bytes src-unix))))
        (cons 'dst-unix (list (cons 'raw dst-unix) (cons 'formatted (fmt-bytes dst-unix))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        )))

    (catch (e)
      (err (str "PROXY parse error: " e)))))

;; dissect-proxy: parse PROXY from bytevector
;; Returns (ok fields-alist) or (err message)