;; packet-memcache.c
;; Routines for Memcache Binary Protocol
;; http://code.google.com/p/memcached/wiki/MemcacheBinaryProtocol
;;
;; Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
;;
;; Routines for Memcache Textual Protocol
;; http://code.sixapart.com/svn/memcached/trunk/server/doc/protocol.txt
;;
;; Copyright 2009, Rama Chitta <rama@gear6.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/memcache.ss
;; Auto-generated from wireshark/epan/dissectors/packet-memcache.c

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
(def (dissect-memcache buffer)
  "Memcache Protocol"
  (try
    (let* (
           (flags (unwrap (read-u32be buffer 4)))
           (hf-reserved (unwrap (read-u16be buffer 6)))
           (body-length (unwrap (read-u32be buffer 8)))
           (delta (unwrap (read-u64be buffer 12)))
           (hf-opaque (unwrap (read-u32be buffer 12)))
           (initial (unwrap (read-u64be buffer 20)))
           (response (unwrap (read-u64be buffer 24)))
           (hf-command (unwrap (slice buffer 24 1)))
           (hf-slabclass (unwrap (read-u32be buffer 24)))
           (hf-name (unwrap (slice buffer 24 1)))
           (value (unwrap (slice buffer 24 1)))
           (hf-flags (unwrap (read-u16be buffer 24)))
           (length (unwrap (read-u32be buffer 24)))
           (hf-cas (unwrap (read-u64be buffer 24)))
           (hf-version (unwrap (slice buffer 24 1)))
           (hf-response (unwrap (slice buffer 24 1)))
           (hf-value (unwrap (slice buffer 26 1)))
           (hf-noreply (unwrap (slice buffer 26 1)))
           (hf-expiration (unwrap (read-u32be buffer 26)))
           (hf-subcommand (unwrap (slice buffer 26 1)))
           (expiration (unwrap (read-u32be buffer 28)))
           (unknown (unwrap (slice buffer 36 1)))
           (hf-key (unwrap (slice buffer 36 1)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'hf-reserved (list (cons 'raw hf-reserved) (cons 'formatted (number->string hf-reserved))))
        (cons 'body-length (list (cons 'raw body-length) (cons 'formatted (number->string body-length))))
        (cons 'delta (list (cons 'raw delta) (cons 'formatted (number->string delta))))
        (cons 'hf-opaque (list (cons 'raw hf-opaque) (cons 'formatted (number->string hf-opaque))))
        (cons 'initial (list (cons 'raw initial) (cons 'formatted (number->string initial))))
        (cons 'response (list (cons 'raw response) (cons 'formatted (number->string response))))
        (cons 'hf-command (list (cons 'raw hf-command) (cons 'formatted (utf8->string hf-command))))
        (cons 'hf-slabclass (list (cons 'raw hf-slabclass) (cons 'formatted (number->string hf-slabclass))))
        (cons 'hf-name (list (cons 'raw hf-name) (cons 'formatted (utf8->string hf-name))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (utf8->string value))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (number->string hf-flags))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'hf-cas (list (cons 'raw hf-cas) (cons 'formatted (number->string hf-cas))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (utf8->string hf-version))))
        (cons 'hf-response (list (cons 'raw hf-response) (cons 'formatted (utf8->string hf-response))))
        (cons 'hf-value (list (cons 'raw hf-value) (cons 'formatted (utf8->string hf-value))))
        (cons 'hf-noreply (list (cons 'raw hf-noreply) (cons 'formatted (utf8->string hf-noreply))))
        (cons 'hf-expiration (list (cons 'raw hf-expiration) (cons 'formatted (number->string hf-expiration))))
        (cons 'hf-subcommand (list (cons 'raw hf-subcommand) (cons 'formatted (utf8->string hf-subcommand))))
        (cons 'expiration (list (cons 'raw expiration) (cons 'formatted (number->string expiration))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        (cons 'hf-key (list (cons 'raw hf-key) (cons 'formatted (utf8->string hf-key))))
        )))

    (catch (e)
      (err (str "MEMCACHE parse error: " e)))))

;; dissect-memcache: parse MEMCACHE from bytevector
;; Returns (ok fields-alist) or (err message)