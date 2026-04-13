;; packet-fcip.c
;; Routines for FCIP dissection
;; RFC 3821, RFC 3643
;; Copyright 2001, Dinesh G Dutt (ddutt@cisco.com)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcip.c
;; RFC 3821

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
(def (dissect-fcip buffer)
  "FCIP"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (protocol-c (unwrap (read-u8 buffer 0)))
           (version-c (unwrap (read-u8 buffer 0)))
           (encap-word1 (unwrap (read-u32be buffer 0)))
           (pflags-changed (unwrap (read-u8 buffer 0)))
           (pflags-special (unwrap (read-u8 buffer 0)))
           (pflags-c (unwrap (read-u8 buffer 0)))
           (flags (unwrap (read-u8 buffer 0)))
           (framelen (unwrap (read-u16be buffer 0)))
           (flags-c (unwrap (read-u8 buffer 0)))
           (framelen-c (unwrap (read-u16be buffer 0)))
           (tsec (unwrap (read-u32be buffer 0)))
           (tusec (unwrap (read-u32be buffer 0)))
           (encap-crc (unwrap (read-u32be buffer 0)))
           (src-entity-id (unwrap (slice buffer 0 8)))
           (conn-nonce (unwrap (slice buffer 0 8)))
           (conn-flags (unwrap (read-u8 buffer 0)))
           (conn-code (unwrap (read-u16be buffer 0)))
           (katov (unwrap (read-u32be buffer 0)))
           (sof-c (unwrap (read-u8 buffer 0)))
           (eof-c (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'protocol-c (list (cons 'raw protocol-c) (cons 'formatted (number->string protocol-c))))
        (cons 'version-c (list (cons 'raw version-c) (cons 'formatted (number->string version-c))))
        (cons 'encap-word1 (list (cons 'raw encap-word1) (cons 'formatted (fmt-hex encap-word1))))
        (cons 'pflags-changed (list (cons 'raw pflags-changed) (cons 'formatted (number->string pflags-changed))))
        (cons 'pflags-special (list (cons 'raw pflags-special) (cons 'formatted (number->string pflags-special))))
        (cons 'pflags-c (list (cons 'raw pflags-c) (cons 'formatted (fmt-hex pflags-c))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'framelen (list (cons 'raw framelen) (cons 'formatted (number->string framelen))))
        (cons 'flags-c (list (cons 'raw flags-c) (cons 'formatted (fmt-hex flags-c))))
        (cons 'framelen-c (list (cons 'raw framelen-c) (cons 'formatted (number->string framelen-c))))
        (cons 'tsec (list (cons 'raw tsec) (cons 'formatted (number->string tsec))))
        (cons 'tusec (list (cons 'raw tusec) (cons 'formatted (number->string tusec))))
        (cons 'encap-crc (list (cons 'raw encap-crc) (cons 'formatted (fmt-hex encap-crc))))
        (cons 'src-entity-id (list (cons 'raw src-entity-id) (cons 'formatted (fmt-bytes src-entity-id))))
        (cons 'conn-nonce (list (cons 'raw conn-nonce) (cons 'formatted (fmt-bytes conn-nonce))))
        (cons 'conn-flags (list (cons 'raw conn-flags) (cons 'formatted (fmt-hex conn-flags))))
        (cons 'conn-code (list (cons 'raw conn-code) (cons 'formatted (fmt-hex conn-code))))
        (cons 'katov (list (cons 'raw katov) (cons 'formatted (number->string katov))))
        (cons 'sof-c (list (cons 'raw sof-c) (cons 'formatted (fmt-hex sof-c))))
        (cons 'eof-c (list (cons 'raw eof-c) (cons 'formatted (fmt-hex eof-c))))
        )))

    (catch (e)
      (err (str "FCIP parse error: " e)))))

;; dissect-fcip: parse FCIP from bytevector
;; Returns (ok fields-alist) or (err message)