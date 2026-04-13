;; packet-nano.c
;; Routines for Nano / RaiBlocks dissection
;; Copyright 2018, Roland Haenel <roland@haenel.me>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nano.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nano.c

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
(def (dissect-nano buffer)
  "Nano Cryptocurrency Protocol"
  (try
    (let* (
           (magic-number (unwrap (slice buffer 0 2)))
           (keepalive-peer-ip (unwrap (slice buffer 0 16)))
           (keepalive-peer-port (unwrap (read-u16be buffer 16)))
           (block-destination-account (unwrap (slice buffer 186 32)))
           (block-hash-source (unwrap (slice buffer 306 32)))
           (block-account (unwrap (slice buffer 610 32)))
           (block-hash-previous (unwrap (slice buffer 642 32)))
           (block-representative-account (unwrap (slice buffer 674 32)))
           (block-balance (unwrap (slice buffer 706 16)))
           (block-link (unwrap (slice buffer 722 32)))
           (block-signature (unwrap (slice buffer 754 64)))
           (block-work (unwrap (slice buffer 818 8)))
           (vote-account (unwrap (slice buffer 826 32)))
           (vote-signature (unwrap (slice buffer 858 64)))
           (vote-sequence (unwrap (read-u64be buffer 922)))
           (version-max (unwrap (read-u8 buffer 932)))
           (version-using (unwrap (read-u8 buffer 933)))
           (version-min (unwrap (read-u8 buffer 934)))
           (bulk-pull-account (unwrap (slice buffer 938 32)))
           (bulk-pull-block-hash-end (unwrap (slice buffer 970 32)))
           (frontier-req-account (unwrap (slice buffer 1002 32)))
           (frontier-req-age (unwrap (read-u32be buffer 1034)))
           (frontier-req-count (unwrap (read-u32be buffer 1038)))
           (bulk-pull-blocks-min-hash (unwrap (slice buffer 1042 32)))
           (bulk-pull-blocks-max-hash (unwrap (slice buffer 1074 32)))
           (bulk-pull-blocks-max-count (unwrap (read-u32be buffer 1107)))
           (frontier-account (unwrap (slice buffer 1111 32)))
           (frontier-head-hash (unwrap (slice buffer 1143 32)))
           )

      (ok (list
        (cons 'magic-number (list (cons 'raw magic-number) (cons 'formatted (utf8->string magic-number))))
        (cons 'keepalive-peer-ip (list (cons 'raw keepalive-peer-ip) (cons 'formatted (fmt-ipv6-address keepalive-peer-ip))))
        (cons 'keepalive-peer-port (list (cons 'raw keepalive-peer-port) (cons 'formatted (number->string keepalive-peer-port))))
        (cons 'block-destination-account (list (cons 'raw block-destination-account) (cons 'formatted (fmt-bytes block-destination-account))))
        (cons 'block-hash-source (list (cons 'raw block-hash-source) (cons 'formatted (fmt-bytes block-hash-source))))
        (cons 'block-account (list (cons 'raw block-account) (cons 'formatted (fmt-bytes block-account))))
        (cons 'block-hash-previous (list (cons 'raw block-hash-previous) (cons 'formatted (fmt-bytes block-hash-previous))))
        (cons 'block-representative-account (list (cons 'raw block-representative-account) (cons 'formatted (fmt-bytes block-representative-account))))
        (cons 'block-balance (list (cons 'raw block-balance) (cons 'formatted (fmt-bytes block-balance))))
        (cons 'block-link (list (cons 'raw block-link) (cons 'formatted (fmt-bytes block-link))))
        (cons 'block-signature (list (cons 'raw block-signature) (cons 'formatted (fmt-bytes block-signature))))
        (cons 'block-work (list (cons 'raw block-work) (cons 'formatted (fmt-bytes block-work))))
        (cons 'vote-account (list (cons 'raw vote-account) (cons 'formatted (fmt-bytes vote-account))))
        (cons 'vote-signature (list (cons 'raw vote-signature) (cons 'formatted (fmt-bytes vote-signature))))
        (cons 'vote-sequence (list (cons 'raw vote-sequence) (cons 'formatted (number->string vote-sequence))))
        (cons 'version-max (list (cons 'raw version-max) (cons 'formatted (number->string version-max))))
        (cons 'version-using (list (cons 'raw version-using) (cons 'formatted (number->string version-using))))
        (cons 'version-min (list (cons 'raw version-min) (cons 'formatted (number->string version-min))))
        (cons 'bulk-pull-account (list (cons 'raw bulk-pull-account) (cons 'formatted (fmt-bytes bulk-pull-account))))
        (cons 'bulk-pull-block-hash-end (list (cons 'raw bulk-pull-block-hash-end) (cons 'formatted (fmt-bytes bulk-pull-block-hash-end))))
        (cons 'frontier-req-account (list (cons 'raw frontier-req-account) (cons 'formatted (fmt-bytes frontier-req-account))))
        (cons 'frontier-req-age (list (cons 'raw frontier-req-age) (cons 'formatted (fmt-hex frontier-req-age))))
        (cons 'frontier-req-count (list (cons 'raw frontier-req-count) (cons 'formatted (fmt-hex frontier-req-count))))
        (cons 'bulk-pull-blocks-min-hash (list (cons 'raw bulk-pull-blocks-min-hash) (cons 'formatted (fmt-bytes bulk-pull-blocks-min-hash))))
        (cons 'bulk-pull-blocks-max-hash (list (cons 'raw bulk-pull-blocks-max-hash) (cons 'formatted (fmt-bytes bulk-pull-blocks-max-hash))))
        (cons 'bulk-pull-blocks-max-count (list (cons 'raw bulk-pull-blocks-max-count) (cons 'formatted (fmt-hex bulk-pull-blocks-max-count))))
        (cons 'frontier-account (list (cons 'raw frontier-account) (cons 'formatted (fmt-bytes frontier-account))))
        (cons 'frontier-head-hash (list (cons 'raw frontier-head-hash) (cons 'formatted (fmt-bytes frontier-head-hash))))
        )))

    (catch (e)
      (err (str "NANO parse error: " e)))))

;; dissect-nano: parse NANO from bytevector
;; Returns (ok fields-alist) or (err message)