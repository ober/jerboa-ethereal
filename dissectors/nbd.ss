;; packet-nbd.c
;; Routines for Network Block Device (NBD) dissection.
;;
;; https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
;;
;; Ronnie sahlberg 2006
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nbd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nbd.c

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
(def (dissect-nbd buffer)
  "Network Block Device"
  (try
    (let* (
           (magic (unwrap (read-u32be buffer 0)))
           (hnd-magic (unwrap (read-u64be buffer 0)))
           (export-name-len (unwrap (read-u32be buffer 0)))
           (hnd-flags (unwrap (read-u16be buffer 0)))
           (hnd-flags-fixed-new (extract-bits hnd-flags 0x1 0))
           (hnd-flags-no-zeroes (extract-bits hnd-flags 0x0 0))
           (cmd-flags (unwrap (read-u16be buffer 4)))
           (cmd-flags-fua (extract-bits cmd-flags 0x1 0))
           (cmd-flags-no-hole (extract-bits cmd-flags 0x2 1))
           (cmd-flags-df (extract-bits cmd-flags 0x4 2))
           (cmd-flags-req-one (extract-bits cmd-flags 0x8 3))
           (cmd-flags-fast-zero (extract-bits cmd-flags 0x10 4))
           (cmd-flags-payload-len (extract-bits cmd-flags 0x20 5))
           (export-name (unwrap (slice buffer 4 1)))
           (from (unwrap (read-u64be buffer 16)))
           (export-description (unwrap (slice buffer 16 1)))
           (block-size-min (unwrap (read-u32be buffer 16)))
           (len (unwrap (read-u32be buffer 16)))
           (trans-flags (unwrap (read-u16be buffer 18)))
           (trans-flags-has-flags (extract-bits trans-flags 0x1 0))
           (trans-flags-read-only (extract-bits trans-flags 0x2 1))
           (trans-flags-flush (extract-bits trans-flags 0x4 2))
           (trans-flags-fua (extract-bits trans-flags 0x8 3))
           (trans-flags-rotational (extract-bits trans-flags 0x10 4))
           (trans-flags-trim (extract-bits trans-flags 0x20 5))
           (trans-flags-write-zeroes (extract-bits trans-flags 0x40 6))
           (trans-flags-df (extract-bits trans-flags 0x80 7))
           (trans-flags-multi-conn (extract-bits trans-flags 0x100 8))
           (trans-flags-resize (extract-bits trans-flags 0x200 9))
           (trans-flags-cache (extract-bits trans-flags 0x400 10))
           (trans-flags-fast-zero (extract-bits trans-flags 0x800 11))
           (trans-flags-block-status-payload (extract-bits trans-flags 0x1000 12))
           (info-num (unwrap (read-u16be buffer 20)))
           (block-size-prefer (unwrap (read-u32be buffer 20)))
           (reserved (unwrap (slice buffer 20 124)))
           (status-flags (unwrap (read-u32be buffer 24)))
           (payload-size-max (unwrap (read-u32be buffer 24)))
           (query-num (unwrap (read-u32be buffer 28)))
           (meta-context-id (unwrap (read-u32be buffer 28)))
           (data (unwrap (slice buffer 32 1)))
           (meta-context-name (unwrap (slice buffer 32 1)))
           (error-msg (unwrap (slice buffer 32 1)))
           (error-msg-len (unwrap (read-u16be buffer 38)))
           (reply-flags (unwrap (read-u16be buffer 40)))
           (reply-flags-done (extract-bits reply-flags 0x1 0))
           (handle (unwrap (read-u64be buffer 44)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'hnd-magic (list (cons 'raw hnd-magic) (cons 'formatted (fmt-hex hnd-magic))))
        (cons 'export-name-len (list (cons 'raw export-name-len) (cons 'formatted (number->string export-name-len))))
        (cons 'hnd-flags (list (cons 'raw hnd-flags) (cons 'formatted (fmt-hex hnd-flags))))
        (cons 'hnd-flags-fixed-new (list (cons 'raw hnd-flags-fixed-new) (cons 'formatted (if (= hnd-flags-fixed-new 0) "Not set" "Set"))))
        (cons 'hnd-flags-no-zeroes (list (cons 'raw hnd-flags-no-zeroes) (cons 'formatted (if (= hnd-flags-no-zeroes 0) "Not set" "Set"))))
        (cons 'cmd-flags (list (cons 'raw cmd-flags) (cons 'formatted (fmt-hex cmd-flags))))
        (cons 'cmd-flags-fua (list (cons 'raw cmd-flags-fua) (cons 'formatted (if (= cmd-flags-fua 0) "Not set" "Set"))))
        (cons 'cmd-flags-no-hole (list (cons 'raw cmd-flags-no-hole) (cons 'formatted (if (= cmd-flags-no-hole 0) "Not set" "Set"))))
        (cons 'cmd-flags-df (list (cons 'raw cmd-flags-df) (cons 'formatted (if (= cmd-flags-df 0) "Not set" "Set"))))
        (cons 'cmd-flags-req-one (list (cons 'raw cmd-flags-req-one) (cons 'formatted (if (= cmd-flags-req-one 0) "Not set" "Set"))))
        (cons 'cmd-flags-fast-zero (list (cons 'raw cmd-flags-fast-zero) (cons 'formatted (if (= cmd-flags-fast-zero 0) "Not set" "Set"))))
        (cons 'cmd-flags-payload-len (list (cons 'raw cmd-flags-payload-len) (cons 'formatted (if (= cmd-flags-payload-len 0) "Not set" "Set"))))
        (cons 'export-name (list (cons 'raw export-name) (cons 'formatted (utf8->string export-name))))
        (cons 'from (list (cons 'raw from) (cons 'formatted (fmt-hex from))))
        (cons 'export-description (list (cons 'raw export-description) (cons 'formatted (utf8->string export-description))))
        (cons 'block-size-min (list (cons 'raw block-size-min) (cons 'formatted (number->string block-size-min))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'trans-flags (list (cons 'raw trans-flags) (cons 'formatted (fmt-hex trans-flags))))
        (cons 'trans-flags-has-flags (list (cons 'raw trans-flags-has-flags) (cons 'formatted (if (= trans-flags-has-flags 0) "Not set" "Set"))))
        (cons 'trans-flags-read-only (list (cons 'raw trans-flags-read-only) (cons 'formatted (if (= trans-flags-read-only 0) "Not set" "Set"))))
        (cons 'trans-flags-flush (list (cons 'raw trans-flags-flush) (cons 'formatted (if (= trans-flags-flush 0) "Not set" "Set"))))
        (cons 'trans-flags-fua (list (cons 'raw trans-flags-fua) (cons 'formatted (if (= trans-flags-fua 0) "Not set" "Set"))))
        (cons 'trans-flags-rotational (list (cons 'raw trans-flags-rotational) (cons 'formatted (if (= trans-flags-rotational 0) "Not set" "Set"))))
        (cons 'trans-flags-trim (list (cons 'raw trans-flags-trim) (cons 'formatted (if (= trans-flags-trim 0) "Not set" "Set"))))
        (cons 'trans-flags-write-zeroes (list (cons 'raw trans-flags-write-zeroes) (cons 'formatted (if (= trans-flags-write-zeroes 0) "Not set" "Set"))))
        (cons 'trans-flags-df (list (cons 'raw trans-flags-df) (cons 'formatted (if (= trans-flags-df 0) "Not set" "Set"))))
        (cons 'trans-flags-multi-conn (list (cons 'raw trans-flags-multi-conn) (cons 'formatted (if (= trans-flags-multi-conn 0) "Not set" "Set"))))
        (cons 'trans-flags-resize (list (cons 'raw trans-flags-resize) (cons 'formatted (if (= trans-flags-resize 0) "Not set" "Set"))))
        (cons 'trans-flags-cache (list (cons 'raw trans-flags-cache) (cons 'formatted (if (= trans-flags-cache 0) "Not set" "Set"))))
        (cons 'trans-flags-fast-zero (list (cons 'raw trans-flags-fast-zero) (cons 'formatted (if (= trans-flags-fast-zero 0) "Not set" "Set"))))
        (cons 'trans-flags-block-status-payload (list (cons 'raw trans-flags-block-status-payload) (cons 'formatted (if (= trans-flags-block-status-payload 0) "Not set" "Set"))))
        (cons 'info-num (list (cons 'raw info-num) (cons 'formatted (number->string info-num))))
        (cons 'block-size-prefer (list (cons 'raw block-size-prefer) (cons 'formatted (number->string block-size-prefer))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'status-flags (list (cons 'raw status-flags) (cons 'formatted (number->string status-flags))))
        (cons 'payload-size-max (list (cons 'raw payload-size-max) (cons 'formatted (number->string payload-size-max))))
        (cons 'query-num (list (cons 'raw query-num) (cons 'formatted (number->string query-num))))
        (cons 'meta-context-id (list (cons 'raw meta-context-id) (cons 'formatted (number->string meta-context-id))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'meta-context-name (list (cons 'raw meta-context-name) (cons 'formatted (utf8->string meta-context-name))))
        (cons 'error-msg (list (cons 'raw error-msg) (cons 'formatted (utf8->string error-msg))))
        (cons 'error-msg-len (list (cons 'raw error-msg-len) (cons 'formatted (number->string error-msg-len))))
        (cons 'reply-flags (list (cons 'raw reply-flags) (cons 'formatted (fmt-hex reply-flags))))
        (cons 'reply-flags-done (list (cons 'raw reply-flags-done) (cons 'formatted (if (= reply-flags-done 0) "Not set" "Set"))))
        (cons 'handle (list (cons 'raw handle) (cons 'formatted (fmt-hex handle))))
        )))

    (catch (e)
      (err (str "NBD parse error: " e)))))

;; dissect-nbd: parse NBD from bytevector
;; Returns (ok fields-alist) or (err message)