;; packet-http3.c
;; Routines for HTTP/3 dissection
;; Copyright 2019, Peter Wu <peter@lekensteyn.nl>
;; Copyright 2023, Omer Shapira <oesh@github.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/http3.ss
;; Auto-generated from wireshark/epan/dissectors/packet-http3.c

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
(def (dissect-http3 buffer)
  "Hypertext Transfer Protocol Version 3"
  (try
    (let* (
           (header-request-full-uri (unwrap (slice buffer 0 1)))
           (datagram-quarter-stream-id (unwrap (read-u64be buffer 0)))
           (datagram-request-stream-id (unwrap (read-u64be buffer 0)))
           (datagram-payload (unwrap (slice buffer 0 1)))
           (data (unwrap (slice buffer 8 1)))
           (settings-value (unwrap (read-u64be buffer 8)))
           (settings-qpack-max-table-capacity (unwrap (read-u64be buffer 8)))
           (settings-max-field-section-size (unwrap (read-u64be buffer 8)))
           (settings-qpack-blocked-streams (unwrap (read-u64be buffer 8)))
           (settings-extended-connect (unwrap (read-u64be buffer 8)))
           (settings-webtransport (unwrap (read-u64be buffer 8)))
           (settings-h3-datagram (unwrap (read-u64be buffer 8)))
           (settings-h3-datagram-draft04 (unwrap (read-u64be buffer 8)))
           (priority-update-element-id (unwrap (read-u64be buffer 8)))
           (frame-streamid (unwrap (read-u64be buffer 8)))
           (frame-length (unwrap (read-u64be buffer 8)))
           (frame-payload (unwrap (slice buffer 8 1)))
           (qpack-encoder (unwrap (slice buffer 8 1)))
           (qpack-encoder-icnt-inc (unwrap (read-u32be buffer 8)))
           (qpack-encoder-icnt (unwrap (read-u64be buffer 8)))
           (qpack-decoder (unwrap (slice buffer 8 1)))
           (push-id (unwrap (read-u64be buffer 8)))
           )

      (ok (list
        (cons 'header-request-full-uri (list (cons 'raw header-request-full-uri) (cons 'formatted (utf8->string header-request-full-uri))))
        (cons 'datagram-quarter-stream-id (list (cons 'raw datagram-quarter-stream-id) (cons 'formatted (number->string datagram-quarter-stream-id))))
        (cons 'datagram-request-stream-id (list (cons 'raw datagram-request-stream-id) (cons 'formatted (number->string datagram-request-stream-id))))
        (cons 'datagram-payload (list (cons 'raw datagram-payload) (cons 'formatted (fmt-bytes datagram-payload))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'settings-value (list (cons 'raw settings-value) (cons 'formatted (number->string settings-value))))
        (cons 'settings-qpack-max-table-capacity (list (cons 'raw settings-qpack-max-table-capacity) (cons 'formatted (number->string settings-qpack-max-table-capacity))))
        (cons 'settings-max-field-section-size (list (cons 'raw settings-max-field-section-size) (cons 'formatted (number->string settings-max-field-section-size))))
        (cons 'settings-qpack-blocked-streams (list (cons 'raw settings-qpack-blocked-streams) (cons 'formatted (number->string settings-qpack-blocked-streams))))
        (cons 'settings-extended-connect (list (cons 'raw settings-extended-connect) (cons 'formatted (number->string settings-extended-connect))))
        (cons 'settings-webtransport (list (cons 'raw settings-webtransport) (cons 'formatted (number->string settings-webtransport))))
        (cons 'settings-h3-datagram (list (cons 'raw settings-h3-datagram) (cons 'formatted (number->string settings-h3-datagram))))
        (cons 'settings-h3-datagram-draft04 (list (cons 'raw settings-h3-datagram-draft04) (cons 'formatted (number->string settings-h3-datagram-draft04))))
        (cons 'priority-update-element-id (list (cons 'raw priority-update-element-id) (cons 'formatted (number->string priority-update-element-id))))
        (cons 'frame-streamid (list (cons 'raw frame-streamid) (cons 'formatted (number->string frame-streamid))))
        (cons 'frame-length (list (cons 'raw frame-length) (cons 'formatted (number->string frame-length))))
        (cons 'frame-payload (list (cons 'raw frame-payload) (cons 'formatted (fmt-bytes frame-payload))))
        (cons 'qpack-encoder (list (cons 'raw qpack-encoder) (cons 'formatted (fmt-bytes qpack-encoder))))
        (cons 'qpack-encoder-icnt-inc (list (cons 'raw qpack-encoder-icnt-inc) (cons 'formatted (number->string qpack-encoder-icnt-inc))))
        (cons 'qpack-encoder-icnt (list (cons 'raw qpack-encoder-icnt) (cons 'formatted (number->string qpack-encoder-icnt))))
        (cons 'qpack-decoder (list (cons 'raw qpack-decoder) (cons 'formatted (fmt-bytes qpack-decoder))))
        (cons 'push-id (list (cons 'raw push-id) (cons 'formatted (number->string push-id))))
        )))

    (catch (e)
      (err (str "HTTP3 parse error: " e)))))

;; dissect-http3: parse HTTP3 from bytevector
;; Returns (ok fields-alist) or (err message)