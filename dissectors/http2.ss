;; packet-http2.c
;; Routines for HTTP2 dissection
;; Copyright 2013, Alexis La Goutte <alexis.lagoutte@gmail.com>
;; Copyright 2013, Stephen Ludin <sludin@ludin.org>
;; Copyright 2014, Daniel Stenberg <daniel@haxx.se>
;; Copyright 2014, Tatsuhiro Tsujikawa <tatsuhiro.t@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/http2.ss
;; Auto-generated from wireshark/epan/dissectors/packet-http2.c
;; RFC 7540

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
(def (dissect-http2 buffer)
  "HyperText Transfer Protocol 2"
  (try
    (let* (
           (header-request-full-uri (unwrap (slice buffer 0 1)))
           (calculated-window-size-stream-after (unwrap (read-u32be buffer 0)))
           (calculated-window-size-stream-before (unwrap (read-u32be buffer 0)))
           (calculated-window-size-connection-after (unwrap (read-u32be buffer 0)))
           (calculated-window-size-connection-before (unwrap (read-u32be buffer 0)))
           (body-reassembled-in (unwrap (read-u32be buffer 0)))
           (header-table-size (unwrap (read-u32be buffer 0)))
           (data-data (unwrap (slice buffer 0 1)))
           (data-padding (unwrap (slice buffer 0 1)))
           (headers (unwrap (slice buffer 0 1)))
           (headers-padding (unwrap (slice buffer 0 1)))
           (magic (unwrap (slice buffer 0 1)))
           (length (unwrap (read-u24be buffer 0)))
           (r (unwrap (read-u32be buffer 5)))
           (streamid (unwrap (read-u32be buffer 5)))
           (settings-header-table-size (unwrap (read-u32be buffer 6)))
           (settings-enable-push (unwrap (read-u32be buffer 6)))
           (settings-max-concurrent-streams (unwrap (read-u32be buffer 6)))
           (settings-initial-window-size (unwrap (read-u32be buffer 6)))
           (settings-max-frame-size (unwrap (read-u32be buffer 6)))
           (settings-max-header-list-size (unwrap (read-u32be buffer 6)))
           (settings-extended-connect (unwrap (read-u32be buffer 6)))
           (settings-no-rfc7540-priorities (unwrap (read-u32be buffer 6)))
           (settings-unknown (unwrap (read-u32be buffer 6)))
           (header-repr (unwrap (slice buffer 8 1)))
           (header-index (unwrap (read-u32be buffer 8)))
           (fake-header-count (unwrap (read-u32be buffer 8)))
           (header-name (unwrap (slice buffer 8 1)))
           (header-value (unwrap (slice buffer 8 1)))
           (padding (unwrap (read-u8 buffer 8)))
           (pad-length (unwrap (read-u16be buffer 8)))
           (excl-dependency (unwrap (read-u8 buffer 8)))
           (stream-dependency (unwrap (read-u32be buffer 8)))
           (unknown (unwrap (slice buffer 9 1)))
           (push-promise-r (unwrap (read-u32be buffer 10)))
           (push-promise-promised-stream-id (unwrap (read-u32be buffer 10)))
           (weight (unwrap (read-u8 buffer 12)))
           (weight-real (unwrap (read-u8 buffer 12)))
           (push-promise-header (unwrap (slice buffer 14 1)))
           (push-promise-padding (unwrap (slice buffer 14 1)))
           (pong (unwrap (slice buffer 14 8)))
           (ping (unwrap (slice buffer 14 8)))
           (goaway-r (unwrap (read-u32be buffer 22)))
           (goaway-last-stream-id (unwrap (read-u32be buffer 22)))
           (goaway-addata (unwrap (slice buffer 30 1)))
           (window-update-r (unwrap (read-u32be buffer 30)))
           (window-update-window-size-increment (unwrap (read-u32be buffer 30)))
           (continuation-header (unwrap (slice buffer 34 1)))
           (continuation-padding (unwrap (slice buffer 34 1)))
           (altsvc-origin-len (unwrap (read-u16be buffer 34)))
           (altsvc-origin (unwrap (slice buffer 36 1)))
           (altsvc-field-value (unwrap (slice buffer 36 1)))
           (origin-origin-len (unwrap (read-u16be buffer 36)))
           (origin-origin (unwrap (slice buffer 38 1)))
           (priority-update-stream-id (unwrap (read-u64be buffer 38)))
           (priority-update-field-value (unwrap (slice buffer 42 1)))
           )

      (ok (list
        (cons 'header-request-full-uri (list (cons 'raw header-request-full-uri) (cons 'formatted (utf8->string header-request-full-uri))))
        (cons 'calculated-window-size-stream-after (list (cons 'raw calculated-window-size-stream-after) (cons 'formatted (number->string calculated-window-size-stream-after))))
        (cons 'calculated-window-size-stream-before (list (cons 'raw calculated-window-size-stream-before) (cons 'formatted (number->string calculated-window-size-stream-before))))
        (cons 'calculated-window-size-connection-after (list (cons 'raw calculated-window-size-connection-after) (cons 'formatted (number->string calculated-window-size-connection-after))))
        (cons 'calculated-window-size-connection-before (list (cons 'raw calculated-window-size-connection-before) (cons 'formatted (number->string calculated-window-size-connection-before))))
        (cons 'body-reassembled-in (list (cons 'raw body-reassembled-in) (cons 'formatted (number->string body-reassembled-in))))
        (cons 'header-table-size (list (cons 'raw header-table-size) (cons 'formatted (number->string header-table-size))))
        (cons 'data-data (list (cons 'raw data-data) (cons 'formatted (fmt-bytes data-data))))
        (cons 'data-padding (list (cons 'raw data-padding) (cons 'formatted (fmt-bytes data-padding))))
        (cons 'headers (list (cons 'raw headers) (cons 'formatted (fmt-bytes headers))))
        (cons 'headers-padding (list (cons 'raw headers-padding) (cons 'formatted (fmt-bytes headers-padding))))
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (utf8->string magic))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'r (list (cons 'raw r) (cons 'formatted (fmt-hex r))))
        (cons 'streamid (list (cons 'raw streamid) (cons 'formatted (number->string streamid))))
        (cons 'settings-header-table-size (list (cons 'raw settings-header-table-size) (cons 'formatted (number->string settings-header-table-size))))
        (cons 'settings-enable-push (list (cons 'raw settings-enable-push) (cons 'formatted (number->string settings-enable-push))))
        (cons 'settings-max-concurrent-streams (list (cons 'raw settings-max-concurrent-streams) (cons 'formatted (number->string settings-max-concurrent-streams))))
        (cons 'settings-initial-window-size (list (cons 'raw settings-initial-window-size) (cons 'formatted (number->string settings-initial-window-size))))
        (cons 'settings-max-frame-size (list (cons 'raw settings-max-frame-size) (cons 'formatted (number->string settings-max-frame-size))))
        (cons 'settings-max-header-list-size (list (cons 'raw settings-max-header-list-size) (cons 'formatted (number->string settings-max-header-list-size))))
        (cons 'settings-extended-connect (list (cons 'raw settings-extended-connect) (cons 'formatted (number->string settings-extended-connect))))
        (cons 'settings-no-rfc7540-priorities (list (cons 'raw settings-no-rfc7540-priorities) (cons 'formatted (number->string settings-no-rfc7540-priorities))))
        (cons 'settings-unknown (list (cons 'raw settings-unknown) (cons 'formatted (number->string settings-unknown))))
        (cons 'header-repr (list (cons 'raw header-repr) (cons 'formatted (utf8->string header-repr))))
        (cons 'header-index (list (cons 'raw header-index) (cons 'formatted (number->string header-index))))
        (cons 'fake-header-count (list (cons 'raw fake-header-count) (cons 'formatted (number->string fake-header-count))))
        (cons 'header-name (list (cons 'raw header-name) (cons 'formatted (utf8->string header-name))))
        (cons 'header-value (list (cons 'raw header-value) (cons 'formatted (utf8->string header-value))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-hex padding))))
        (cons 'pad-length (list (cons 'raw pad-length) (cons 'formatted (number->string pad-length))))
        (cons 'excl-dependency (list (cons 'raw excl-dependency) (cons 'formatted (number->string excl-dependency))))
        (cons 'stream-dependency (list (cons 'raw stream-dependency) (cons 'formatted (number->string stream-dependency))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        (cons 'push-promise-r (list (cons 'raw push-promise-r) (cons 'formatted (fmt-hex push-promise-r))))
        (cons 'push-promise-promised-stream-id (list (cons 'raw push-promise-promised-stream-id) (cons 'formatted (number->string push-promise-promised-stream-id))))
        (cons 'weight (list (cons 'raw weight) (cons 'formatted (number->string weight))))
        (cons 'weight-real (list (cons 'raw weight-real) (cons 'formatted (number->string weight-real))))
        (cons 'push-promise-header (list (cons 'raw push-promise-header) (cons 'formatted (fmt-bytes push-promise-header))))
        (cons 'push-promise-padding (list (cons 'raw push-promise-padding) (cons 'formatted (fmt-bytes push-promise-padding))))
        (cons 'pong (list (cons 'raw pong) (cons 'formatted (fmt-bytes pong))))
        (cons 'ping (list (cons 'raw ping) (cons 'formatted (fmt-bytes ping))))
        (cons 'goaway-r (list (cons 'raw goaway-r) (cons 'formatted (fmt-hex goaway-r))))
        (cons 'goaway-last-stream-id (list (cons 'raw goaway-last-stream-id) (cons 'formatted (number->string goaway-last-stream-id))))
        (cons 'goaway-addata (list (cons 'raw goaway-addata) (cons 'formatted (fmt-bytes goaway-addata))))
        (cons 'window-update-r (list (cons 'raw window-update-r) (cons 'formatted (fmt-hex window-update-r))))
        (cons 'window-update-window-size-increment (list (cons 'raw window-update-window-size-increment) (cons 'formatted (number->string window-update-window-size-increment))))
        (cons 'continuation-header (list (cons 'raw continuation-header) (cons 'formatted (fmt-bytes continuation-header))))
        (cons 'continuation-padding (list (cons 'raw continuation-padding) (cons 'formatted (fmt-bytes continuation-padding))))
        (cons 'altsvc-origin-len (list (cons 'raw altsvc-origin-len) (cons 'formatted (number->string altsvc-origin-len))))
        (cons 'altsvc-origin (list (cons 'raw altsvc-origin) (cons 'formatted (utf8->string altsvc-origin))))
        (cons 'altsvc-field-value (list (cons 'raw altsvc-field-value) (cons 'formatted (utf8->string altsvc-field-value))))
        (cons 'origin-origin-len (list (cons 'raw origin-origin-len) (cons 'formatted (number->string origin-origin-len))))
        (cons 'origin-origin (list (cons 'raw origin-origin) (cons 'formatted (utf8->string origin-origin))))
        (cons 'priority-update-stream-id (list (cons 'raw priority-update-stream-id) (cons 'formatted (number->string priority-update-stream-id))))
        (cons 'priority-update-field-value (list (cons 'raw priority-update-field-value) (cons 'formatted (utf8->string priority-update-field-value))))
        )))

    (catch (e)
      (err (str "HTTP2 parse error: " e)))))

;; dissect-http2: parse HTTP2 from bytevector
;; Returns (ok fields-alist) or (err message)