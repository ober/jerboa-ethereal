;; packet-dtpt.c
;; Routines for Microsoft ActiveSync Desktop Pass-Through (DTPT) packet
;; dissection
;;
;; Uwe Girlich <uwe@planetquake.com>
;; http://www.synce.org/moin/ProtocolDocumentation/DesktopPassThrough
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-quake.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dtpt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dtpt.c

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
(def (dissect-dtpt buffer)
  "DeskTop PassThrough Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (queryset-rawsize (unwrap (read-u32be buffer 0)))
           (wstring-length (unwrap (read-u32be buffer 0)))
           (wstring-data (unwrap (slice buffer 0 1)))
           (handle (unwrap (read-u64be buffer 4)))
           (guid-length (unwrap (read-u32be buffer 4)))
           (guid-data (unwrap (slice buffer 4 16)))
           (sockaddr-length (unwrap (read-u16be buffer 8)))
           (sockaddr-port (unwrap (read-u16be buffer 8)))
           (sockaddr-address (unwrap (read-u32be buffer 8)))
           (padding (unwrap (slice buffer 8 8)))
           (flags (unwrap (read-u32le buffer 12)))
           (flags-res-service (extract-bits flags 0x0 0))
           (flags-flushprevious (extract-bits flags 0x0 0))
           (flags-flushcache (extract-bits flags 0x0 0))
           (flags-return-query-string (extract-bits flags 0x0 0))
           (flags-return-aliases (extract-bits flags 0x0 0))
           (flags-return-blob (extract-bits flags 0x0 0))
           (flags-return-addr (extract-bits flags 0x0 0))
           (flags-return-comment (extract-bits flags 0x0 0))
           (flags-return-version (extract-bits flags 0x0 0))
           (flags-return-type (extract-bits flags 0x0 0))
           (flags-return-name (extract-bits flags 0x0 0))
           (flags-nearest (extract-bits flags 0x0 0))
           (flags-nocontainers (extract-bits flags 0x0 0))
           (flags-containers (extract-bits flags 0x0 0))
           (flags-deep (extract-bits flags 0x0 0))
           (data-size (unwrap (read-u32be buffer 16)))
           (buffer-size (unwrap (read-u32be buffer 16)))
           (payload-size (unwrap (read-u32be buffer 16)))
           (protocols-number (unwrap (read-u32be buffer 64)))
           (protocols-length (unwrap (read-u32be buffer 64)))
           (cs-addrs-number (unwrap (read-u32be buffer 68)))
           (cs-addrs-length1 (unwrap (read-u32be buffer 68)))
           (cs-addr-local-pointer (unwrap (read-u32be buffer 96)))
           (cs-addr-local-length (unwrap (read-u32be buffer 96)))
           (cs-addr-remote-pointer (unwrap (read-u32be buffer 96)))
           (cs-addr-remote-length (unwrap (read-u32be buffer 96)))
           (blob-rawsize (unwrap (read-u32be buffer 96)))
           (blob-data-length (unwrap (read-u32be buffer 100)))
           (blob-data (unwrap (slice buffer 100 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'queryset-rawsize (list (cons 'raw queryset-rawsize) (cons 'formatted (number->string queryset-rawsize))))
        (cons 'wstring-length (list (cons 'raw wstring-length) (cons 'formatted (number->string wstring-length))))
        (cons 'wstring-data (list (cons 'raw wstring-data) (cons 'formatted (utf8->string wstring-data))))
        (cons 'handle (list (cons 'raw handle) (cons 'formatted (fmt-hex handle))))
        (cons 'guid-length (list (cons 'raw guid-length) (cons 'formatted (number->string guid-length))))
        (cons 'guid-data (list (cons 'raw guid-data) (cons 'formatted (fmt-bytes guid-data))))
        (cons 'sockaddr-length (list (cons 'raw sockaddr-length) (cons 'formatted (number->string sockaddr-length))))
        (cons 'sockaddr-port (list (cons 'raw sockaddr-port) (cons 'formatted (number->string sockaddr-port))))
        (cons 'sockaddr-address (list (cons 'raw sockaddr-address) (cons 'formatted (fmt-ipv4 sockaddr-address))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-res-service (list (cons 'raw flags-res-service) (cons 'formatted (if (= flags-res-service 0) "Not set" "Set"))))
        (cons 'flags-flushprevious (list (cons 'raw flags-flushprevious) (cons 'formatted (if (= flags-flushprevious 0) "Not set" "Set"))))
        (cons 'flags-flushcache (list (cons 'raw flags-flushcache) (cons 'formatted (if (= flags-flushcache 0) "Not set" "Set"))))
        (cons 'flags-return-query-string (list (cons 'raw flags-return-query-string) (cons 'formatted (if (= flags-return-query-string 0) "Not set" "Set"))))
        (cons 'flags-return-aliases (list (cons 'raw flags-return-aliases) (cons 'formatted (if (= flags-return-aliases 0) "Not set" "Set"))))
        (cons 'flags-return-blob (list (cons 'raw flags-return-blob) (cons 'formatted (if (= flags-return-blob 0) "Not set" "Set"))))
        (cons 'flags-return-addr (list (cons 'raw flags-return-addr) (cons 'formatted (if (= flags-return-addr 0) "Not set" "Set"))))
        (cons 'flags-return-comment (list (cons 'raw flags-return-comment) (cons 'formatted (if (= flags-return-comment 0) "Not set" "Set"))))
        (cons 'flags-return-version (list (cons 'raw flags-return-version) (cons 'formatted (if (= flags-return-version 0) "Not set" "Set"))))
        (cons 'flags-return-type (list (cons 'raw flags-return-type) (cons 'formatted (if (= flags-return-type 0) "Not set" "Set"))))
        (cons 'flags-return-name (list (cons 'raw flags-return-name) (cons 'formatted (if (= flags-return-name 0) "Not set" "Set"))))
        (cons 'flags-nearest (list (cons 'raw flags-nearest) (cons 'formatted (if (= flags-nearest 0) "Not set" "Set"))))
        (cons 'flags-nocontainers (list (cons 'raw flags-nocontainers) (cons 'formatted (if (= flags-nocontainers 0) "Not set" "Set"))))
        (cons 'flags-containers (list (cons 'raw flags-containers) (cons 'formatted (if (= flags-containers 0) "Not set" "Set"))))
        (cons 'flags-deep (list (cons 'raw flags-deep) (cons 'formatted (if (= flags-deep 0) "Not set" "Set"))))
        (cons 'data-size (list (cons 'raw data-size) (cons 'formatted (number->string data-size))))
        (cons 'buffer-size (list (cons 'raw buffer-size) (cons 'formatted (number->string buffer-size))))
        (cons 'payload-size (list (cons 'raw payload-size) (cons 'formatted (number->string payload-size))))
        (cons 'protocols-number (list (cons 'raw protocols-number) (cons 'formatted (number->string protocols-number))))
        (cons 'protocols-length (list (cons 'raw protocols-length) (cons 'formatted (number->string protocols-length))))
        (cons 'cs-addrs-number (list (cons 'raw cs-addrs-number) (cons 'formatted (number->string cs-addrs-number))))
        (cons 'cs-addrs-length1 (list (cons 'raw cs-addrs-length1) (cons 'formatted (number->string cs-addrs-length1))))
        (cons 'cs-addr-local-pointer (list (cons 'raw cs-addr-local-pointer) (cons 'formatted (fmt-hex cs-addr-local-pointer))))
        (cons 'cs-addr-local-length (list (cons 'raw cs-addr-local-length) (cons 'formatted (number->string cs-addr-local-length))))
        (cons 'cs-addr-remote-pointer (list (cons 'raw cs-addr-remote-pointer) (cons 'formatted (fmt-hex cs-addr-remote-pointer))))
        (cons 'cs-addr-remote-length (list (cons 'raw cs-addr-remote-length) (cons 'formatted (number->string cs-addr-remote-length))))
        (cons 'blob-rawsize (list (cons 'raw blob-rawsize) (cons 'formatted (number->string blob-rawsize))))
        (cons 'blob-data-length (list (cons 'raw blob-data-length) (cons 'formatted (number->string blob-data-length))))
        (cons 'blob-data (list (cons 'raw blob-data) (cons 'formatted (fmt-bytes blob-data))))
        )))

    (catch (e)
      (err (str "DTPT parse error: " e)))))

;; dissect-dtpt: parse DTPT from bytevector
;; Returns (ok fields-alist) or (err message)