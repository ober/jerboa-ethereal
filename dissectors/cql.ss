;; packet-cql.c
;; Routines for Apache Cassandra CQL dissection
;; Copyright 2015, Aaron Ten Clay <aarontc@aarontc.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cql.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cql.c

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
(def (dissect-cql buffer)
  "Cassandra CQL Protocol"
  (try
    (let* (
           (string-map-size (unwrap (read-u16be buffer 0)))
           (batch-query-size (unwrap (read-u16be buffer 21)))
           (batch-flags-bitmap (unwrap (read-u8 buffer 38)))
           (batch-flag-serial-consistency (extract-bits batch-flags-bitmap 0x0 0))
           (batch-flag-default-timestamp (extract-bits batch-flags-bitmap 0x0 0))
           (batch-flag-with-name-for-values (extract-bits batch-flags-bitmap 0x0 0))
           (error-failure-received (unwrap (read-u32be buffer 66)))
           (error-block-for (unwrap (read-u32be buffer 70)))
           (error-data-present (unwrap (read-u8 buffer 80)))
           (error-num-failures (unwrap (read-u32be buffer 80)))
           (error-write-type (unwrap (slice buffer 86 1)))
           (value-count (unwrap (read-u16be buffer 88)))
           (string-list-size (unwrap (read-u16be buffer 92)))
           (result-rows-row-count (unwrap (read-u32be buffer 108)))
           (bytes-length (unwrap (read-u32be buffer 112)))
           (bytes (unwrap (slice buffer 116 1)))
           (string (unwrap (slice buffer 118 1)))
           (query-id (unwrap (slice buffer 120 1)))
           (query-metadata-id (unwrap (slice buffer 122 1)))
           (result-prepared-flags-values (unwrap (read-u32be buffer 122)))
           (result-prepared-pk-count (unwrap (read-u32be buffer 130)))
           (result-rows-flags-values (unwrap (read-u32be buffer 134)))
           (result-rows-flag-global-tables-spec (unwrap (read-u8 buffer 134)))
           (result-rows-flag-has-more-pages (unwrap (read-u8 buffer 134)))
           (result-rows-flag-no-metadata (unwrap (read-u8 buffer 134)))
           (result-rows-column-count (unwrap (read-u32be buffer 138)))
           (short-bytes-length (unwrap (read-u16be buffer 142)))
           (event-type (unwrap (slice buffer 144 1)))
           (string-length (unwrap (read-u32be buffer 148)))
           )

      (ok (list
        (cons 'string-map-size (list (cons 'raw string-map-size) (cons 'formatted (number->string string-map-size))))
        (cons 'batch-query-size (list (cons 'raw batch-query-size) (cons 'formatted (number->string batch-query-size))))
        (cons 'batch-flags-bitmap (list (cons 'raw batch-flags-bitmap) (cons 'formatted (fmt-hex batch-flags-bitmap))))
        (cons 'batch-flag-serial-consistency (list (cons 'raw batch-flag-serial-consistency) (cons 'formatted (if (= batch-flag-serial-consistency 0) "Not set" "Set"))))
        (cons 'batch-flag-default-timestamp (list (cons 'raw batch-flag-default-timestamp) (cons 'formatted (if (= batch-flag-default-timestamp 0) "Not set" "Set"))))
        (cons 'batch-flag-with-name-for-values (list (cons 'raw batch-flag-with-name-for-values) (cons 'formatted (if (= batch-flag-with-name-for-values 0) "Not set" "Set"))))
        (cons 'error-failure-received (list (cons 'raw error-failure-received) (cons 'formatted (number->string error-failure-received))))
        (cons 'error-block-for (list (cons 'raw error-block-for) (cons 'formatted (number->string error-block-for))))
        (cons 'error-data-present (list (cons 'raw error-data-present) (cons 'formatted (number->string error-data-present))))
        (cons 'error-num-failures (list (cons 'raw error-num-failures) (cons 'formatted (number->string error-num-failures))))
        (cons 'error-write-type (list (cons 'raw error-write-type) (cons 'formatted (utf8->string error-write-type))))
        (cons 'value-count (list (cons 'raw value-count) (cons 'formatted (number->string value-count))))
        (cons 'string-list-size (list (cons 'raw string-list-size) (cons 'formatted (number->string string-list-size))))
        (cons 'result-rows-row-count (list (cons 'raw result-rows-row-count) (cons 'formatted (number->string result-rows-row-count))))
        (cons 'bytes-length (list (cons 'raw bytes-length) (cons 'formatted (number->string bytes-length))))
        (cons 'bytes (list (cons 'raw bytes) (cons 'formatted (fmt-bytes bytes))))
        (cons 'string (list (cons 'raw string) (cons 'formatted (utf8->string string))))
        (cons 'query-id (list (cons 'raw query-id) (cons 'formatted (fmt-bytes query-id))))
        (cons 'query-metadata-id (list (cons 'raw query-metadata-id) (cons 'formatted (fmt-bytes query-metadata-id))))
        (cons 'result-prepared-flags-values (list (cons 'raw result-prepared-flags-values) (cons 'formatted (number->string result-prepared-flags-values))))
        (cons 'result-prepared-pk-count (list (cons 'raw result-prepared-pk-count) (cons 'formatted (number->string result-prepared-pk-count))))
        (cons 'result-rows-flags-values (list (cons 'raw result-rows-flags-values) (cons 'formatted (number->string result-rows-flags-values))))
        (cons 'result-rows-flag-global-tables-spec (list (cons 'raw result-rows-flag-global-tables-spec) (cons 'formatted (number->string result-rows-flag-global-tables-spec))))
        (cons 'result-rows-flag-has-more-pages (list (cons 'raw result-rows-flag-has-more-pages) (cons 'formatted (number->string result-rows-flag-has-more-pages))))
        (cons 'result-rows-flag-no-metadata (list (cons 'raw result-rows-flag-no-metadata) (cons 'formatted (number->string result-rows-flag-no-metadata))))
        (cons 'result-rows-column-count (list (cons 'raw result-rows-column-count) (cons 'formatted (number->string result-rows-column-count))))
        (cons 'short-bytes-length (list (cons 'raw short-bytes-length) (cons 'formatted (number->string short-bytes-length))))
        (cons 'event-type (list (cons 'raw event-type) (cons 'formatted (utf8->string event-type))))
        (cons 'string-length (list (cons 'raw string-length) (cons 'formatted (number->string string-length))))
        )))

    (catch (e)
      (err (str "CQL parse error: " e)))))

;; dissect-cql: parse CQL from bytevector
;; Returns (ok fields-alist) or (err message)