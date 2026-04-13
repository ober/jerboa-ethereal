;; packet-dlt.c
;; DLT Dissector
;; By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
;; Copyright 2013-2019 Dr. Lars Voelker, BMW
;; Copyright 2020-2025 Dr. Lars Voelker, Technica Engineering GmbH
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dlt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dlt.c

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
(def (dissect-dlt buffer)
  "Diagnostic Log and Trace (DLT)"
  (try
    (let* (
           (storage-tstamp-s (unwrap (read-u32be buffer 0)))
           (int8 (unwrap (read-u8 buffer 4)))
           (int16 (unwrap (read-u16be buffer 4)))
           (int32 (unwrap (read-u32be buffer 4)))
           (int64 (unwrap (read-u64be buffer 4)))
           (uint8 (unwrap (read-u8 buffer 4)))
           (uint16 (unwrap (read-u16be buffer 4)))
           (uint32 (unwrap (read-u32be buffer 4)))
           (uint64 (unwrap (read-u64be buffer 4)))
           (float (unwrap (read-u32be buffer 4)))
           (double (unwrap (read-u64be buffer 4)))
           (storage-tstamp-us (unwrap (read-u32be buffer 4)))
           (rawd (unwrap (slice buffer 6 1)))
           (string (unwrap (slice buffer 8 1)))
           (storage-ecu-name (unwrap (slice buffer 8 5)))
           (service-reserved (unwrap (slice buffer 12 4)))
           (service-status-log-info (unwrap (read-u8 buffer 12)))
           (storage-reserved (unwrap (slice buffer 13 3)))
           (service-application-id (unwrap (slice buffer 15 4)))
           (service-context-id (unwrap (slice buffer 21 4)))
           (service-ctx-desc (unwrap (slice buffer 29 1)))
           (service-count (unwrap (read-u16be buffer 29)))
           (service-app-desc (unwrap (slice buffer 31 1)))
           (service-length (unwrap (read-u32be buffer 31)))
           (service-swVersion (unwrap (slice buffer 31 1)))
           (message-id (unwrap (read-u32be buffer 31)))
           (payload-data (unwrap (slice buffer 35 1)))
           (ht-ext-header (unwrap (read-u8 buffer 35)))
           (ht-msb-first (unwrap (read-u8 buffer 35)))
           (ht-with-ecuid (unwrap (read-u8 buffer 35)))
           (ht-with-sessionid (unwrap (read-u8 buffer 35)))
           (ht-with-timestamp (unwrap (read-u8 buffer 35)))
           (ht-version (unwrap (read-u8 buffer 35)))
           (msg-ctr (unwrap (read-u8 buffer 36)))
           (length (unwrap (read-u16be buffer 37)))
           (ecu-id (unwrap (slice buffer 39 4)))
           (session-id (unwrap (read-u32be buffer 43)))
           (timestamp (unwrap (read-u64be buffer 47)))
           (mi-verbose (unwrap (read-u8 buffer 51)))
           (mi-msg-type-info (unwrap (read-u8 buffer 51)))
           (num-of-args (unwrap (read-u8 buffer 52)))
           (app-id (unwrap (slice buffer 53 4)))
           (ctx-id (unwrap (slice buffer 57 4)))
           (data-bool (unwrap (read-u8 buffer 61)))
           )

      (ok (list
        (cons 'storage-tstamp-s (list (cons 'raw storage-tstamp-s) (cons 'formatted (number->string storage-tstamp-s))))
        (cons 'int8 (list (cons 'raw int8) (cons 'formatted (number->string int8))))
        (cons 'int16 (list (cons 'raw int16) (cons 'formatted (number->string int16))))
        (cons 'int32 (list (cons 'raw int32) (cons 'formatted (number->string int32))))
        (cons 'int64 (list (cons 'raw int64) (cons 'formatted (number->string int64))))
        (cons 'uint8 (list (cons 'raw uint8) (cons 'formatted (number->string uint8))))
        (cons 'uint16 (list (cons 'raw uint16) (cons 'formatted (number->string uint16))))
        (cons 'uint32 (list (cons 'raw uint32) (cons 'formatted (number->string uint32))))
        (cons 'uint64 (list (cons 'raw uint64) (cons 'formatted (number->string uint64))))
        (cons 'float (list (cons 'raw float) (cons 'formatted (number->string float))))
        (cons 'double (list (cons 'raw double) (cons 'formatted (number->string double))))
        (cons 'storage-tstamp-us (list (cons 'raw storage-tstamp-us) (cons 'formatted (number->string storage-tstamp-us))))
        (cons 'rawd (list (cons 'raw rawd) (cons 'formatted (fmt-bytes rawd))))
        (cons 'string (list (cons 'raw string) (cons 'formatted (utf8->string string))))
        (cons 'storage-ecu-name (list (cons 'raw storage-ecu-name) (cons 'formatted (utf8->string storage-ecu-name))))
        (cons 'service-reserved (list (cons 'raw service-reserved) (cons 'formatted (fmt-bytes service-reserved))))
        (cons 'service-status-log-info (list (cons 'raw service-status-log-info) (cons 'formatted (number->string service-status-log-info))))
        (cons 'storage-reserved (list (cons 'raw storage-reserved) (cons 'formatted (fmt-bytes storage-reserved))))
        (cons 'service-application-id (list (cons 'raw service-application-id) (cons 'formatted (utf8->string service-application-id))))
        (cons 'service-context-id (list (cons 'raw service-context-id) (cons 'formatted (utf8->string service-context-id))))
        (cons 'service-ctx-desc (list (cons 'raw service-ctx-desc) (cons 'formatted (utf8->string service-ctx-desc))))
        (cons 'service-count (list (cons 'raw service-count) (cons 'formatted (number->string service-count))))
        (cons 'service-app-desc (list (cons 'raw service-app-desc) (cons 'formatted (utf8->string service-app-desc))))
        (cons 'service-length (list (cons 'raw service-length) (cons 'formatted (number->string service-length))))
        (cons 'service-swVersion (list (cons 'raw service-swVersion) (cons 'formatted (utf8->string service-swVersion))))
        (cons 'message-id (list (cons 'raw message-id) (cons 'formatted (fmt-hex message-id))))
        (cons 'payload-data (list (cons 'raw payload-data) (cons 'formatted (fmt-bytes payload-data))))
        (cons 'ht-ext-header (list (cons 'raw ht-ext-header) (cons 'formatted (number->string ht-ext-header))))
        (cons 'ht-msb-first (list (cons 'raw ht-msb-first) (cons 'formatted (number->string ht-msb-first))))
        (cons 'ht-with-ecuid (list (cons 'raw ht-with-ecuid) (cons 'formatted (number->string ht-with-ecuid))))
        (cons 'ht-with-sessionid (list (cons 'raw ht-with-sessionid) (cons 'formatted (number->string ht-with-sessionid))))
        (cons 'ht-with-timestamp (list (cons 'raw ht-with-timestamp) (cons 'formatted (number->string ht-with-timestamp))))
        (cons 'ht-version (list (cons 'raw ht-version) (cons 'formatted (number->string ht-version))))
        (cons 'msg-ctr (list (cons 'raw msg-ctr) (cons 'formatted (number->string msg-ctr))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'ecu-id (list (cons 'raw ecu-id) (cons 'formatted (utf8->string ecu-id))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (number->string session-id))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'mi-verbose (list (cons 'raw mi-verbose) (cons 'formatted (number->string mi-verbose))))
        (cons 'mi-msg-type-info (list (cons 'raw mi-msg-type-info) (cons 'formatted (number->string mi-msg-type-info))))
        (cons 'num-of-args (list (cons 'raw num-of-args) (cons 'formatted (number->string num-of-args))))
        (cons 'app-id (list (cons 'raw app-id) (cons 'formatted (utf8->string app-id))))
        (cons 'ctx-id (list (cons 'raw ctx-id) (cons 'formatted (utf8->string ctx-id))))
        (cons 'data-bool (list (cons 'raw data-bool) (cons 'formatted (number->string data-bool))))
        )))

    (catch (e)
      (err (str "DLT parse error: " e)))))

;; dissect-dlt: parse DLT from bytevector
;; Returns (ok fields-alist) or (err message)