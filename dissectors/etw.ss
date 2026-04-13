;; packet-etw.c
;; Routines for ETW Dissection
;;
;; Copyright 2020, Odysseus Yang
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/etw.ss
;; Auto-generated from wireshark/epan/dissectors/packet-etw.c

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
(def (dissect-etw buffer)
  "Event Tracing for Windows"
  (try
    (let* (
           (header-type (unwrap (read-u16be buffer 2)))
           (flags (unwrap (read-u16le buffer 4)))
           (header-flag-extended-info (extract-bits flags 0x1 0))
           (header-flag-private-session (extract-bits flags 0x2 1))
           (header-flag-string-only (extract-bits flags 0x4 2))
           (header-flag-trace-message (extract-bits flags 0x8 3))
           (header-flag-no-cputime (extract-bits flags 0x10 4))
           (header-flag-32-bit-header (extract-bits flags 0x20 5))
           (header-flag-64-bit-header (extract-bits flags 0x40 6))
           (header-flag-decode-guid (extract-bits flags 0x80 7))
           (header-flag-classic-header (extract-bits flags 0x100 8))
           (header-flag-processor-index (extract-bits flags 0x200 9))
           (event-property (unwrap (read-u16le buffer 6)))
           (event-property-xml (extract-bits event-property 0x1 0))
           (event-property-forwarded-xml (extract-bits event-property 0x2 1))
           (event-property-legacy-eventlog (extract-bits event-property 0x4 2))
           (event-property-legacy-reloggable (extract-bits event-property 0x8 3))
           (thread-id (unwrap (read-u32be buffer 8)))
           (process-id (unwrap (read-u32be buffer 12)))
           (time-stamp (unwrap (read-u64be buffer 16)))
           (provider-id (unwrap (slice buffer 24 16)))
           (descriptor-id (unwrap (read-u16be buffer 40)))
           (descriptor-version (unwrap (read-u8 buffer 42)))
           (descriptor-channel (unwrap (read-u8 buffer 43)))
           (descriptor-level (unwrap (read-u8 buffer 44)))
           (descriptor-opcode (unwrap (read-u8 buffer 45)))
           (descriptor-task (unwrap (read-u16be buffer 46)))
           (descriptor-keywords (unwrap (read-u64be buffer 48)))
           (processor-time (unwrap (read-u64be buffer 56)))
           (activity-id (unwrap (slice buffer 64 16)))
           (buffer-context-processor-number (unwrap (read-u8 buffer 80)))
           (buffer-context-alignment (unwrap (read-u8 buffer 81)))
           (buffer-context-logger-id (unwrap (read-u16be buffer 82)))
           (user-data-length (unwrap (read-u32be buffer 84)))
           (message-length (unwrap (read-u32be buffer 88)))
           (provider-name-length (unwrap (read-u32be buffer 92)))
           (size (unwrap (read-u16be buffer 96)))
           )

      (ok (list
        (cons 'header-type (list (cons 'raw header-type) (cons 'formatted (number->string header-type))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'header-flag-extended-info (list (cons 'raw header-flag-extended-info) (cons 'formatted (if (= header-flag-extended-info 0) "Not set" "Set"))))
        (cons 'header-flag-private-session (list (cons 'raw header-flag-private-session) (cons 'formatted (if (= header-flag-private-session 0) "Not set" "Set"))))
        (cons 'header-flag-string-only (list (cons 'raw header-flag-string-only) (cons 'formatted (if (= header-flag-string-only 0) "Not set" "Set"))))
        (cons 'header-flag-trace-message (list (cons 'raw header-flag-trace-message) (cons 'formatted (if (= header-flag-trace-message 0) "Not set" "Set"))))
        (cons 'header-flag-no-cputime (list (cons 'raw header-flag-no-cputime) (cons 'formatted (if (= header-flag-no-cputime 0) "Not set" "Set"))))
        (cons 'header-flag-32-bit-header (list (cons 'raw header-flag-32-bit-header) (cons 'formatted (if (= header-flag-32-bit-header 0) "Not set" "Set"))))
        (cons 'header-flag-64-bit-header (list (cons 'raw header-flag-64-bit-header) (cons 'formatted (if (= header-flag-64-bit-header 0) "Not set" "Set"))))
        (cons 'header-flag-decode-guid (list (cons 'raw header-flag-decode-guid) (cons 'formatted (if (= header-flag-decode-guid 0) "Not set" "Set"))))
        (cons 'header-flag-classic-header (list (cons 'raw header-flag-classic-header) (cons 'formatted (if (= header-flag-classic-header 0) "Not set" "Set"))))
        (cons 'header-flag-processor-index (list (cons 'raw header-flag-processor-index) (cons 'formatted (if (= header-flag-processor-index 0) "Not set" "Set"))))
        (cons 'event-property (list (cons 'raw event-property) (cons 'formatted (number->string event-property))))
        (cons 'event-property-xml (list (cons 'raw event-property-xml) (cons 'formatted (if (= event-property-xml 0) "Not set" "Set"))))
        (cons 'event-property-forwarded-xml (list (cons 'raw event-property-forwarded-xml) (cons 'formatted (if (= event-property-forwarded-xml 0) "Not set" "Set"))))
        (cons 'event-property-legacy-eventlog (list (cons 'raw event-property-legacy-eventlog) (cons 'formatted (if (= event-property-legacy-eventlog 0) "Not set" "Set"))))
        (cons 'event-property-legacy-reloggable (list (cons 'raw event-property-legacy-reloggable) (cons 'formatted (if (= event-property-legacy-reloggable 0) "Not set" "Set"))))
        (cons 'thread-id (list (cons 'raw thread-id) (cons 'formatted (number->string thread-id))))
        (cons 'process-id (list (cons 'raw process-id) (cons 'formatted (number->string process-id))))
        (cons 'time-stamp (list (cons 'raw time-stamp) (cons 'formatted (number->string time-stamp))))
        (cons 'provider-id (list (cons 'raw provider-id) (cons 'formatted (fmt-bytes provider-id))))
        (cons 'descriptor-id (list (cons 'raw descriptor-id) (cons 'formatted (number->string descriptor-id))))
        (cons 'descriptor-version (list (cons 'raw descriptor-version) (cons 'formatted (number->string descriptor-version))))
        (cons 'descriptor-channel (list (cons 'raw descriptor-channel) (cons 'formatted (number->string descriptor-channel))))
        (cons 'descriptor-level (list (cons 'raw descriptor-level) (cons 'formatted (number->string descriptor-level))))
        (cons 'descriptor-opcode (list (cons 'raw descriptor-opcode) (cons 'formatted (number->string descriptor-opcode))))
        (cons 'descriptor-task (list (cons 'raw descriptor-task) (cons 'formatted (number->string descriptor-task))))
        (cons 'descriptor-keywords (list (cons 'raw descriptor-keywords) (cons 'formatted (number->string descriptor-keywords))))
        (cons 'processor-time (list (cons 'raw processor-time) (cons 'formatted (number->string processor-time))))
        (cons 'activity-id (list (cons 'raw activity-id) (cons 'formatted (fmt-bytes activity-id))))
        (cons 'buffer-context-processor-number (list (cons 'raw buffer-context-processor-number) (cons 'formatted (number->string buffer-context-processor-number))))
        (cons 'buffer-context-alignment (list (cons 'raw buffer-context-alignment) (cons 'formatted (number->string buffer-context-alignment))))
        (cons 'buffer-context-logger-id (list (cons 'raw buffer-context-logger-id) (cons 'formatted (number->string buffer-context-logger-id))))
        (cons 'user-data-length (list (cons 'raw user-data-length) (cons 'formatted (number->string user-data-length))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'provider-name-length (list (cons 'raw provider-name-length) (cons 'formatted (number->string provider-name-length))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        )))

    (catch (e)
      (err (str "ETW parse error: " e)))))

;; dissect-etw: parse ETW from bytevector
;; Returns (ok fields-alist) or (err message)