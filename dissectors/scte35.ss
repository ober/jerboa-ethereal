;; packet-scte35.c
;; Routines for SCTE-35 dissection
;; Author: Ben Stewart <bst[at]google.com>
;; Copyright 2016 Google Inc.
;;
;; The SCTE-35 protocol is described by the Society of Cable Telecommunications
;; Engineers at <https://www.scte.org/documents/pdf/Standards/Top%20Ten/ANSI_SCTE%2035%202013.pdf>.
;;
;; This module implements a dissector for the main table in a SCTE-35 message, a
;; splice_info_section. This payload is carried in a MPEG Section Table with a
;; table ID of 0xFC. PIDs carrying this sort of table are also noted in the PMT
;; with a stream type of 0x86, and a registration descriptor with fourcc 'CUEI'.
;;
;; The various splice command types are implemented in separate modules, and are
;; linked to this dissector through the field scte35.splice_command_type. All
;; field names follow the conventions documented in the SCTE35 specification.
;;
;; This dissector does not support encrypted SCTE35 messages, other than
;; indicating through the scte35.encrypted_packet flag.
;;
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/scte35.ss
;; Auto-generated from wireshark/epan/dissectors/packet-scte35.c

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
(def (dissect-scte35 buffer)
  "SCTE-35 Time Signal"
  (try
    (let* (
           (reserved (unwrap (read-u8 buffer 0)))
           (pts (unwrap (read-u64be buffer 0)))
           (hf-identifier (unwrap (read-u32be buffer 0)))
           (tag (unwrap (read-u8 buffer 0)))
           (splice-time-tsf (unwrap (read-u8 buffer 0)))
           (splice-time-reserved (unwrap (read-u8 buffer 0)))
           (splice-time-pts-time (unwrap (read-u64be buffer 0)))
           (insert-event-id (unwrap (read-u32be buffer 0)))
           (provider-avail-id (unwrap (read-u32be buffer 0)))
           (preroll (unwrap (read-u8 buffer 0)))
           (dtmf-count (unwrap (read-u8 buffer 0)))
           (dtmf-reserved (unwrap (read-u8 buffer 0)))
           (dtmf (unwrap (slice buffer 0 1)))
           (component-reserved (unwrap (read-u8 buffer 0)))
           (component-pts-offset (unwrap (slice buffer 0 5)))
           (event-id (unwrap (read-u32be buffer 0)))
           (descriptor-length (unwrap (read-u8 buffer 0)))
           (descriptor-identifier (unwrap (read-u32be buffer 0)))
           (id (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 2)))
           (byte (unwrap (slice buffer 4 1)))
           (hf-reserved0 (unwrap (read-u8 buffer 4)))
           (time-specified-flag (unwrap (read-u8 buffer 4)))
           (time-reserved (unwrap (read-u8 buffer 4)))
           (time-pts-time (unwrap (read-u64be buffer 4)))
           (event-cancel-indicator (unwrap (read-u8 buffer 4)))
           (utc-splice-time (unwrap (read-u32be buffer 4)))
           (cancel-indicator (unwrap (read-u8 buffer 4)))
           (reserved0 (unwrap (read-u8 buffer 4)))
           (psf (unwrap (read-u8 buffer 4)))
           (segmentation-duration-flag (unwrap (read-u8 buffer 4)))
           (delivery-not-restricted-flag (unwrap (read-u8 buffer 4)))
           (reserved1 (unwrap (read-u8 buffer 4)))
           (web-delivery-allowed-flag (unwrap (read-u8 buffer 4)))
           (no-regional-blackout-flag (unwrap (read-u8 buffer 4)))
           (archive-allow-flag (unwrap (read-u8 buffer 4)))
           (segmentation-duration (unwrap (read-u64be buffer 4)))
           (index (unwrap (read-u8 buffer 7)))
           (hf-tier (unwrap (read-u16be buffer 7)))
           (command-length (unwrap (read-u16be buffer 7)))
           (count (unwrap (read-u8 buffer 8)))
           (duration-auto-return (unwrap (read-u8 buffer 8)))
           (duration-reserved (unwrap (read-u8 buffer 8)))
           (duration-duration (unwrap (read-u64be buffer 8)))
           (component-count (unwrap (read-u8 buffer 8)))
           (component-tag (unwrap (read-u8 buffer 8)))
           (component-utc-splice-time (unwrap (read-u32be buffer 8)))
           (segmentation-upid-length (unwrap (read-u8 buffer 9)))
           (segmentation-upid (unwrap (slice buffer 9 1)))
           (segment-num (unwrap (read-u8 buffer 9)))
           (segments-expected (unwrap (read-u8 buffer 9)))
           (loop-length (unwrap (read-u16be buffer 9)))
           (crc32 (unwrap (read-u32be buffer 11)))
           (break-duration-auto-return (unwrap (read-u8 buffer 12)))
           (break-duration-reserved (unwrap (read-u8 buffer 12)))
           (break-duration-duration (unwrap (read-u64be buffer 12)))
           (program-id (unwrap (read-u16be buffer 13)))
           (num (unwrap (read-u8 buffer 15)))
           (expected (unwrap (read-u8 buffer 15)))
           (hf-crc32 (unwrap (read-u32be buffer 15)))
           (unique-program-id (unwrap (read-u16be buffer 17)))
           (avail-num (unwrap (read-u8 buffer 19)))
           (avails-expected (unwrap (read-u8 buffer 19)))
           (specified (unwrap (read-u8 buffer 20)))
           )

      (ok (list
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'pts (list (cons 'raw pts) (cons 'formatted (number->string pts))))
        (cons 'hf-identifier (list (cons 'raw hf-identifier) (cons 'formatted (fmt-hex hf-identifier))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (fmt-hex tag))))
        (cons 'splice-time-tsf (list (cons 'raw splice-time-tsf) (cons 'formatted (number->string splice-time-tsf))))
        (cons 'splice-time-reserved (list (cons 'raw splice-time-reserved) (cons 'formatted (number->string splice-time-reserved))))
        (cons 'splice-time-pts-time (list (cons 'raw splice-time-pts-time) (cons 'formatted (number->string splice-time-pts-time))))
        (cons 'insert-event-id (list (cons 'raw insert-event-id) (cons 'formatted (fmt-hex insert-event-id))))
        (cons 'provider-avail-id (list (cons 'raw provider-avail-id) (cons 'formatted (fmt-hex provider-avail-id))))
        (cons 'preroll (list (cons 'raw preroll) (cons 'formatted (number->string preroll))))
        (cons 'dtmf-count (list (cons 'raw dtmf-count) (cons 'formatted (number->string dtmf-count))))
        (cons 'dtmf-reserved (list (cons 'raw dtmf-reserved) (cons 'formatted (fmt-hex dtmf-reserved))))
        (cons 'dtmf (list (cons 'raw dtmf) (cons 'formatted (utf8->string dtmf))))
        (cons 'component-reserved (list (cons 'raw component-reserved) (cons 'formatted (fmt-hex component-reserved))))
        (cons 'component-pts-offset (list (cons 'raw component-pts-offset) (cons 'formatted (number->string component-pts-offset))))
        (cons 'event-id (list (cons 'raw event-id) (cons 'formatted (fmt-hex event-id))))
        (cons 'descriptor-length (list (cons 'raw descriptor-length) (cons 'formatted (number->string descriptor-length))))
        (cons 'descriptor-identifier (list (cons 'raw descriptor-identifier) (cons 'formatted (fmt-hex descriptor-identifier))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'byte (list (cons 'raw byte) (cons 'formatted (fmt-bytes byte))))
        (cons 'hf-reserved0 (list (cons 'raw hf-reserved0) (cons 'formatted (number->string hf-reserved0))))
        (cons 'time-specified-flag (list (cons 'raw time-specified-flag) (cons 'formatted (number->string time-specified-flag))))
        (cons 'time-reserved (list (cons 'raw time-reserved) (cons 'formatted (number->string time-reserved))))
        (cons 'time-pts-time (list (cons 'raw time-pts-time) (cons 'formatted (number->string time-pts-time))))
        (cons 'event-cancel-indicator (list (cons 'raw event-cancel-indicator) (cons 'formatted (number->string event-cancel-indicator))))
        (cons 'utc-splice-time (list (cons 'raw utc-splice-time) (cons 'formatted (number->string utc-splice-time))))
        (cons 'cancel-indicator (list (cons 'raw cancel-indicator) (cons 'formatted (if (= cancel-indicator 0) "New or existing event" "Cancel Request"))))
        (cons 'reserved0 (list (cons 'raw reserved0) (cons 'formatted (fmt-hex reserved0))))
        (cons 'psf (list (cons 'raw psf) (cons 'formatted (if (= psf 0) "Component Splice Mode" "All PIDs to be spliced"))))
        (cons 'segmentation-duration-flag (list (cons 'raw segmentation-duration-flag) (cons 'formatted (if (= segmentation-duration-flag 0) "No duration present" "Segmentation duration present"))))
        (cons 'delivery-not-restricted-flag (list (cons 'raw delivery-not-restricted-flag) (cons 'formatted (if (= delivery-not-restricted-flag 0) "Restricted delivery" "No delivery restrictions"))))
        (cons 'reserved1 (list (cons 'raw reserved1) (cons 'formatted (fmt-hex reserved1))))
        (cons 'web-delivery-allowed-flag (list (cons 'raw web-delivery-allowed-flag) (cons 'formatted (if (= web-delivery-allowed-flag 0) "Restricted" "Permitted"))))
        (cons 'no-regional-blackout-flag (list (cons 'raw no-regional-blackout-flag) (cons 'formatted (if (= no-regional-blackout-flag 0) "Regional restrictions" "No regional blackouts"))))
        (cons 'archive-allow-flag (list (cons 'raw archive-allow-flag) (cons 'formatted (if (= archive-allow-flag 0) "Recording is restricted" "No recording restrictions"))))
        (cons 'segmentation-duration (list (cons 'raw segmentation-duration) (cons 'formatted (number->string segmentation-duration))))
        (cons 'index (list (cons 'raw index) (cons 'formatted (fmt-hex index))))
        (cons 'hf-tier (list (cons 'raw hf-tier) (cons 'formatted (number->string hf-tier))))
        (cons 'command-length (list (cons 'raw command-length) (cons 'formatted (number->string command-length))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'duration-auto-return (list (cons 'raw duration-auto-return) (cons 'formatted (number->string duration-auto-return))))
        (cons 'duration-reserved (list (cons 'raw duration-reserved) (cons 'formatted (number->string duration-reserved))))
        (cons 'duration-duration (list (cons 'raw duration-duration) (cons 'formatted (number->string duration-duration))))
        (cons 'component-count (list (cons 'raw component-count) (cons 'formatted (number->string component-count))))
        (cons 'component-tag (list (cons 'raw component-tag) (cons 'formatted (fmt-hex component-tag))))
        (cons 'component-utc-splice-time (list (cons 'raw component-utc-splice-time) (cons 'formatted (number->string component-utc-splice-time))))
        (cons 'segmentation-upid-length (list (cons 'raw segmentation-upid-length) (cons 'formatted (number->string segmentation-upid-length))))
        (cons 'segmentation-upid (list (cons 'raw segmentation-upid) (cons 'formatted (utf8->string segmentation-upid))))
        (cons 'segment-num (list (cons 'raw segment-num) (cons 'formatted (number->string segment-num))))
        (cons 'segments-expected (list (cons 'raw segments-expected) (cons 'formatted (number->string segments-expected))))
        (cons 'loop-length (list (cons 'raw loop-length) (cons 'formatted (number->string loop-length))))
        (cons 'crc32 (list (cons 'raw crc32) (cons 'formatted (fmt-hex crc32))))
        (cons 'break-duration-auto-return (list (cons 'raw break-duration-auto-return) (cons 'formatted (number->string break-duration-auto-return))))
        (cons 'break-duration-reserved (list (cons 'raw break-duration-reserved) (cons 'formatted (fmt-hex break-duration-reserved))))
        (cons 'break-duration-duration (list (cons 'raw break-duration-duration) (cons 'formatted (number->string break-duration-duration))))
        (cons 'program-id (list (cons 'raw program-id) (cons 'formatted (fmt-hex program-id))))
        (cons 'num (list (cons 'raw num) (cons 'formatted (number->string num))))
        (cons 'expected (list (cons 'raw expected) (cons 'formatted (number->string expected))))
        (cons 'hf-crc32 (list (cons 'raw hf-crc32) (cons 'formatted (fmt-hex hf-crc32))))
        (cons 'unique-program-id (list (cons 'raw unique-program-id) (cons 'formatted (fmt-hex unique-program-id))))
        (cons 'avail-num (list (cons 'raw avail-num) (cons 'formatted (number->string avail-num))))
        (cons 'avails-expected (list (cons 'raw avails-expected) (cons 'formatted (number->string avails-expected))))
        (cons 'specified (list (cons 'raw specified) (cons 'formatted (number->string specified))))
        )))

    (catch (e)
      (err (str "SCTE35 parse error: " e)))))

;; dissect-scte35: parse SCTE35 from bytevector
;; Returns (ok fields-alist) or (err message)