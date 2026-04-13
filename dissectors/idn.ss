;; packet-idn.c
;; Routines for IDN dissection
;; By Maxim Kropp <maxim.kropp@hotmail.de>
;; Copyright 2017 Maxim Kropp
;;
;; Supervised by Matthias Frank <matthew@cs.uni-bonn.de>
;; Copyright 2017 Matthias Frank, Institute of Computer Science 4, University of Bonn
;;
;; Stream Specification: https://www.ilda.com/resources/StandardsDocs/ILDA_IDN-Stream_rev001.pdf
;; This specification only defines IDN messages, the other packet commands
;; are part of the hello specification which is not released yet.
;; All ILDA Technical Standards can be found at https://www.ilda.com/technical.htm
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/idn.ss
;; Auto-generated from wireshark/epan/dissectors/packet-idn.c

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
(def (dissect-idn buffer)
  "Ilda Digital Network Protocol"
  (try
    (let* (
           (event-flags (unwrap (read-u16be buffer 2)))
           (gts-sample (unwrap (slice buffer 20 1)))
           (reserved (unwrap (slice buffer 41 3)))
           (dlim (unwrap (read-u8 buffer 44)))
           (chunk-data-sequence (unwrap (read-u8 buffer 45)))
           (offset (unwrap (read-u16be buffer 46)))
           (once (unwrap (read-u8 buffer 48)))
           (four-bits-reserved (unwrap (read-u8 buffer 52)))
           (duration (unwrap (read-u24be buffer 53)))
           (chunk-header-flags (unwrap (read-u8 buffer 56)))
           (two-bits-reserved-1 (unwrap (read-u8 buffer 56)))
           (scm (unwrap (read-u8 buffer 56)))
           (dmx-base (unwrap (read-u16be buffer 56)))
           (dmx-count (unwrap (read-u8 buffer 58)))
           (dmx-void (unwrap (read-u8 buffer 58)))
           (octet (unwrap (read-u8 buffer 59)))
           (scwc (unwrap (read-u8 buffer 60)))
           (total-size (unwrap (read-u16be buffer 64)))
           (cnl (unwrap (read-u8 buffer 66)))
           (most-significant-bit-cnl (extract-bits cnl 0x80 7))
           (cclf (extract-bits cnl 0x40 6))
           (channel-id (extract-bits cnl 0x3F 0))
           (timestamp (unwrap (read-u32be buffer 68)))
           (audio-dictionary-tag (unwrap (read-u16be buffer 73)))
           (layout (extract-bits audio-dictionary-tag 0xF0 4))
           (4bit-channels (extract-bits audio-dictionary-tag 0xF 0))
           (gts-void (unwrap (read-u16be buffer 73)))
           (audio-flags (unwrap (read-u8 buffer 77)))
           (audio-flags-two-bits-reserved (extract-bits audio-flags 0xC0 6))
           (audio-flags-scm (extract-bits audio-flags 0x30 4))
           (audio-flags-four-bits-reserved (extract-bits audio-flags 0xF 0))
           (audio-duration (unwrap (read-u24be buffer 78)))
           (audio-sample-format-zero (unwrap (read-u8 buffer 81)))
           (audio-sample-format-one (unwrap (read-u16be buffer 81)))
           (audio-sample-format-two (unwrap (read-u24be buffer 83)))
           (service-id (unwrap (read-u8 buffer 86)))
           (relay-number (unwrap (read-u8 buffer 89)))
           (entry-size (unwrap (read-u8 buffer 111)))
           (relay-count (unwrap (read-u8 buffer 112)))
           (service-count (unwrap (read-u8 buffer 113)))
           (struct-size (unwrap (read-u8 buffer 114)))
           (protocol-version (unwrap (read-u8 buffer 115)))
           (protocol-version-major (extract-bits protocol-version 0xF0 4))
           (protocol-version-minor (extract-bits protocol-version 0xF 0))
           (status (unwrap (read-u8 buffer 116)))
           (malfn (extract-bits status 0x80 7))
           (offline (extract-bits status 0x40 6))
           (xcld (extract-bits status 0x20 5))
           (ocpd (extract-bits status 0x10 4))
           (three-bits-reserved (extract-bits status 0xE 1))
           (rt (extract-bits status 0x1 0))
           (reserved8 (unwrap (read-u8 buffer 117)))
           (uid-length (unwrap (read-u8 buffer 118)))
           (uid-category (unwrap (read-u8 buffer 119)))
           (name (unwrap (slice buffer 134 20)))
           (flags (unwrap (read-u8 buffer 155)))
           (sequence (unwrap (read-u16be buffer 156)))
           )

      (ok (list
        (cons 'event-flags (list (cons 'raw event-flags) (cons 'formatted (fmt-hex event-flags))))
        (cons 'gts-sample (list (cons 'raw gts-sample) (cons 'formatted (fmt-bytes gts-sample))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'dlim (list (cons 'raw dlim) (cons 'formatted (number->string dlim))))
        (cons 'chunk-data-sequence (list (cons 'raw chunk-data-sequence) (cons 'formatted (number->string chunk-data-sequence))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (fmt-hex offset))))
        (cons 'once (list (cons 'raw once) (cons 'formatted (number->string once))))
        (cons 'four-bits-reserved (list (cons 'raw four-bits-reserved) (cons 'formatted (number->string four-bits-reserved))))
        (cons 'duration (list (cons 'raw duration) (cons 'formatted (number->string duration))))
        (cons 'chunk-header-flags (list (cons 'raw chunk-header-flags) (cons 'formatted (fmt-hex chunk-header-flags))))
        (cons 'two-bits-reserved-1 (list (cons 'raw two-bits-reserved-1) (cons 'formatted (number->string two-bits-reserved-1))))
        (cons 'scm (list (cons 'raw scm) (cons 'formatted (number->string scm))))
        (cons 'dmx-base (list (cons 'raw dmx-base) (cons 'formatted (number->string dmx-base))))
        (cons 'dmx-count (list (cons 'raw dmx-count) (cons 'formatted (number->string dmx-count))))
        (cons 'dmx-void (list (cons 'raw dmx-void) (cons 'formatted (fmt-hex dmx-void))))
        (cons 'octet (list (cons 'raw octet) (cons 'formatted (fmt-hex octet))))
        (cons 'scwc (list (cons 'raw scwc) (cons 'formatted (number->string scwc))))
        (cons 'total-size (list (cons 'raw total-size) (cons 'formatted (number->string total-size))))
        (cons 'cnl (list (cons 'raw cnl) (cons 'formatted (fmt-hex cnl))))
        (cons 'most-significant-bit-cnl (list (cons 'raw most-significant-bit-cnl) (cons 'formatted (if (= most-significant-bit-cnl 0) "Not set" "Set"))))
        (cons 'cclf (list (cons 'raw cclf) (cons 'formatted (if (= cclf 0) "Not set" "Set"))))
        (cons 'channel-id (list (cons 'raw channel-id) (cons 'formatted (if (= channel-id 0) "Not set" "Set"))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'audio-dictionary-tag (list (cons 'raw audio-dictionary-tag) (cons 'formatted (fmt-hex audio-dictionary-tag))))
        (cons 'layout (list (cons 'raw layout) (cons 'formatted (if (= layout 0) "Not set" "Set"))))
        (cons '4bit-channels (list (cons 'raw 4bit-channels) (cons 'formatted (if (= 4bit-channels 0) "Not set" "Set"))))
        (cons 'gts-void (list (cons 'raw gts-void) (cons 'formatted (fmt-hex gts-void))))
        (cons 'audio-flags (list (cons 'raw audio-flags) (cons 'formatted (fmt-hex audio-flags))))
        (cons 'audio-flags-two-bits-reserved (list (cons 'raw audio-flags-two-bits-reserved) (cons 'formatted (if (= audio-flags-two-bits-reserved 0) "Not set" "Set"))))
        (cons 'audio-flags-scm (list (cons 'raw audio-flags-scm) (cons 'formatted (if (= audio-flags-scm 0) "Not set" "Set"))))
        (cons 'audio-flags-four-bits-reserved (list (cons 'raw audio-flags-four-bits-reserved) (cons 'formatted (if (= audio-flags-four-bits-reserved 0) "Not set" "Set"))))
        (cons 'audio-duration (list (cons 'raw audio-duration) (cons 'formatted (number->string audio-duration))))
        (cons 'audio-sample-format-zero (list (cons 'raw audio-sample-format-zero) (cons 'formatted (fmt-hex audio-sample-format-zero))))
        (cons 'audio-sample-format-one (list (cons 'raw audio-sample-format-one) (cons 'formatted (fmt-hex audio-sample-format-one))))
        (cons 'audio-sample-format-two (list (cons 'raw audio-sample-format-two) (cons 'formatted (fmt-hex audio-sample-format-two))))
        (cons 'service-id (list (cons 'raw service-id) (cons 'formatted (fmt-hex service-id))))
        (cons 'relay-number (list (cons 'raw relay-number) (cons 'formatted (fmt-hex relay-number))))
        (cons 'entry-size (list (cons 'raw entry-size) (cons 'formatted (number->string entry-size))))
        (cons 'relay-count (list (cons 'raw relay-count) (cons 'formatted (number->string relay-count))))
        (cons 'service-count (list (cons 'raw service-count) (cons 'formatted (number->string service-count))))
        (cons 'struct-size (list (cons 'raw struct-size) (cons 'formatted (number->string struct-size))))
        (cons 'protocol-version (list (cons 'raw protocol-version) (cons 'formatted (number->string protocol-version))))
        (cons 'protocol-version-major (list (cons 'raw protocol-version-major) (cons 'formatted (if (= protocol-version-major 0) "Not set" "Set"))))
        (cons 'protocol-version-minor (list (cons 'raw protocol-version-minor) (cons 'formatted (if (= protocol-version-minor 0) "Not set" "Set"))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (fmt-hex status))))
        (cons 'malfn (list (cons 'raw malfn) (cons 'formatted (if (= malfn 0) "Not set" "Set"))))
        (cons 'offline (list (cons 'raw offline) (cons 'formatted (if (= offline 0) "Not set" "Set"))))
        (cons 'xcld (list (cons 'raw xcld) (cons 'formatted (if (= xcld 0) "Not set" "Set"))))
        (cons 'ocpd (list (cons 'raw ocpd) (cons 'formatted (if (= ocpd 0) "Not set" "Set"))))
        (cons 'three-bits-reserved (list (cons 'raw three-bits-reserved) (cons 'formatted (if (= three-bits-reserved 0) "Not set" "Set"))))
        (cons 'rt (list (cons 'raw rt) (cons 'formatted (if (= rt 0) "Not set" "Set"))))
        (cons 'reserved8 (list (cons 'raw reserved8) (cons 'formatted (fmt-hex reserved8))))
        (cons 'uid-length (list (cons 'raw uid-length) (cons 'formatted (fmt-hex uid-length))))
        (cons 'uid-category (list (cons 'raw uid-category) (cons 'formatted (fmt-hex uid-category))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        )))

    (catch (e)
      (err (str "IDN parse error: " e)))))

;; dissect-idn: parse IDN from bytevector
;; Returns (ok fields-alist) or (err message)