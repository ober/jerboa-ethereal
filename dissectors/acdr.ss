;; packet-acdr.c
;; Routines for acdr packet dissection
;; Copyright 2019, AudioCodes Ltd
;; @author: Alex Rodikov <alex.rodikov@audiocodes.com>
;; @author: Beni Bloch <beni.bloch@audiocodes.com>
;; @author: Orgad Shaneh <orgad.shaneh@audiocodes.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/acdr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-acdr.c

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
(def (dissect-acdr buffer)
  "Debug Recording Trace"
  (try
    (let* (
           (hpi-udp-checksum (unwrap (read-u8 buffer 0)))
           (hpi-sync5 (unwrap (read-u8 buffer 0)))
           (analysis-version (unwrap (read-u16be buffer 0)))
           (session-id (unwrap (slice buffer 0 1)))
           (session-id-board-id (unwrap (read-u24be buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (seq-num (unwrap (read-u16be buffer 0)))
           (hpi-resource-id (unwrap (read-u8 buffer 1)))
           (hpi-favorite (unwrap (read-u8 buffer 2)))
           (analysis-sub-version (unwrap (read-u8 buffer 2)))
           (analysis-direction (unwrap (read-u8 buffer 2)))
           (data (unwrap (read-u8 buffer 2)))
           (pl-offset-type (unwrap (read-u8 buffer 2)))
           (header-ext-len-type (unwrap (read-u8 buffer 2)))
           (session-id-session-number (unwrap (read-u32be buffer 2)))
           (hpi-protocol (unwrap (read-u8 buffer 3)))
           (analysis-device (unwrap (read-u8 buffer 3)))
           (session-id-reset-counter (unwrap (read-u8 buffer 3)))
           (analysis-sequence (unwrap (read-u16be buffer 4)))
           (analysis-spare1 (unwrap (read-u16be buffer 6)))
           (session-id-long-session-number (unwrap (slice buffer 7 5)))
           (analysis-timestamp (unwrap (read-u32be buffer 8)))
           (analysis-spare2 (unwrap (read-u32be buffer 12)))
           (ext-dsp-core (unwrap (read-u8 buffer 12)))
           (ext-dsp-channel (unwrap (read-u8 buffer 12)))
           (ext-pstn-trace-seq-num (unwrap (read-u32be buffer 12)))
           (ext-event-id (unwrap (read-u8 buffer 12)))
           (ext-event-source (unwrap (read-u8 buffer 12)))
           (ext-srcipv6 (unwrap (slice buffer 12 16)))
           (ext-c5-control-flags (unwrap (read-u8 buffer 36)))
           (ext-c5-control-favorite (extract-bits ext-c5-control-flags 0x0 0))
           (ext-dstipv6 (unwrap (slice buffer 36 16)))
           (ext-iptos (unwrap (read-u8 buffer 60)))
           (ext-srcudp (unwrap (read-u16be buffer 72)))
           (ext-dstudp (unwrap (read-u16be buffer 74)))
           (ext-srcip (unwrap (read-u32be buffer 76)))
           (ext-dstip (unwrap (read-u32be buffer 80)))
           (payload-header (unwrap (slice buffer 84 1)))
           (mii-sequence (unwrap (read-u16be buffer 84)))
           (mii-packet-size (unwrap (read-u16be buffer 86)))
           )

      (ok (list
        (cons 'hpi-udp-checksum (list (cons 'raw hpi-udp-checksum) (cons 'formatted (fmt-hex hpi-udp-checksum))))
        (cons 'hpi-sync5 (list (cons 'raw hpi-sync5) (cons 'formatted (fmt-hex hpi-sync5))))
        (cons 'analysis-version (list (cons 'raw analysis-version) (cons 'formatted (number->string analysis-version))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (utf8->string session-id))))
        (cons 'session-id-board-id (list (cons 'raw session-id-board-id) (cons 'formatted (fmt-hex session-id-board-id))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'hpi-resource-id (list (cons 'raw hpi-resource-id) (cons 'formatted (number->string hpi-resource-id))))
        (cons 'hpi-favorite (list (cons 'raw hpi-favorite) (cons 'formatted (number->string hpi-favorite))))
        (cons 'analysis-sub-version (list (cons 'raw analysis-sub-version) (cons 'formatted (number->string analysis-sub-version))))
        (cons 'analysis-direction (list (cons 'raw analysis-direction) (cons 'formatted (fmt-hex analysis-direction))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-hex data))))
        (cons 'pl-offset-type (list (cons 'raw pl-offset-type) (cons 'formatted (number->string pl-offset-type))))
        (cons 'header-ext-len-type (list (cons 'raw header-ext-len-type) (cons 'formatted (number->string header-ext-len-type))))
        (cons 'session-id-session-number (list (cons 'raw session-id-session-number) (cons 'formatted (number->string session-id-session-number))))
        (cons 'hpi-protocol (list (cons 'raw hpi-protocol) (cons 'formatted (number->string hpi-protocol))))
        (cons 'analysis-device (list (cons 'raw analysis-device) (cons 'formatted (number->string analysis-device))))
        (cons 'session-id-reset-counter (list (cons 'raw session-id-reset-counter) (cons 'formatted (number->string session-id-reset-counter))))
        (cons 'analysis-sequence (list (cons 'raw analysis-sequence) (cons 'formatted (number->string analysis-sequence))))
        (cons 'analysis-spare1 (list (cons 'raw analysis-spare1) (cons 'formatted (number->string analysis-spare1))))
        (cons 'session-id-long-session-number (list (cons 'raw session-id-long-session-number) (cons 'formatted (number->string session-id-long-session-number))))
        (cons 'analysis-timestamp (list (cons 'raw analysis-timestamp) (cons 'formatted (number->string analysis-timestamp))))
        (cons 'analysis-spare2 (list (cons 'raw analysis-spare2) (cons 'formatted (number->string analysis-spare2))))
        (cons 'ext-dsp-core (list (cons 'raw ext-dsp-core) (cons 'formatted (number->string ext-dsp-core))))
        (cons 'ext-dsp-channel (list (cons 'raw ext-dsp-channel) (cons 'formatted (number->string ext-dsp-channel))))
        (cons 'ext-pstn-trace-seq-num (list (cons 'raw ext-pstn-trace-seq-num) (cons 'formatted (number->string ext-pstn-trace-seq-num))))
        (cons 'ext-event-id (list (cons 'raw ext-event-id) (cons 'formatted (number->string ext-event-id))))
        (cons 'ext-event-source (list (cons 'raw ext-event-source) (cons 'formatted (number->string ext-event-source))))
        (cons 'ext-srcipv6 (list (cons 'raw ext-srcipv6) (cons 'formatted (fmt-ipv6-address ext-srcipv6))))
        (cons 'ext-c5-control-flags (list (cons 'raw ext-c5-control-flags) (cons 'formatted (fmt-hex ext-c5-control-flags))))
        (cons 'ext-c5-control-favorite (list (cons 'raw ext-c5-control-favorite) (cons 'formatted (if (= ext-c5-control-favorite 0) "Not set" "Set"))))
        (cons 'ext-dstipv6 (list (cons 'raw ext-dstipv6) (cons 'formatted (fmt-ipv6-address ext-dstipv6))))
        (cons 'ext-iptos (list (cons 'raw ext-iptos) (cons 'formatted (number->string ext-iptos))))
        (cons 'ext-srcudp (list (cons 'raw ext-srcudp) (cons 'formatted (fmt-port ext-srcudp))))
        (cons 'ext-dstudp (list (cons 'raw ext-dstudp) (cons 'formatted (fmt-port ext-dstudp))))
        (cons 'ext-srcip (list (cons 'raw ext-srcip) (cons 'formatted (fmt-ipv4 ext-srcip))))
        (cons 'ext-dstip (list (cons 'raw ext-dstip) (cons 'formatted (fmt-ipv4 ext-dstip))))
        (cons 'payload-header (list (cons 'raw payload-header) (cons 'formatted (fmt-bytes payload-header))))
        (cons 'mii-sequence (list (cons 'raw mii-sequence) (cons 'formatted (number->string mii-sequence))))
        (cons 'mii-packet-size (list (cons 'raw mii-packet-size) (cons 'formatted (number->string mii-packet-size))))
        )))

    (catch (e)
      (err (str "ACDR parse error: " e)))))

;; dissect-acdr: parse ACDR from bytevector
;; Returns (ok fields-alist) or (err message)