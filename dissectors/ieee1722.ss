;; packet-ieee1722.c
;; Routines for AVTP (Audio Video Transport Protocol) dissection
;; Copyright 2010, Torrey Atcitty <tatcitty@harman.com>
;; Dave Olsen <dave.olsen@harman.com>
;; Levi Pearson <levi.pearson@harman.com>
;;
;; Copyright 2011, Thomas Bottom <tom.bottom@labxtechnologies.com>
;;
;; Copyright 2016, Andreas Leibold <andreas.leibold@harman.com>
;; Dissection for the following 1722 subtypes added:
;; Clock Reference Format (CRF).
;; IEC 61883-4 MPEG-TS data transmission.
;; IEC 61883-6 audio/music data transmission protocol improved.
;; Changes to meet 1722 Draft 15 specification.
;;
;; Copyright 2017, Marouen Ghodhbane <marouen.ghodhbane@nxp.com>
;; Dissection for the 1722 Compressed Video subtype added.
;; CVF Format subtype supported: H264 and MJPEG
;; The dissection meets the 1722-2016 specification.
;;
;; Copyright 2019, Dmitry Linikov <linikov@arrival.com>
;; Dissection for the 1722 Time-Sensitive and Non-Time-Sensitive
;; Control formats added.
;; ACF Message types supported: CAN, CAN_BRIEF, LIN
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; The 1722 Protocol specification can be found at the following:
;; http://grouper.ieee.org/groups/1722/
;;
;;

;; jerboa-ethereal/dissectors/ieee1722.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ieee1722.c

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
(def (dissect-ieee1722 buffer)
  "IEEE 1722 Audio Video Transport Protocol (AVTP)"
  (try
    (let* (
           (acf-msg-length (unwrap (read-u16be buffer 0)))
           (encap-seqnum (unwrap (read-u32be buffer 0)))
           (can-flags (unwrap (read-u8 buffer 0)))
           (can-pad (unwrap (read-u8 buffer 0)))
           (lin-pad (unwrap (read-u8 buffer 0)))
           (lin-mtv (unwrap (read-u8 buffer 0)))
           (lin-bus-id (unwrap (read-u8 buffer 0)))
           (ntscf-data-length (unwrap (read-u16be buffer 1)))
           (tscf-mr (unwrap (read-u8 buffer 1)))
           (tscf-rsv1 (unwrap (read-u8 buffer 1)))
           (tscf-tv (unwrap (read-u8 buffer 1)))
           (can-rsv1 (unwrap (read-u8 buffer 1)))
           (can-bus-id (unwrap (read-u8 buffer 1)))
           (lin-identifier (unwrap (read-u8 buffer 1)))
           (61883-seqnum (unwrap (read-u8 buffer 2)))
           (aaf-seqnum (unwrap (read-u8 buffer 2)))
           (cvf-seqnum (unwrap (read-u8 buffer 2)))
           (crf-seqnum (unwrap (read-u8 buffer 2)))
           (tscf-seqnum (unwrap (read-u8 buffer 2)))
           (can-message-timestamp (unwrap (read-u64be buffer 2)))
           (lin-message-timestamp (unwrap (read-u64be buffer 2)))
           (61883-tufield (unwrap (read-u8 buffer 3)))
           (aaf-tufield (unwrap (read-u8 buffer 3)))
           (cvf-tufield (unwrap (read-u8 buffer 3)))
           (ntscf-seqnum (unwrap (read-u8 buffer 3)))
           (tscf-rsv2 (unwrap (read-u8 buffer 3)))
           (tscf-tu (unwrap (read-u8 buffer 3)))
           (61883-stream-id (unwrap (read-u64be buffer 4)))
           (aaf-stream-id (unwrap (read-u64be buffer 4)))
           (cvf-stream-id (unwrap (read-u64be buffer 4)))
           (crf-stream-id (unwrap (read-u64be buffer 4)))
           (ntscf-stream-id (unwrap (read-u64be buffer 4)))
           (tscf-stream-id (unwrap (read-u64be buffer 4)))
           (can-rsv2 (unwrap (read-u32be buffer 10)))
           (can-identifier (unwrap (read-u32be buffer 10)))
           (lin-padding (unwrap (slice buffer 10 1)))
           (61883-avtp-timestamp (unwrap (read-u32be buffer 12)))
           (aaf-avtp-timestamp (unwrap (read-u32be buffer 12)))
           (cvf-avtp-timestamp (unwrap (read-u32be buffer 12)))
           (tscf-avtp-timestamp (unwrap (read-u32be buffer 12)))
           (can-len (unwrap (read-u8 buffer 14)))
           (can-padding (unwrap (slice buffer 14 1)))
           (61883-gateway-info (unwrap (read-u32be buffer 16)))
           (tscf-rsv3 (unwrap (read-u32be buffer 16)))
           (aaf-channels-per-frame (unwrap (read-u16be buffer 17)))
           (crf-timestamp-interval (unwrap (read-u16be buffer 18)))
           (aaf-bit-depth (unwrap (read-u8 buffer 19)))
           (crf-timestamp-data (unwrap (slice buffer 20 1)))
           (crf-timestamp (unwrap (read-u64be buffer 20)))
           (tscf-data-length (unwrap (read-u16be buffer 20)))
           (61883-channel (unwrap (read-u8 buffer 22)))
           (tscf-rsv4 (unwrap (read-u16be buffer 22)))
           (61883-tcode (unwrap (read-u8 buffer 23)))
           (61883-sy (unwrap (read-u8 buffer 23)))
           (aaf-reserved (unwrap (read-u8 buffer 23)))
           (61883-cip-qi1 (unwrap (read-u8 buffer 24)))
           (61883-cip-sid (unwrap (read-u8 buffer 24)))
           (aaf-data (unwrap (slice buffer 24 1)))
           (aaf-sample (unwrap (slice buffer 24 1)))
           (61883-cip-dbs (unwrap (read-u8 buffer 25)))
           (61883-cip-qpc (unwrap (read-u8 buffer 26)))
           (61883-cip-sph (unwrap (read-u8 buffer 26)))
           (61883-cip-dbc (unwrap (read-u8 buffer 27)))
           (61883-cip-qi2 (unwrap (read-u8 buffer 28)))
           (cvf-h264-timestamp (unwrap (read-u32be buffer 28)))
           (61883-cip-fdf-no-syt (unwrap (read-u24be buffer 32)))
           (61883-cip-fdf-tsf (unwrap (read-u8 buffer 32)))
           (61883-audio-data (unwrap (slice buffer 35 1)))
           (61883-label (unwrap (read-u8 buffer 35)))
           (61883-sample (unwrap (slice buffer 36 3)))
           (61883-video-data (unwrap (slice buffer 39 1)))
           (61883-source-packet-header-timestamp (unwrap (read-u32be buffer 39)))
           )

      (ok (list
        (cons 'acf-msg-length (list (cons 'raw acf-msg-length) (cons 'formatted (number->string acf-msg-length))))
        (cons 'encap-seqnum (list (cons 'raw encap-seqnum) (cons 'formatted (fmt-hex encap-seqnum))))
        (cons 'can-flags (list (cons 'raw can-flags) (cons 'formatted (fmt-hex can-flags))))
        (cons 'can-pad (list (cons 'raw can-pad) (cons 'formatted (number->string can-pad))))
        (cons 'lin-pad (list (cons 'raw lin-pad) (cons 'formatted (number->string lin-pad))))
        (cons 'lin-mtv (list (cons 'raw lin-mtv) (cons 'formatted (number->string lin-mtv))))
        (cons 'lin-bus-id (list (cons 'raw lin-bus-id) (cons 'formatted (number->string lin-bus-id))))
        (cons 'ntscf-data-length (list (cons 'raw ntscf-data-length) (cons 'formatted (number->string ntscf-data-length))))
        (cons 'tscf-mr (list (cons 'raw tscf-mr) (cons 'formatted (fmt-hex tscf-mr))))
        (cons 'tscf-rsv1 (list (cons 'raw tscf-rsv1) (cons 'formatted (fmt-hex tscf-rsv1))))
        (cons 'tscf-tv (list (cons 'raw tscf-tv) (cons 'formatted (fmt-hex tscf-tv))))
        (cons 'can-rsv1 (list (cons 'raw can-rsv1) (cons 'formatted (fmt-hex can-rsv1))))
        (cons 'can-bus-id (list (cons 'raw can-bus-id) (cons 'formatted (number->string can-bus-id))))
        (cons 'lin-identifier (list (cons 'raw lin-identifier) (cons 'formatted (fmt-hex lin-identifier))))
        (cons '61883-seqnum (list (cons 'raw 61883-seqnum) (cons 'formatted (fmt-hex 61883-seqnum))))
        (cons 'aaf-seqnum (list (cons 'raw aaf-seqnum) (cons 'formatted (number->string aaf-seqnum))))
        (cons 'cvf-seqnum (list (cons 'raw cvf-seqnum) (cons 'formatted (number->string cvf-seqnum))))
        (cons 'crf-seqnum (list (cons 'raw crf-seqnum) (cons 'formatted (number->string crf-seqnum))))
        (cons 'tscf-seqnum (list (cons 'raw tscf-seqnum) (cons 'formatted (number->string tscf-seqnum))))
        (cons 'can-message-timestamp (list (cons 'raw can-message-timestamp) (cons 'formatted (fmt-hex can-message-timestamp))))
        (cons 'lin-message-timestamp (list (cons 'raw lin-message-timestamp) (cons 'formatted (fmt-hex lin-message-timestamp))))
        (cons '61883-tufield (list (cons 'raw 61883-tufield) (cons 'formatted (number->string 61883-tufield))))
        (cons 'aaf-tufield (list (cons 'raw aaf-tufield) (cons 'formatted (number->string aaf-tufield))))
        (cons 'cvf-tufield (list (cons 'raw cvf-tufield) (cons 'formatted (number->string cvf-tufield))))
        (cons 'ntscf-seqnum (list (cons 'raw ntscf-seqnum) (cons 'formatted (number->string ntscf-seqnum))))
        (cons 'tscf-rsv2 (list (cons 'raw tscf-rsv2) (cons 'formatted (number->string tscf-rsv2))))
        (cons 'tscf-tu (list (cons 'raw tscf-tu) (cons 'formatted (number->string tscf-tu))))
        (cons '61883-stream-id (list (cons 'raw 61883-stream-id) (cons 'formatted (fmt-hex 61883-stream-id))))
        (cons 'aaf-stream-id (list (cons 'raw aaf-stream-id) (cons 'formatted (fmt-hex aaf-stream-id))))
        (cons 'cvf-stream-id (list (cons 'raw cvf-stream-id) (cons 'formatted (fmt-hex cvf-stream-id))))
        (cons 'crf-stream-id (list (cons 'raw crf-stream-id) (cons 'formatted (fmt-hex crf-stream-id))))
        (cons 'ntscf-stream-id (list (cons 'raw ntscf-stream-id) (cons 'formatted (fmt-hex ntscf-stream-id))))
        (cons 'tscf-stream-id (list (cons 'raw tscf-stream-id) (cons 'formatted (fmt-hex tscf-stream-id))))
        (cons 'can-rsv2 (list (cons 'raw can-rsv2) (cons 'formatted (fmt-hex can-rsv2))))
        (cons 'can-identifier (list (cons 'raw can-identifier) (cons 'formatted (fmt-hex can-identifier))))
        (cons 'lin-padding (list (cons 'raw lin-padding) (cons 'formatted (fmt-bytes lin-padding))))
        (cons '61883-avtp-timestamp (list (cons 'raw 61883-avtp-timestamp) (cons 'formatted (fmt-hex 61883-avtp-timestamp))))
        (cons 'aaf-avtp-timestamp (list (cons 'raw aaf-avtp-timestamp) (cons 'formatted (number->string aaf-avtp-timestamp))))
        (cons 'cvf-avtp-timestamp (list (cons 'raw cvf-avtp-timestamp) (cons 'formatted (number->string cvf-avtp-timestamp))))
        (cons 'tscf-avtp-timestamp (list (cons 'raw tscf-avtp-timestamp) (cons 'formatted (fmt-hex tscf-avtp-timestamp))))
        (cons 'can-len (list (cons 'raw can-len) (cons 'formatted (number->string can-len))))
        (cons 'can-padding (list (cons 'raw can-padding) (cons 'formatted (fmt-bytes can-padding))))
        (cons '61883-gateway-info (list (cons 'raw 61883-gateway-info) (cons 'formatted (fmt-hex 61883-gateway-info))))
        (cons 'tscf-rsv3 (list (cons 'raw tscf-rsv3) (cons 'formatted (fmt-hex tscf-rsv3))))
        (cons 'aaf-channels-per-frame (list (cons 'raw aaf-channels-per-frame) (cons 'formatted (number->string aaf-channels-per-frame))))
        (cons 'crf-timestamp-interval (list (cons 'raw crf-timestamp-interval) (cons 'formatted (number->string crf-timestamp-interval))))
        (cons 'aaf-bit-depth (list (cons 'raw aaf-bit-depth) (cons 'formatted (number->string aaf-bit-depth))))
        (cons 'crf-timestamp-data (list (cons 'raw crf-timestamp-data) (cons 'formatted (fmt-bytes crf-timestamp-data))))
        (cons 'crf-timestamp (list (cons 'raw crf-timestamp) (cons 'formatted (fmt-hex crf-timestamp))))
        (cons 'tscf-data-length (list (cons 'raw tscf-data-length) (cons 'formatted (number->string tscf-data-length))))
        (cons '61883-channel (list (cons 'raw 61883-channel) (cons 'formatted (number->string 61883-channel))))
        (cons 'tscf-rsv4 (list (cons 'raw tscf-rsv4) (cons 'formatted (fmt-hex tscf-rsv4))))
        (cons '61883-tcode (list (cons 'raw 61883-tcode) (cons 'formatted (fmt-hex 61883-tcode))))
        (cons '61883-sy (list (cons 'raw 61883-sy) (cons 'formatted (fmt-hex 61883-sy))))
        (cons 'aaf-reserved (list (cons 'raw aaf-reserved) (cons 'formatted (fmt-hex aaf-reserved))))
        (cons '61883-cip-qi1 (list (cons 'raw 61883-cip-qi1) (cons 'formatted (fmt-hex 61883-cip-qi1))))
        (cons '61883-cip-sid (list (cons 'raw 61883-cip-sid) (cons 'formatted (number->string 61883-cip-sid))))
        (cons 'aaf-data (list (cons 'raw aaf-data) (cons 'formatted (fmt-bytes aaf-data))))
        (cons 'aaf-sample (list (cons 'raw aaf-sample) (cons 'formatted (fmt-bytes aaf-sample))))
        (cons '61883-cip-dbs (list (cons 'raw 61883-cip-dbs) (cons 'formatted (fmt-hex 61883-cip-dbs))))
        (cons '61883-cip-qpc (list (cons 'raw 61883-cip-qpc) (cons 'formatted (fmt-hex 61883-cip-qpc))))
        (cons '61883-cip-sph (list (cons 'raw 61883-cip-sph) (cons 'formatted (number->string 61883-cip-sph))))
        (cons '61883-cip-dbc (list (cons 'raw 61883-cip-dbc) (cons 'formatted (fmt-hex 61883-cip-dbc))))
        (cons '61883-cip-qi2 (list (cons 'raw 61883-cip-qi2) (cons 'formatted (fmt-hex 61883-cip-qi2))))
        (cons 'cvf-h264-timestamp (list (cons 'raw cvf-h264-timestamp) (cons 'formatted (number->string cvf-h264-timestamp))))
        (cons '61883-cip-fdf-no-syt (list (cons 'raw 61883-cip-fdf-no-syt) (cons 'formatted (fmt-hex 61883-cip-fdf-no-syt))))
        (cons '61883-cip-fdf-tsf (list (cons 'raw 61883-cip-fdf-tsf) (cons 'formatted (number->string 61883-cip-fdf-tsf))))
        (cons '61883-audio-data (list (cons 'raw 61883-audio-data) (cons 'formatted (fmt-bytes 61883-audio-data))))
        (cons '61883-label (list (cons 'raw 61883-label) (cons 'formatted (fmt-hex 61883-label))))
        (cons '61883-sample (list (cons 'raw 61883-sample) (cons 'formatted (fmt-bytes 61883-sample))))
        (cons '61883-video-data (list (cons 'raw 61883-video-data) (cons 'formatted (fmt-bytes 61883-video-data))))
        (cons '61883-source-packet-header-timestamp (list (cons 'raw 61883-source-packet-header-timestamp) (cons 'formatted (fmt-hex 61883-source-packet-header-timestamp))))
        )))

    (catch (e)
      (err (str "IEEE1722 parse error: " e)))))

;; dissect-ieee1722: parse IEEE1722 from bytevector
;; Returns (ok fields-alist) or (err message)