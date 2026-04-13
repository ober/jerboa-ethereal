;;
;; packet-iax2.c
;;
;; Routines for IAX2 packet disassembly
;; By Alastair Maw <asterisk@almaw.com>
;; Copyright 2003 Alastair Maw
;;
;; IAX2 is a VoIP protocol for the open source PBX Asterisk. Please see
;; http://www.asterisk.org for more information; see RFC 5456 for the
;; protocol.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/iax2.ss
;; Auto-generated from wireshark/epan/dissectors/packet-iax2.c
;; RFC 5456

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
(def (dissect-iax2 buffer)
  "Inter-Asterisk eXchange v2"
  (try
    (let* (
           (callno (unwrap (read-u32be buffer 0)))
           (scallno (unwrap (read-u16be buffer 6)))
           (length (unwrap (read-u8 buffer 6)))
           (version (unwrap (read-u8 buffer 6)))
           (IE-APPARENTADDR-SINFAMILY (unwrap (read-u16be buffer 6)))
           (IE-APPARENTADDR-SINPORT (unwrap (read-u16be buffer 6)))
           (IE-APPARENTADDR-SINADDR (unwrap (read-u32be buffer 6)))
           (IE-UNKNOWN-BYTE (unwrap (read-u8 buffer 6)))
           (IE-UNKNOWN-I16 (unwrap (read-u16be buffer 6)))
           (IE-UNKNOWN-I32 (unwrap (read-u32be buffer 6)))
           (IE-UNKNOWN-BYTES (unwrap (slice buffer 6 1)))
           (dcallno (unwrap (read-u16be buffer 6)))
           (retransmission (unwrap (read-u8 buffer 6)))
           (ts (unwrap (read-u32be buffer 6)))
           (oseqno (unwrap (read-u16be buffer 6)))
           (iseqno (unwrap (read-u16be buffer 6)))
           (dtmf-csub (unwrap (slice buffer 6 1)))
           (voice-csub (unwrap (read-u8 buffer 26)))
           (video-csub (unwrap (read-u8 buffer 36)))
           (marker (unwrap (read-u8 buffer 36)))
           (text-text (unwrap (slice buffer 66 1)))
           (html-url (unwrap (slice buffer 76 1)))
           (csub (unwrap (read-u8 buffer 76)))
           (minividts (unwrap (read-u16be buffer 86)))
           (minividmarker (unwrap (read-u16be buffer 86)))
           (minits (unwrap (read-u16be buffer 88)))
           (trunk-call-ts (unwrap (read-u16be buffer 90)))
           (trunk-call-scallno (unwrap (read-u16be buffer 96)))
           (trunk-call-len (unwrap (read-u16be buffer 96)))
           (trunk-call-data (unwrap (slice buffer 96 1)))
           (trunk-metacmd (unwrap (read-u8 buffer 100)))
           (trunk-cmddata (unwrap (read-u8 buffer 100)))
           (trunk-cmddata-ts (unwrap (read-u8 buffer 100)))
           (trunk-ts (unwrap (read-u32be buffer 100)))
           )

      (ok (list
        (cons 'callno (list (cons 'raw callno) (cons 'formatted (number->string callno))))
        (cons 'scallno (list (cons 'raw scallno) (cons 'formatted (number->string scallno))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'IE-APPARENTADDR-SINFAMILY (list (cons 'raw IE-APPARENTADDR-SINFAMILY) (cons 'formatted (number->string IE-APPARENTADDR-SINFAMILY))))
        (cons 'IE-APPARENTADDR-SINPORT (list (cons 'raw IE-APPARENTADDR-SINPORT) (cons 'formatted (number->string IE-APPARENTADDR-SINPORT))))
        (cons 'IE-APPARENTADDR-SINADDR (list (cons 'raw IE-APPARENTADDR-SINADDR) (cons 'formatted (fmt-ipv4 IE-APPARENTADDR-SINADDR))))
        (cons 'IE-UNKNOWN-BYTE (list (cons 'raw IE-UNKNOWN-BYTE) (cons 'formatted (fmt-hex IE-UNKNOWN-BYTE))))
        (cons 'IE-UNKNOWN-I16 (list (cons 'raw IE-UNKNOWN-I16) (cons 'formatted (fmt-hex IE-UNKNOWN-I16))))
        (cons 'IE-UNKNOWN-I32 (list (cons 'raw IE-UNKNOWN-I32) (cons 'formatted (fmt-hex IE-UNKNOWN-I32))))
        (cons 'IE-UNKNOWN-BYTES (list (cons 'raw IE-UNKNOWN-BYTES) (cons 'formatted (utf8->string IE-UNKNOWN-BYTES))))
        (cons 'dcallno (list (cons 'raw dcallno) (cons 'formatted (number->string dcallno))))
        (cons 'retransmission (list (cons 'raw retransmission) (cons 'formatted (number->string retransmission))))
        (cons 'ts (list (cons 'raw ts) (cons 'formatted (number->string ts))))
        (cons 'oseqno (list (cons 'raw oseqno) (cons 'formatted (number->string oseqno))))
        (cons 'iseqno (list (cons 'raw iseqno) (cons 'formatted (number->string iseqno))))
        (cons 'dtmf-csub (list (cons 'raw dtmf-csub) (cons 'formatted (utf8->string dtmf-csub))))
        (cons 'voice-csub (list (cons 'raw voice-csub) (cons 'formatted (number->string voice-csub))))
        (cons 'video-csub (list (cons 'raw video-csub) (cons 'formatted (number->string video-csub))))
        (cons 'marker (list (cons 'raw marker) (cons 'formatted (number->string marker))))
        (cons 'text-text (list (cons 'raw text-text) (cons 'formatted (utf8->string text-text))))
        (cons 'html-url (list (cons 'raw html-url) (cons 'formatted (utf8->string html-url))))
        (cons 'csub (list (cons 'raw csub) (cons 'formatted (number->string csub))))
        (cons 'minividts (list (cons 'raw minividts) (cons 'formatted (number->string minividts))))
        (cons 'minividmarker (list (cons 'raw minividmarker) (cons 'formatted (number->string minividmarker))))
        (cons 'minits (list (cons 'raw minits) (cons 'formatted (number->string minits))))
        (cons 'trunk-call-ts (list (cons 'raw trunk-call-ts) (cons 'formatted (number->string trunk-call-ts))))
        (cons 'trunk-call-scallno (list (cons 'raw trunk-call-scallno) (cons 'formatted (number->string trunk-call-scallno))))
        (cons 'trunk-call-len (list (cons 'raw trunk-call-len) (cons 'formatted (number->string trunk-call-len))))
        (cons 'trunk-call-data (list (cons 'raw trunk-call-data) (cons 'formatted (fmt-bytes trunk-call-data))))
        (cons 'trunk-metacmd (list (cons 'raw trunk-metacmd) (cons 'formatted (number->string trunk-metacmd))))
        (cons 'trunk-cmddata (list (cons 'raw trunk-cmddata) (cons 'formatted (fmt-hex trunk-cmddata))))
        (cons 'trunk-cmddata-ts (list (cons 'raw trunk-cmddata-ts) (cons 'formatted (number->string trunk-cmddata-ts))))
        (cons 'trunk-ts (list (cons 'raw trunk-ts) (cons 'formatted (number->string trunk-ts))))
        )))

    (catch (e)
      (err (str "IAX2 parse error: " e)))))

;; dissect-iax2: parse IAX2 from bytevector
;; Returns (ok fields-alist) or (err message)