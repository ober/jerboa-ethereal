;; packet-rtmpt.c
;; Routines for Real Time Messaging Protocol packet dissection
;; metatech <metatech@flashmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rtmpt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rtmpt.c

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
(def (dissect-rtmpt buffer)
  "Real Time Messaging Protocol"
  (try
    (let* (
           (handshake-c2 (unwrap (slice buffer 0 1536)))
           (handshake-s0 (unwrap (slice buffer 0 1)))
           (handshake-c0 (unwrap (slice buffer 0 1)))
           (boolean (unwrap (read-u8 buffer 0)))
           (header-format (unwrap (read-u8 buffer 0)))
           (header-csid (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u16be buffer 0)))
           (handshake-s1 (unwrap (slice buffer 1 1536)))
           (handshake-c1 (unwrap (slice buffer 1 1536)))
           (scm-chunksize (unwrap (read-u32be buffer 2)))
           (scm-csid (unwrap (read-u32be buffer 2)))
           (scm-seq (unwrap (read-u32be buffer 2)))
           (scm-was (unwrap (read-u32be buffer 2)))
           (stringlength (unwrap (read-u32be buffer 2)))
           (header-count (unwrap (read-u16be buffer 2)))
           (string (unwrap (slice buffer 4 1)))
           (header-must-understand (unwrap (read-u8 buffer 6)))
           (audio-is-ex-header (unwrap (read-u8 buffer 7)))
           (header-length (unwrap (read-u32be buffer 7)))
           (audio-multitrack-control (unwrap (read-u8 buffer 8)))
           (message-count (unwrap (read-u16be buffer 11)))
           (audio-track-id (unwrap (read-u8 buffer 17)))
           (message-length (unwrap (read-u32be buffer 17)))
           (audio-fourcc (unwrap (slice buffer 18 4)))
           (audio-track-length (unwrap (read-u24be buffer 22)))
           (audio-data (unwrap (slice buffer 25 1)))
           (audio-control (unwrap (read-u8 buffer 25)))
           (video-is-ex-header (unwrap (read-u8 buffer 25)))
           (video-multitrack-control (unwrap (read-u8 buffer 27)))
           (video-track-id (unwrap (read-u8 buffer 36)))
           (video-fourcc (unwrap (slice buffer 36 4)))
           (video-track-length (unwrap (read-u24be buffer 41)))
           (video-control (unwrap (read-u8 buffer 44)))
           (video-data (unwrap (slice buffer 45 1)))
           (tag-datasize (unwrap (read-u24be buffer 45)))
           (tag-timestamp (unwrap (read-u24be buffer 45)))
           (tag-ets (unwrap (read-u8 buffer 45)))
           (tag-streamid (unwrap (read-u24be buffer 45)))
           (handshake-s2 (unwrap (slice buffer 1537 1536)))
           )

      (ok (list
        (cons 'handshake-c2 (list (cons 'raw handshake-c2) (cons 'formatted (fmt-bytes handshake-c2))))
        (cons 'handshake-s0 (list (cons 'raw handshake-s0) (cons 'formatted (fmt-bytes handshake-s0))))
        (cons 'handshake-c0 (list (cons 'raw handshake-c0) (cons 'formatted (fmt-bytes handshake-c0))))
        (cons 'boolean (list (cons 'raw boolean) (cons 'formatted (number->string boolean))))
        (cons 'header-format (list (cons 'raw header-format) (cons 'formatted (number->string header-format))))
        (cons 'header-csid (list (cons 'raw header-csid) (cons 'formatted (number->string header-csid))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'handshake-s1 (list (cons 'raw handshake-s1) (cons 'formatted (fmt-bytes handshake-s1))))
        (cons 'handshake-c1 (list (cons 'raw handshake-c1) (cons 'formatted (fmt-bytes handshake-c1))))
        (cons 'scm-chunksize (list (cons 'raw scm-chunksize) (cons 'formatted (number->string scm-chunksize))))
        (cons 'scm-csid (list (cons 'raw scm-csid) (cons 'formatted (number->string scm-csid))))
        (cons 'scm-seq (list (cons 'raw scm-seq) (cons 'formatted (number->string scm-seq))))
        (cons 'scm-was (list (cons 'raw scm-was) (cons 'formatted (number->string scm-was))))
        (cons 'stringlength (list (cons 'raw stringlength) (cons 'formatted (number->string stringlength))))
        (cons 'header-count (list (cons 'raw header-count) (cons 'formatted (number->string header-count))))
        (cons 'string (list (cons 'raw string) (cons 'formatted (utf8->string string))))
        (cons 'header-must-understand (list (cons 'raw header-must-understand) (cons 'formatted (number->string header-must-understand))))
        (cons 'audio-is-ex-header (list (cons 'raw audio-is-ex-header) (cons 'formatted (number->string audio-is-ex-header))))
        (cons 'header-length (list (cons 'raw header-length) (cons 'formatted (number->string header-length))))
        (cons 'audio-multitrack-control (list (cons 'raw audio-multitrack-control) (cons 'formatted (fmt-hex audio-multitrack-control))))
        (cons 'message-count (list (cons 'raw message-count) (cons 'formatted (number->string message-count))))
        (cons 'audio-track-id (list (cons 'raw audio-track-id) (cons 'formatted (number->string audio-track-id))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'audio-fourcc (list (cons 'raw audio-fourcc) (cons 'formatted (utf8->string audio-fourcc))))
        (cons 'audio-track-length (list (cons 'raw audio-track-length) (cons 'formatted (number->string audio-track-length))))
        (cons 'audio-data (list (cons 'raw audio-data) (cons 'formatted (fmt-bytes audio-data))))
        (cons 'audio-control (list (cons 'raw audio-control) (cons 'formatted (fmt-hex audio-control))))
        (cons 'video-is-ex-header (list (cons 'raw video-is-ex-header) (cons 'formatted (number->string video-is-ex-header))))
        (cons 'video-multitrack-control (list (cons 'raw video-multitrack-control) (cons 'formatted (fmt-hex video-multitrack-control))))
        (cons 'video-track-id (list (cons 'raw video-track-id) (cons 'formatted (number->string video-track-id))))
        (cons 'video-fourcc (list (cons 'raw video-fourcc) (cons 'formatted (utf8->string video-fourcc))))
        (cons 'video-track-length (list (cons 'raw video-track-length) (cons 'formatted (number->string video-track-length))))
        (cons 'video-control (list (cons 'raw video-control) (cons 'formatted (fmt-hex video-control))))
        (cons 'video-data (list (cons 'raw video-data) (cons 'formatted (fmt-bytes video-data))))
        (cons 'tag-datasize (list (cons 'raw tag-datasize) (cons 'formatted (number->string tag-datasize))))
        (cons 'tag-timestamp (list (cons 'raw tag-timestamp) (cons 'formatted (number->string tag-timestamp))))
        (cons 'tag-ets (list (cons 'raw tag-ets) (cons 'formatted (number->string tag-ets))))
        (cons 'tag-streamid (list (cons 'raw tag-streamid) (cons 'formatted (number->string tag-streamid))))
        (cons 'handshake-s2 (list (cons 'raw handshake-s2) (cons 'formatted (fmt-bytes handshake-s2))))
        )))

    (catch (e)
      (err (str "RTMPT parse error: " e)))))

;; dissect-rtmpt: parse RTMPT from bytevector
;; Returns (ok fields-alist) or (err message)