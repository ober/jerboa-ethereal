;; packet-rtp.c
;;
;; Routines for RTP dissection
;; RTP = Real time Transport Protocol
;;
;; Copyright 2000, Philips Electronics N.V.
;; Written by Andreas Sikkema <h323@ramdyne.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rtp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rtp.c
;; RFC 3550

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
(def (dissect-rtp buffer)
  "PacketCable Call Content Connection"
  (try
    (let* (
           (ccc-id (unwrap (read-u32be buffer 0)))
           (setup-method (unwrap (slice buffer 0 1)))
           (setup-frame (unwrap (read-u32be buffer 0)))
           (setup (unwrap (slice buffer 0 1)))
           (rfc2198-follow (unwrap (read-u8 buffer 0)))
           (header-len (unwrap (read-u16be buffer 0)))
           (ext-seq-nr (unwrap (read-u32be buffer 0)))
           (rfc2198-tm-off (unwrap (read-u16be buffer 1)))
           (rfc2198-bl-len (unwrap (read-u16be buffer 1)))
           (ext-timestamp (unwrap (read-u64be buffer 2)))
           (padding-data (unwrap (slice buffer 30 1)))
           (padding-count (unwrap (read-u8 buffer 30)))
           (marker (unwrap (read-u8 buffer 30)))
           (payload-type (unwrap (read-u8 buffer 30)))
           (seq-nr (unwrap (read-u16be buffer 30)))
           (timestamp (unwrap (read-u32be buffer 32)))
           (ssrc (unwrap (read-u32be buffer 36)))
           (csrc-item (unwrap (read-u32be buffer 52)))
           (length (unwrap (read-u16be buffer 58)))
           (hdr-ext (unwrap (read-u32be buffer 60)))
           )

      (ok (list
        (cons 'ccc-id (list (cons 'raw ccc-id) (cons 'formatted (number->string ccc-id))))
        (cons 'setup-method (list (cons 'raw setup-method) (cons 'formatted (utf8->string setup-method))))
        (cons 'setup-frame (list (cons 'raw setup-frame) (cons 'formatted (number->string setup-frame))))
        (cons 'setup (list (cons 'raw setup) (cons 'formatted (utf8->string setup))))
        (cons 'rfc2198-follow (list (cons 'raw rfc2198-follow) (cons 'formatted (if (= rfc2198-follow 0) "False" "True"))))
        (cons 'header-len (list (cons 'raw header-len) (cons 'formatted (number->string header-len))))
        (cons 'ext-seq-nr (list (cons 'raw ext-seq-nr) (cons 'formatted (number->string ext-seq-nr))))
        (cons 'rfc2198-tm-off (list (cons 'raw rfc2198-tm-off) (cons 'formatted (number->string rfc2198-tm-off))))
        (cons 'rfc2198-bl-len (list (cons 'raw rfc2198-bl-len) (cons 'formatted (number->string rfc2198-bl-len))))
        (cons 'ext-timestamp (list (cons 'raw ext-timestamp) (cons 'formatted (number->string ext-timestamp))))
        (cons 'padding-data (list (cons 'raw padding-data) (cons 'formatted (fmt-bytes padding-data))))
        (cons 'padding-count (list (cons 'raw padding-count) (cons 'formatted (number->string padding-count))))
        (cons 'marker (list (cons 'raw marker) (cons 'formatted (number->string marker))))
        (cons 'payload-type (list (cons 'raw payload-type) (cons 'formatted (number->string payload-type))))
        (cons 'seq-nr (list (cons 'raw seq-nr) (cons 'formatted (number->string seq-nr))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'ssrc (list (cons 'raw ssrc) (cons 'formatted (fmt-hex ssrc))))
        (cons 'csrc-item (list (cons 'raw csrc-item) (cons 'formatted (fmt-hex csrc-item))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'hdr-ext (list (cons 'raw hdr-ext) (cons 'formatted (fmt-hex hdr-ext))))
        )))

    (catch (e)
      (err (str "RTP parse error: " e)))))

;; dissect-rtp: parse RTP from bytevector
;; Returns (ok fields-alist) or (err message)