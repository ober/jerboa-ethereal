;; packet-applemidi.c
;; Routines for dissection of Apple network-midi session establishment.
;; Copyright 2006-2012, Tobias Erichsen <t.erichsen@gmx.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-data.c, README.developer, and various other files.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; Apple network-midi session establishment is a lightweight protocol for
;; providing a simple session establishment for MIDI-data sent in the form
;; of RTP-MIDI (RFC 4695 / 6295).  Peers recognize each other using the
;; Apple Bonjour scheme with the service-name "_apple-midi._udp", establish
;; a connection using AppleMIDI (no official name, just an abbreviation)
;; and then send payload using RTP-MIDI.  The implementation of this
;; dissector is based on the Apple implementation summary from May 6th, 2005
;; and the extension from August 13th, 2010.
;;
;; 2010-11-29
;; - initial version of dissector
;; 2012-02-24
;; - implemented dynamic payloadtype support to automatically punt
;; the decoding to the RTP-MIDI dissector via the RTP dissector
;; - added new bitrate receive limit feature
;;
;; Here are some links:
;;
;; http://www.cs.berkeley.edu/~lazzaro/rtpmidi/
;; https://tools.ietf.org/html/rfc4695
;; https://tools.ietf.org/html/rfc6925
;;

;; jerboa-ethereal/dissectors/applemidi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-applemidi.c
;; RFC 4695

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
(def (dissect-applemidi buffer)
  "applemidi dissector"
  (try
    (let* (
           (protocol-version (unwrap (read-u32be buffer 4)))
           (token (unwrap (read-u32be buffer 8)))
           (name (unwrap (slice buffer 16 1)))
           (count (unwrap (read-u8 buffer 20)))
           (padding (unwrap (read-u24be buffer 21)))
           (timestamp1 (unwrap (read-u64be buffer 24)))
           (timestamp2 (unwrap (read-u64be buffer 32)))
           (timestamp3 (unwrap (read-u64be buffer 40)))
           (sequence-num (unwrap (read-u32be buffer 52)))
           (rtp-sequence-num (unwrap (read-u16be buffer 52)))
           (ssrc (unwrap (read-u32be buffer 56)))
           (rtp-bitrate-limit (unwrap (read-u32be buffer 60)))
           (unknown-data (unwrap (slice buffer 64 1)))
           (signature (unwrap (read-u16be buffer 65)))
           )

      (ok (list
        (cons 'protocol-version (list (cons 'raw protocol-version) (cons 'formatted (number->string protocol-version))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (fmt-hex token))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-hex padding))))
        (cons 'timestamp1 (list (cons 'raw timestamp1) (cons 'formatted (fmt-hex timestamp1))))
        (cons 'timestamp2 (list (cons 'raw timestamp2) (cons 'formatted (fmt-hex timestamp2))))
        (cons 'timestamp3 (list (cons 'raw timestamp3) (cons 'formatted (fmt-hex timestamp3))))
        (cons 'sequence-num (list (cons 'raw sequence-num) (cons 'formatted (fmt-hex sequence-num))))
        (cons 'rtp-sequence-num (list (cons 'raw rtp-sequence-num) (cons 'formatted (number->string rtp-sequence-num))))
        (cons 'ssrc (list (cons 'raw ssrc) (cons 'formatted (fmt-hex ssrc))))
        (cons 'rtp-bitrate-limit (list (cons 'raw rtp-bitrate-limit) (cons 'formatted (number->string rtp-bitrate-limit))))
        (cons 'unknown-data (list (cons 'raw unknown-data) (cons 'formatted (fmt-bytes unknown-data))))
        (cons 'signature (list (cons 'raw signature) (cons 'formatted (fmt-hex signature))))
        )))

    (catch (e)
      (err (str "APPLEMIDI parse error: " e)))))

;; dissect-applemidi: parse APPLEMIDI from bytevector
;; Returns (ok fields-alist) or (err message)