;; packet-peekremote.c
;;
;; Routines for the disassembly of packets sent from Cisco WLAN
;; Controllers, possibly other Cisco access points, and possibly
;; other devices such as Aruba access points.  See
;;
;; https://web.archive.org/web/20130117041444/http://www.wildpackets.com/elements/omnipeek/OmniPeek_UserGuide.pdf
;;
;; which speaks of Aruba access points supporting remote capture and
;; defaulting to port 5000 for this, and also speaks of Cisco access
;; points supporting remote capture without any reference to a port
;; number.  The two types of remote capture are described separately;
;; there's no indication of whether they use the same protocol for
;; streaming packets but perhaps other protocols for, for example,
;; discovery and setup, or whether they use different protocols
;; for streaming packets.
;;
;; A later manual at
;;
;; https://community.liveaction.com/wp-content/uploads/2020/02/Omnipeek-UserGuide-2-20.pdf
;;
;; speaks of Aruba and Cisco access points together, mentioning port 5000.
;;
;; Apparently Aruba supports several protocols, including Peek remote.
;; See the packet-aruba-erm dissector.
;;
;; Tested with frames captured from a Cisco WCS.
;;
;; Copyright 2007 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/peekremote.ss
;; Auto-generated from wireshark/epan/dissectors/packet-peekremote.c

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
(def (dissect-peekremote buffer)
  "AiroPeek/OmniPeek encapsulated IEEE 802.11"
  (try
    (let* (
           (extflags (unwrap (read-u32be buffer 0)))
           (extflags-20mhz-lower (unwrap (read-u8 buffer 0)))
           (extflags-20mhz-upper (unwrap (read-u8 buffer 0)))
           (extflags-40mhz (unwrap (read-u8 buffer 0)))
           (extflags-half-gi (unwrap (read-u8 buffer 0)))
           (extflags-full-gi (unwrap (read-u8 buffer 0)))
           (extflags-ampdu (unwrap (read-u8 buffer 0)))
           (extflags-amsdu (unwrap (read-u8 buffer 0)))
           (extflags-11ac (unwrap (read-u8 buffer 0)))
           (extflags-future-use (unwrap (read-u8 buffer 0)))
           (extflags-80mhz (unwrap (read-u8 buffer 0)))
           (extflags-shortpreamble (unwrap (read-u8 buffer 0)))
           (extflags-heflag (unwrap (read-u8 buffer 0)))
           (extflags-160mhz (unwrap (read-u8 buffer 0)))
           (extflags-ehtflag (unwrap (read-u8 buffer 0)))
           (extflags-320mhz (unwrap (read-u8 buffer 0)))
           (extflags-quarter-gi (unwrap (read-u8 buffer 0)))
           (extflags-reserved (unwrap (read-u32be buffer 0)))
           (flags (unwrap (read-u8 buffer 0)))
           (flags-control-frame (unwrap (read-u8 buffer 0)))
           (flags-crc-error (unwrap (read-u8 buffer 0)))
           (flags-frame-error (unwrap (read-u8 buffer 0)))
           (flags-6ghz-band-valid (unwrap (read-u8 buffer 0)))
           (flags-6ghz (unwrap (read-u8 buffer 0)))
           (flags-reserved (unwrap (read-u8 buffer 0)))
           (status (unwrap (read-u8 buffer 0)))
           (status-protected (unwrap (read-u8 buffer 0)))
           (status-with-decrypt-error (unwrap (read-u8 buffer 0)))
           (status-with-short-preamble (unwrap (read-u8 buffer 0)))
           (status-reserved (unwrap (read-u8 buffer 0)))
           (magic-number (unwrap (read-u32be buffer 0)))
           (header-version (unwrap (read-u8 buffer 4)))
           (header-size (unwrap (read-u32be buffer 5)))
           (channel (unwrap (read-u16be buffer 15)))
           (speed (unwrap (read-u8 buffer 16)))
           (frequency (unwrap (read-u32be buffer 17)))
           (band (unwrap (read-u32be buffer 21)))
           (signal-percent (unwrap (read-u8 buffer 25)))
           (noise-percent (unwrap (read-u8 buffer 26)))
           (signal-dbm (unwrap (read-u8 buffer 27)))
           (noise-dbm (unwrap (read-u8 buffer 28)))
           (signal-1-dbm (unwrap (read-u8 buffer 29)))
           (signal-2-dbm (unwrap (read-u8 buffer 30)))
           (signal-3-dbm (unwrap (read-u8 buffer 31)))
           (signal-4-dbm (unwrap (read-u8 buffer 32)))
           (noise-1-dbm (unwrap (read-u8 buffer 33)))
           (noise-2-dbm (unwrap (read-u8 buffer 34)))
           (noise-3-dbm (unwrap (read-u8 buffer 35)))
           (noise-4-dbm (unwrap (read-u8 buffer 36)))
           (packetlength (unwrap (read-u16be buffer 37)))
           (slicelength (unwrap (read-u16be buffer 39)))
           (timestamp (unwrap (read-u64be buffer 41)))
           )

      (ok (list
        (cons 'extflags (list (cons 'raw extflags) (cons 'formatted (fmt-hex extflags))))
        (cons 'extflags-20mhz-lower (list (cons 'raw extflags-20mhz-lower) (cons 'formatted (if (= extflags-20mhz-lower 0) "False" "True"))))
        (cons 'extflags-20mhz-upper (list (cons 'raw extflags-20mhz-upper) (cons 'formatted (if (= extflags-20mhz-upper 0) "False" "True"))))
        (cons 'extflags-40mhz (list (cons 'raw extflags-40mhz) (cons 'formatted (if (= extflags-40mhz 0) "False" "True"))))
        (cons 'extflags-half-gi (list (cons 'raw extflags-half-gi) (cons 'formatted (if (= extflags-half-gi 0) "False" "True"))))
        (cons 'extflags-full-gi (list (cons 'raw extflags-full-gi) (cons 'formatted (if (= extflags-full-gi 0) "False" "True"))))
        (cons 'extflags-ampdu (list (cons 'raw extflags-ampdu) (cons 'formatted (if (= extflags-ampdu 0) "False" "True"))))
        (cons 'extflags-amsdu (list (cons 'raw extflags-amsdu) (cons 'formatted (if (= extflags-amsdu 0) "False" "True"))))
        (cons 'extflags-11ac (list (cons 'raw extflags-11ac) (cons 'formatted (if (= extflags-11ac 0) "False" "True"))))
        (cons 'extflags-future-use (list (cons 'raw extflags-future-use) (cons 'formatted (if (= extflags-future-use 0) "False" "True"))))
        (cons 'extflags-80mhz (list (cons 'raw extflags-80mhz) (cons 'formatted (if (= extflags-80mhz 0) "False" "True"))))
        (cons 'extflags-shortpreamble (list (cons 'raw extflags-shortpreamble) (cons 'formatted (if (= extflags-shortpreamble 0) "False" "True"))))
        (cons 'extflags-heflag (list (cons 'raw extflags-heflag) (cons 'formatted (if (= extflags-heflag 0) "False" "True"))))
        (cons 'extflags-160mhz (list (cons 'raw extflags-160mhz) (cons 'formatted (if (= extflags-160mhz 0) "False" "True"))))
        (cons 'extflags-ehtflag (list (cons 'raw extflags-ehtflag) (cons 'formatted (if (= extflags-ehtflag 0) "False" "True"))))
        (cons 'extflags-320mhz (list (cons 'raw extflags-320mhz) (cons 'formatted (if (= extflags-320mhz 0) "False" "True"))))
        (cons 'extflags-quarter-gi (list (cons 'raw extflags-quarter-gi) (cons 'formatted (if (= extflags-quarter-gi 0) "False" "True"))))
        (cons 'extflags-reserved (list (cons 'raw extflags-reserved) (cons 'formatted (fmt-hex extflags-reserved))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-control-frame (list (cons 'raw flags-control-frame) (cons 'formatted (if (= flags-control-frame 0) "False" "True"))))
        (cons 'flags-crc-error (list (cons 'raw flags-crc-error) (cons 'formatted (if (= flags-crc-error 0) "False" "True"))))
        (cons 'flags-frame-error (list (cons 'raw flags-frame-error) (cons 'formatted (if (= flags-frame-error 0) "False" "True"))))
        (cons 'flags-6ghz-band-valid (list (cons 'raw flags-6ghz-band-valid) (cons 'formatted (if (= flags-6ghz-band-valid 0) "False" "True"))))
        (cons 'flags-6ghz (list (cons 'raw flags-6ghz) (cons 'formatted (if (= flags-6ghz 0) "False" "True"))))
        (cons 'flags-reserved (list (cons 'raw flags-reserved) (cons 'formatted (fmt-hex flags-reserved))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (fmt-hex status))))
        (cons 'status-protected (list (cons 'raw status-protected) (cons 'formatted (if (= status-protected 0) "False" "True"))))
        (cons 'status-with-decrypt-error (list (cons 'raw status-with-decrypt-error) (cons 'formatted (if (= status-with-decrypt-error 0) "False" "True"))))
        (cons 'status-with-short-preamble (list (cons 'raw status-with-short-preamble) (cons 'formatted (if (= status-with-short-preamble 0) "False" "True"))))
        (cons 'status-reserved (list (cons 'raw status-reserved) (cons 'formatted (fmt-hex status-reserved))))
        (cons 'magic-number (list (cons 'raw magic-number) (cons 'formatted (fmt-hex magic-number))))
        (cons 'header-version (list (cons 'raw header-version) (cons 'formatted (number->string header-version))))
        (cons 'header-size (list (cons 'raw header-size) (cons 'formatted (number->string header-size))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (number->string channel))))
        (cons 'speed (list (cons 'raw speed) (cons 'formatted (number->string speed))))
        (cons 'frequency (list (cons 'raw frequency) (cons 'formatted (number->string frequency))))
        (cons 'band (list (cons 'raw band) (cons 'formatted (number->string band))))
        (cons 'signal-percent (list (cons 'raw signal-percent) (cons 'formatted (number->string signal-percent))))
        (cons 'noise-percent (list (cons 'raw noise-percent) (cons 'formatted (number->string noise-percent))))
        (cons 'signal-dbm (list (cons 'raw signal-dbm) (cons 'formatted (number->string signal-dbm))))
        (cons 'noise-dbm (list (cons 'raw noise-dbm) (cons 'formatted (number->string noise-dbm))))
        (cons 'signal-1-dbm (list (cons 'raw signal-1-dbm) (cons 'formatted (number->string signal-1-dbm))))
        (cons 'signal-2-dbm (list (cons 'raw signal-2-dbm) (cons 'formatted (number->string signal-2-dbm))))
        (cons 'signal-3-dbm (list (cons 'raw signal-3-dbm) (cons 'formatted (number->string signal-3-dbm))))
        (cons 'signal-4-dbm (list (cons 'raw signal-4-dbm) (cons 'formatted (number->string signal-4-dbm))))
        (cons 'noise-1-dbm (list (cons 'raw noise-1-dbm) (cons 'formatted (number->string noise-1-dbm))))
        (cons 'noise-2-dbm (list (cons 'raw noise-2-dbm) (cons 'formatted (number->string noise-2-dbm))))
        (cons 'noise-3-dbm (list (cons 'raw noise-3-dbm) (cons 'formatted (number->string noise-3-dbm))))
        (cons 'noise-4-dbm (list (cons 'raw noise-4-dbm) (cons 'formatted (number->string noise-4-dbm))))
        (cons 'packetlength (list (cons 'raw packetlength) (cons 'formatted (number->string packetlength))))
        (cons 'slicelength (list (cons 'raw slicelength) (cons 'formatted (number->string slicelength))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        )))

    (catch (e)
      (err (str "PEEKREMOTE parse error: " e)))))

;; dissect-peekremote: parse PEEKREMOTE from bytevector
;; Returns (ok fields-alist) or (err message)