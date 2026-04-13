;; packet-rttrp.c
;; Routines for RTTrP packet disassembly
;;
;; Copyright (c) 2025 by Matt Morris <mattm.dev.1[AT]gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; Specification:
;; https://rttrp.github.io/RTTrP-Wiki/index.html
;; https://rttrp.github.io/RTTrP-Wiki/RTTrPM.html
;; https://rttrp.github.io/RTTrP-Wiki/RTTrPL.html
;; https://rttrp.github.io/RTTrP-Wiki/BlackTrax.html
;;
;; Old Zone Method:
;; https://github.com/RTTrP/RTTrP-Wiki/commit/2ddb420fa3e23e2fb7f19b51702a835026b32cf5
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rttrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rttrp.c

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
(def (dissect-rttrp buffer)
  "Real-Time Tracking Protocol"
  (try
    (let* (
           (zone-names-delimited-length (unwrap (read-u16be buffer 3)))
           (header-version (unwrap (read-u16be buffer 4)))
           (zone-count (unwrap (read-u8 buffer 5)))
           (zone-size (unwrap (read-u16be buffer 6)))
           (packet-id (unwrap (read-u32be buffer 6)))
           (zone-name-length (unwrap (read-u8 buffer 7)))
           (zone-name (unwrap (slice buffer 8 1)))
           (orientation-qx (unwrap (read-u64be buffer 10)))
           (packet-size (unwrap (read-u16be buffer 11)))
           (packet-context (unwrap (read-u32be buffer 13)))
           (packet-module-count (unwrap (read-u8 buffer 17)))
           (orientation-qy (unwrap (read-u64be buffer 18)))
           (orientation-qz (unwrap (read-u64be buffer 26)))
           (orientation-qw (unwrap (read-u64be buffer 34)))
           (orientation-r1 (unwrap (read-u64be buffer 44)))
           (orientation-r2 (unwrap (read-u64be buffer 52)))
           (orientation-r3 (unwrap (read-u64be buffer 60)))
           (position-x (unwrap (read-u64be buffer 68)))
           (position-y (unwrap (read-u64be buffer 76)))
           (position-z (unwrap (read-u64be buffer 84)))
           (acceleration-x (unwrap (read-u32be buffer 92)))
           (acceleration-y (unwrap (read-u32be buffer 96)))
           (acceleration-z (unwrap (read-u32be buffer 100)))
           (velocity-x (unwrap (read-u32be buffer 104)))
           (velocity-y (unwrap (read-u32be buffer 108)))
           (velocity-z (unwrap (read-u32be buffer 112)))
           (point-index (unwrap (read-u8 buffer 116)))
           (trackable-name-length (unwrap (read-u8 buffer 117)))
           (trackable-name (unwrap (slice buffer 118 1)))
           (trackable-timestamp (unwrap (read-u32be buffer 118)))
           (trackable-module-count (unwrap (read-u8 buffer 122)))
           (spot-id (unwrap (read-u16be buffer 123)))
           (spot-offset (unwrap (read-u16be buffer 125)))
           (spot-channel-count (unwrap (read-u16be buffer 127)))
           (channel-offset (unwrap (read-u16be buffer 129)))
           (channel-xfade (unwrap (read-u16be buffer 131)))
           (channel-value (unwrap (read-u8 buffer 133)))
           (universe-id (unwrap (read-u16be buffer 134)))
           (universe-spot-count (unwrap (read-u16be buffer 136)))
           (sync-device-id (unwrap (read-u32be buffer 138)))
           (sync-device-sub-id-0 (unwrap (read-u32be buffer 142)))
           (sync-device-sub-id-1 (unwrap (read-u32be buffer 146)))
           (sync-device-sequence-number (unwrap (read-u32be buffer 150)))
           (lighting-sequence (unwrap (read-u32be buffer 154)))
           (lighting-universe-count (unwrap (read-u16be buffer 163)))
           )

      (ok (list
        (cons 'zone-names-delimited-length (list (cons 'raw zone-names-delimited-length) (cons 'formatted (number->string zone-names-delimited-length))))
        (cons 'header-version (list (cons 'raw header-version) (cons 'formatted (fmt-hex header-version))))
        (cons 'zone-count (list (cons 'raw zone-count) (cons 'formatted (number->string zone-count))))
        (cons 'zone-size (list (cons 'raw zone-size) (cons 'formatted (number->string zone-size))))
        (cons 'packet-id (list (cons 'raw packet-id) (cons 'formatted (number->string packet-id))))
        (cons 'zone-name-length (list (cons 'raw zone-name-length) (cons 'formatted (number->string zone-name-length))))
        (cons 'zone-name (list (cons 'raw zone-name) (cons 'formatted (utf8->string zone-name))))
        (cons 'orientation-qx (list (cons 'raw orientation-qx) (cons 'formatted (number->string orientation-qx))))
        (cons 'packet-size (list (cons 'raw packet-size) (cons 'formatted (number->string packet-size))))
        (cons 'packet-context (list (cons 'raw packet-context) (cons 'formatted (fmt-hex packet-context))))
        (cons 'packet-module-count (list (cons 'raw packet-module-count) (cons 'formatted (number->string packet-module-count))))
        (cons 'orientation-qy (list (cons 'raw orientation-qy) (cons 'formatted (number->string orientation-qy))))
        (cons 'orientation-qz (list (cons 'raw orientation-qz) (cons 'formatted (number->string orientation-qz))))
        (cons 'orientation-qw (list (cons 'raw orientation-qw) (cons 'formatted (number->string orientation-qw))))
        (cons 'orientation-r1 (list (cons 'raw orientation-r1) (cons 'formatted (number->string orientation-r1))))
        (cons 'orientation-r2 (list (cons 'raw orientation-r2) (cons 'formatted (number->string orientation-r2))))
        (cons 'orientation-r3 (list (cons 'raw orientation-r3) (cons 'formatted (number->string orientation-r3))))
        (cons 'position-x (list (cons 'raw position-x) (cons 'formatted (number->string position-x))))
        (cons 'position-y (list (cons 'raw position-y) (cons 'formatted (number->string position-y))))
        (cons 'position-z (list (cons 'raw position-z) (cons 'formatted (number->string position-z))))
        (cons 'acceleration-x (list (cons 'raw acceleration-x) (cons 'formatted (number->string acceleration-x))))
        (cons 'acceleration-y (list (cons 'raw acceleration-y) (cons 'formatted (number->string acceleration-y))))
        (cons 'acceleration-z (list (cons 'raw acceleration-z) (cons 'formatted (number->string acceleration-z))))
        (cons 'velocity-x (list (cons 'raw velocity-x) (cons 'formatted (number->string velocity-x))))
        (cons 'velocity-y (list (cons 'raw velocity-y) (cons 'formatted (number->string velocity-y))))
        (cons 'velocity-z (list (cons 'raw velocity-z) (cons 'formatted (number->string velocity-z))))
        (cons 'point-index (list (cons 'raw point-index) (cons 'formatted (number->string point-index))))
        (cons 'trackable-name-length (list (cons 'raw trackable-name-length) (cons 'formatted (number->string trackable-name-length))))
        (cons 'trackable-name (list (cons 'raw trackable-name) (cons 'formatted (utf8->string trackable-name))))
        (cons 'trackable-timestamp (list (cons 'raw trackable-timestamp) (cons 'formatted (number->string trackable-timestamp))))
        (cons 'trackable-module-count (list (cons 'raw trackable-module-count) (cons 'formatted (number->string trackable-module-count))))
        (cons 'spot-id (list (cons 'raw spot-id) (cons 'formatted (number->string spot-id))))
        (cons 'spot-offset (list (cons 'raw spot-offset) (cons 'formatted (number->string spot-offset))))
        (cons 'spot-channel-count (list (cons 'raw spot-channel-count) (cons 'formatted (number->string spot-channel-count))))
        (cons 'channel-offset (list (cons 'raw channel-offset) (cons 'formatted (number->string channel-offset))))
        (cons 'channel-xfade (list (cons 'raw channel-xfade) (cons 'formatted (number->string channel-xfade))))
        (cons 'channel-value (list (cons 'raw channel-value) (cons 'formatted (number->string channel-value))))
        (cons 'universe-id (list (cons 'raw universe-id) (cons 'formatted (number->string universe-id))))
        (cons 'universe-spot-count (list (cons 'raw universe-spot-count) (cons 'formatted (number->string universe-spot-count))))
        (cons 'sync-device-id (list (cons 'raw sync-device-id) (cons 'formatted (number->string sync-device-id))))
        (cons 'sync-device-sub-id-0 (list (cons 'raw sync-device-sub-id-0) (cons 'formatted (number->string sync-device-sub-id-0))))
        (cons 'sync-device-sub-id-1 (list (cons 'raw sync-device-sub-id-1) (cons 'formatted (number->string sync-device-sub-id-1))))
        (cons 'sync-device-sequence-number (list (cons 'raw sync-device-sequence-number) (cons 'formatted (number->string sync-device-sequence-number))))
        (cons 'lighting-sequence (list (cons 'raw lighting-sequence) (cons 'formatted (number->string lighting-sequence))))
        (cons 'lighting-universe-count (list (cons 'raw lighting-universe-count) (cons 'formatted (number->string lighting-universe-count))))
        )))

    (catch (e)
      (err (str "RTTRP parse error: " e)))))

;; dissect-rttrp: parse RTTRP from bytevector
;; Returns (ok fields-alist) or (err message)