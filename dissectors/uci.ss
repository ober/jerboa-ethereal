;;
;; Author: Henri Chataing <henrichataing@google.com>
;; Copyright 2022 Google LLC
;;
;; This program is free software; you can redistribute it and/or
;; modify it under the terms of the GNU General Public License
;; as published by the Free Software Foundation; either version 2
;; of the License, or (at your option) any later version.
;;
;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
;; GNU General Public License for more details.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; Specification: Fira Consortium UWB Command Interface Generic Technical
;; Specification v1.1.0
;;

;; jerboa-ethereal/dissectors/uci.ss
;; Auto-generated from wireshark/epan/dissectors/packet-uci.c

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
(def (dissect-uci buffer)
  "UWB UCI Protocol"
  (try
    (let* (
           (opcode-id (unwrap (read-u8 buffer 0)))
           (payload-length (unwrap (read-u8 buffer 0)))
           (generic-version (unwrap (read-u16le buffer 1)))
           (mac-version (unwrap (read-u16le buffer 3)))
           (phy-version (unwrap (read-u16le buffer 5)))
           (test-version (unwrap (read-u16le buffer 7)))
           (version-major (extract-bits test-version 0xFF 0))
           (version-minor (extract-bits test-version 0xF000 12))
           (maintenance-number (extract-bits test-version 0xF00 8))
           (vendor-specific-information-length (unwrap (read-u8 buffer 9)))
           (vendor-specific-information (unwrap (slice buffer 10 1)))
           (capability-parameters-count (unwrap (read-u8 buffer 11)))
           (capability-parameter-len (unwrap (read-u8 buffer 13)))
           (capability-parameter-value (unwrap (slice buffer 14 1)))
           (parameter-len (unwrap (read-u8 buffer 18)))
           (parameter-value (unwrap (slice buffer 19 1)))
           (parameters-count (unwrap (read-u8 buffer 21)))
           (app-config-parameter-len (unwrap (read-u8 buffer 34)))
           (app-config-parameter-value (unwrap (slice buffer 35 1)))
           (app-config-parameters-count (unwrap (read-u8 buffer 47)))
           (session-count (unwrap (read-u8 buffer 51)))
           (remaining-multicast-list-size (unwrap (read-u8 buffer 68)))
           (controlees-count (unwrap (read-u8 buffer 69)))
           (controlee-short-address (unwrap (read-u16be buffer 70)))
           (controlee-subsession-id (unwrap (read-u32be buffer 72)))
           (sequence-number (unwrap (read-u32be buffer 77)))
           (current-ranging-interval (unwrap (read-u32be buffer 86)))
           (ranging-measurement-count (unwrap (read-u8 buffer 101)))
           (mac-address (unwrap (slice buffer 104 8)))
           (distance (unwrap (read-u16be buffer 114)))
           (aoa-azimuth (unwrap (read-u16be buffer 116)))
           (aoa-azimuth-fom (unwrap (read-u8 buffer 118)))
           (aoa-elevation (unwrap (read-u16be buffer 119)))
           (aoa-elevation-fom (unwrap (read-u8 buffer 121)))
           (aoa-destination-azimuth (unwrap (read-u16be buffer 122)))
           (aoa-destination-azimuth-fom (unwrap (read-u8 buffer 124)))
           (aoa-destination-elevation (unwrap (read-u16be buffer 125)))
           (aoa-destination-elevation-fom (unwrap (read-u8 buffer 127)))
           (slot-index (unwrap (read-u8 buffer 128)))
           (session-id (unwrap (read-u32be buffer 129)))
           (ranging-count (unwrap (read-u32be buffer 130)))
           )

      (ok (list
        (cons 'opcode-id (list (cons 'raw opcode-id) (cons 'formatted (fmt-hex opcode-id))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'generic-version (list (cons 'raw generic-version) (cons 'formatted (fmt-hex generic-version))))
        (cons 'mac-version (list (cons 'raw mac-version) (cons 'formatted (fmt-hex mac-version))))
        (cons 'phy-version (list (cons 'raw phy-version) (cons 'formatted (fmt-hex phy-version))))
        (cons 'test-version (list (cons 'raw test-version) (cons 'formatted (fmt-hex test-version))))
        (cons 'version-major (list (cons 'raw version-major) (cons 'formatted (if (= version-major 0) "Not set" "Set"))))
        (cons 'version-minor (list (cons 'raw version-minor) (cons 'formatted (if (= version-minor 0) "Not set" "Set"))))
        (cons 'maintenance-number (list (cons 'raw maintenance-number) (cons 'formatted (if (= maintenance-number 0) "Not set" "Set"))))
        (cons 'vendor-specific-information-length (list (cons 'raw vendor-specific-information-length) (cons 'formatted (number->string vendor-specific-information-length))))
        (cons 'vendor-specific-information (list (cons 'raw vendor-specific-information) (cons 'formatted (fmt-bytes vendor-specific-information))))
        (cons 'capability-parameters-count (list (cons 'raw capability-parameters-count) (cons 'formatted (number->string capability-parameters-count))))
        (cons 'capability-parameter-len (list (cons 'raw capability-parameter-len) (cons 'formatted (number->string capability-parameter-len))))
        (cons 'capability-parameter-value (list (cons 'raw capability-parameter-value) (cons 'formatted (fmt-bytes capability-parameter-value))))
        (cons 'parameter-len (list (cons 'raw parameter-len) (cons 'formatted (number->string parameter-len))))
        (cons 'parameter-value (list (cons 'raw parameter-value) (cons 'formatted (fmt-bytes parameter-value))))
        (cons 'parameters-count (list (cons 'raw parameters-count) (cons 'formatted (number->string parameters-count))))
        (cons 'app-config-parameter-len (list (cons 'raw app-config-parameter-len) (cons 'formatted (number->string app-config-parameter-len))))
        (cons 'app-config-parameter-value (list (cons 'raw app-config-parameter-value) (cons 'formatted (fmt-bytes app-config-parameter-value))))
        (cons 'app-config-parameters-count (list (cons 'raw app-config-parameters-count) (cons 'formatted (number->string app-config-parameters-count))))
        (cons 'session-count (list (cons 'raw session-count) (cons 'formatted (number->string session-count))))
        (cons 'remaining-multicast-list-size (list (cons 'raw remaining-multicast-list-size) (cons 'formatted (number->string remaining-multicast-list-size))))
        (cons 'controlees-count (list (cons 'raw controlees-count) (cons 'formatted (number->string controlees-count))))
        (cons 'controlee-short-address (list (cons 'raw controlee-short-address) (cons 'formatted (fmt-hex controlee-short-address))))
        (cons 'controlee-subsession-id (list (cons 'raw controlee-subsession-id) (cons 'formatted (fmt-hex controlee-subsession-id))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'current-ranging-interval (list (cons 'raw current-ranging-interval) (cons 'formatted (number->string current-ranging-interval))))
        (cons 'ranging-measurement-count (list (cons 'raw ranging-measurement-count) (cons 'formatted (number->string ranging-measurement-count))))
        (cons 'mac-address (list (cons 'raw mac-address) (cons 'formatted (fmt-bytes mac-address))))
        (cons 'distance (list (cons 'raw distance) (cons 'formatted (number->string distance))))
        (cons 'aoa-azimuth (list (cons 'raw aoa-azimuth) (cons 'formatted (number->string aoa-azimuth))))
        (cons 'aoa-azimuth-fom (list (cons 'raw aoa-azimuth-fom) (cons 'formatted (number->string aoa-azimuth-fom))))
        (cons 'aoa-elevation (list (cons 'raw aoa-elevation) (cons 'formatted (number->string aoa-elevation))))
        (cons 'aoa-elevation-fom (list (cons 'raw aoa-elevation-fom) (cons 'formatted (number->string aoa-elevation-fom))))
        (cons 'aoa-destination-azimuth (list (cons 'raw aoa-destination-azimuth) (cons 'formatted (number->string aoa-destination-azimuth))))
        (cons 'aoa-destination-azimuth-fom (list (cons 'raw aoa-destination-azimuth-fom) (cons 'formatted (number->string aoa-destination-azimuth-fom))))
        (cons 'aoa-destination-elevation (list (cons 'raw aoa-destination-elevation) (cons 'formatted (number->string aoa-destination-elevation))))
        (cons 'aoa-destination-elevation-fom (list (cons 'raw aoa-destination-elevation-fom) (cons 'formatted (number->string aoa-destination-elevation-fom))))
        (cons 'slot-index (list (cons 'raw slot-index) (cons 'formatted (number->string slot-index))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        (cons 'ranging-count (list (cons 'raw ranging-count) (cons 'formatted (number->string ranging-count))))
        )))

    (catch (e)
      (err (str "UCI parse error: " e)))))

;; dissect-uci: parse UCI from bytevector
;; Returns (ok fields-alist) or (err message)