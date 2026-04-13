;; packet-simulcrypt.c
;; Simulcrypt protocol interface as defined in ETSI TS 103.197 v 1.5.1
;;
;; ECMG <-> SCS support
;; David Castleford, Orange Labs / France Telecom R&D
;; Oct 2008
;;
;; EMMG <-> MUX support and generic interface support
;; Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
;;
;; EIS <-> SCS support, (P)SIG <-> MUX support, MUX <-> CiM support and (P) <-> CiP support
;; Copyright 2010, Giuliano Fabris <giuliano.fabris@appeartv.com> / AppearTV
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/simulcrypt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-simulcrypt.c

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
(def (dissect-simulcrypt buffer)
  "SIMULCRYPT Protocol"
  (try
    (let* (
           (ca-system-id (unwrap (read-u16be buffer 0)))
           (ca-subsystem-id (unwrap (read-u16be buffer 0)))
           (section-tspkt-flag (unwrap (read-u8 buffer 0)))
           (ecm-channel-id (unwrap (read-u16be buffer 0)))
           (max-streams (unwrap (read-u16be buffer 0)))
           (min-cp-duration (unwrap (read-u16be buffer 0)))
           (lead-cw (unwrap (read-u8 buffer 0)))
           (cw-per-msg (unwrap (read-u8 buffer 0)))
           (access-criteria (unwrap (slice buffer 0 1)))
           (ecm-stream-id (unwrap (read-u16be buffer 0)))
           (nominal-cp-duration (unwrap (read-u16be buffer 0)))
           (access-criteria-transfer-mode (unwrap (read-u8 buffer 0)))
           (cp-number (unwrap (read-u16be buffer 0)))
           (cp-duration (unwrap (read-u16be buffer 0)))
           (cp-cw-combination (unwrap (slice buffer 0 1)))
           (ecm-datagram (unwrap (slice buffer 0 1)))
           (ecm-id (unwrap (read-u16be buffer 0)))
           (error-information (unwrap (slice buffer 0 1)))
           (client-id (unwrap (read-u32be buffer 0)))
           (data-channel-id (unwrap (read-u16be buffer 0)))
           (data-stream-id (unwrap (read-u16be buffer 0)))
           (datagram (unwrap (slice buffer 0 1)))
           (data-type (unwrap (read-u8 buffer 0)))
           (data-id (unwrap (read-u16be buffer 0)))
           (eis-channel-id (unwrap (read-u16be buffer 0)))
           (service-flag (unwrap (read-u8 buffer 0)))
           (component-flag (unwrap (read-u8 buffer 0)))
           (max-scg (unwrap (read-u16be buffer 0)))
           (ecm-group (unwrap (slice buffer 0 1)))
           (scg-id (unwrap (read-u16be buffer 0)))
           (scg-reference-id (unwrap (read-u32be buffer 0)))
           (activation-time (unwrap (slice buffer 0 1)))
           (year (unwrap (read-u16be buffer 0)))
           (month (unwrap (read-u8 buffer 0)))
           (day (unwrap (read-u8 buffer 0)))
           (hour (unwrap (read-u8 buffer 0)))
           (minute (unwrap (read-u8 buffer 0)))
           (second (unwrap (read-u8 buffer 0)))
           (hundredth-second (unwrap (read-u8 buffer 0)))
           (activation-pending-flag (unwrap (read-u8 buffer 0)))
           (component-id (unwrap (read-u16be buffer 0)))
           (service-id (unwrap (read-u16be buffer 0)))
           (transport-stream-id (unwrap (read-u16be buffer 0)))
           (ac-changed-flag (unwrap (read-u8 buffer 0)))
           (scg-current-reference-id (unwrap (read-u32be buffer 0)))
           (scg-pending-reference-id (unwrap (read-u32be buffer 0)))
           (cp-duration-flag (unwrap (read-u8 buffer 0)))
           (recommended-cp-duration (unwrap (read-u16be buffer 0)))
           (scg-nominal-cp-duration (unwrap (read-u16be buffer 0)))
           (original-network-id (unwrap (read-u16be buffer 0)))
           (error-description (unwrap (slice buffer 0 1)))
           (psig-type (unwrap (read-u8 buffer 0)))
           (channel-id (unwrap (read-u16be buffer 0)))
           (stream-id (unwrap (read-u16be buffer 0)))
           (packet-id (unwrap (read-u16be buffer 0)))
           (interface-mode-configuration (unwrap (read-u8 buffer 0)))
           (max-stream (unwrap (read-u16be buffer 0)))
           (table-period-pair (unwrap (slice buffer 0 1)))
           (mpeg-section (unwrap (slice buffer 0 1)))
           (repetition-rate (unwrap (read-u32be buffer 0)))
           (asi-input-packet-id (unwrap (read-u16be buffer 0)))
           (psig-error-status (unwrap (read-u16be buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (parameter-type (unwrap (read-u16be buffer 5)))
           (parameter-value (unwrap (slice buffer 7 1)))
           (super-cas-id (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'ca-system-id (list (cons 'raw ca-system-id) (cons 'formatted (number->string ca-system-id))))
        (cons 'ca-subsystem-id (list (cons 'raw ca-subsystem-id) (cons 'formatted (number->string ca-subsystem-id))))
        (cons 'section-tspkt-flag (list (cons 'raw section-tspkt-flag) (cons 'formatted (fmt-hex section-tspkt-flag))))
        (cons 'ecm-channel-id (list (cons 'raw ecm-channel-id) (cons 'formatted (number->string ecm-channel-id))))
        (cons 'max-streams (list (cons 'raw max-streams) (cons 'formatted (number->string max-streams))))
        (cons 'min-cp-duration (list (cons 'raw min-cp-duration) (cons 'formatted (number->string min-cp-duration))))
        (cons 'lead-cw (list (cons 'raw lead-cw) (cons 'formatted (number->string lead-cw))))
        (cons 'cw-per-msg (list (cons 'raw cw-per-msg) (cons 'formatted (number->string cw-per-msg))))
        (cons 'access-criteria (list (cons 'raw access-criteria) (cons 'formatted (fmt-bytes access-criteria))))
        (cons 'ecm-stream-id (list (cons 'raw ecm-stream-id) (cons 'formatted (number->string ecm-stream-id))))
        (cons 'nominal-cp-duration (list (cons 'raw nominal-cp-duration) (cons 'formatted (number->string nominal-cp-duration))))
        (cons 'access-criteria-transfer-mode (list (cons 'raw access-criteria-transfer-mode) (cons 'formatted (number->string access-criteria-transfer-mode))))
        (cons 'cp-number (list (cons 'raw cp-number) (cons 'formatted (number->string cp-number))))
        (cons 'cp-duration (list (cons 'raw cp-duration) (cons 'formatted (number->string cp-duration))))
        (cons 'cp-cw-combination (list (cons 'raw cp-cw-combination) (cons 'formatted (fmt-bytes cp-cw-combination))))
        (cons 'ecm-datagram (list (cons 'raw ecm-datagram) (cons 'formatted (fmt-bytes ecm-datagram))))
        (cons 'ecm-id (list (cons 'raw ecm-id) (cons 'formatted (number->string ecm-id))))
        (cons 'error-information (list (cons 'raw error-information) (cons 'formatted (fmt-bytes error-information))))
        (cons 'client-id (list (cons 'raw client-id) (cons 'formatted (number->string client-id))))
        (cons 'data-channel-id (list (cons 'raw data-channel-id) (cons 'formatted (number->string data-channel-id))))
        (cons 'data-stream-id (list (cons 'raw data-stream-id) (cons 'formatted (number->string data-stream-id))))
        (cons 'datagram (list (cons 'raw datagram) (cons 'formatted (fmt-bytes datagram))))
        (cons 'data-type (list (cons 'raw data-type) (cons 'formatted (number->string data-type))))
        (cons 'data-id (list (cons 'raw data-id) (cons 'formatted (number->string data-id))))
        (cons 'eis-channel-id (list (cons 'raw eis-channel-id) (cons 'formatted (number->string eis-channel-id))))
        (cons 'service-flag (list (cons 'raw service-flag) (cons 'formatted (number->string service-flag))))
        (cons 'component-flag (list (cons 'raw component-flag) (cons 'formatted (number->string component-flag))))
        (cons 'max-scg (list (cons 'raw max-scg) (cons 'formatted (number->string max-scg))))
        (cons 'ecm-group (list (cons 'raw ecm-group) (cons 'formatted (fmt-bytes ecm-group))))
        (cons 'scg-id (list (cons 'raw scg-id) (cons 'formatted (number->string scg-id))))
        (cons 'scg-reference-id (list (cons 'raw scg-reference-id) (cons 'formatted (number->string scg-reference-id))))
        (cons 'activation-time (list (cons 'raw activation-time) (cons 'formatted (fmt-bytes activation-time))))
        (cons 'year (list (cons 'raw year) (cons 'formatted (number->string year))))
        (cons 'month (list (cons 'raw month) (cons 'formatted (number->string month))))
        (cons 'day (list (cons 'raw day) (cons 'formatted (number->string day))))
        (cons 'hour (list (cons 'raw hour) (cons 'formatted (number->string hour))))
        (cons 'minute (list (cons 'raw minute) (cons 'formatted (number->string minute))))
        (cons 'second (list (cons 'raw second) (cons 'formatted (number->string second))))
        (cons 'hundredth-second (list (cons 'raw hundredth-second) (cons 'formatted (number->string hundredth-second))))
        (cons 'activation-pending-flag (list (cons 'raw activation-pending-flag) (cons 'formatted (number->string activation-pending-flag))))
        (cons 'component-id (list (cons 'raw component-id) (cons 'formatted (number->string component-id))))
        (cons 'service-id (list (cons 'raw service-id) (cons 'formatted (number->string service-id))))
        (cons 'transport-stream-id (list (cons 'raw transport-stream-id) (cons 'formatted (number->string transport-stream-id))))
        (cons 'ac-changed-flag (list (cons 'raw ac-changed-flag) (cons 'formatted (number->string ac-changed-flag))))
        (cons 'scg-current-reference-id (list (cons 'raw scg-current-reference-id) (cons 'formatted (number->string scg-current-reference-id))))
        (cons 'scg-pending-reference-id (list (cons 'raw scg-pending-reference-id) (cons 'formatted (number->string scg-pending-reference-id))))
        (cons 'cp-duration-flag (list (cons 'raw cp-duration-flag) (cons 'formatted (number->string cp-duration-flag))))
        (cons 'recommended-cp-duration (list (cons 'raw recommended-cp-duration) (cons 'formatted (number->string recommended-cp-duration))))
        (cons 'scg-nominal-cp-duration (list (cons 'raw scg-nominal-cp-duration) (cons 'formatted (number->string scg-nominal-cp-duration))))
        (cons 'original-network-id (list (cons 'raw original-network-id) (cons 'formatted (number->string original-network-id))))
        (cons 'error-description (list (cons 'raw error-description) (cons 'formatted (utf8->string error-description))))
        (cons 'psig-type (list (cons 'raw psig-type) (cons 'formatted (fmt-hex psig-type))))
        (cons 'channel-id (list (cons 'raw channel-id) (cons 'formatted (number->string channel-id))))
        (cons 'stream-id (list (cons 'raw stream-id) (cons 'formatted (number->string stream-id))))
        (cons 'packet-id (list (cons 'raw packet-id) (cons 'formatted (number->string packet-id))))
        (cons 'interface-mode-configuration (list (cons 'raw interface-mode-configuration) (cons 'formatted (fmt-hex interface-mode-configuration))))
        (cons 'max-stream (list (cons 'raw max-stream) (cons 'formatted (number->string max-stream))))
        (cons 'table-period-pair (list (cons 'raw table-period-pair) (cons 'formatted (fmt-bytes table-period-pair))))
        (cons 'mpeg-section (list (cons 'raw mpeg-section) (cons 'formatted (fmt-bytes mpeg-section))))
        (cons 'repetition-rate (list (cons 'raw repetition-rate) (cons 'formatted (number->string repetition-rate))))
        (cons 'asi-input-packet-id (list (cons 'raw asi-input-packet-id) (cons 'formatted (number->string asi-input-packet-id))))
        (cons 'psig-error-status (list (cons 'raw psig-error-status) (cons 'formatted (number->string psig-error-status))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'parameter-type (list (cons 'raw parameter-type) (cons 'formatted (fmt-hex parameter-type))))
        (cons 'parameter-value (list (cons 'raw parameter-value) (cons 'formatted (utf8->string parameter-value))))
        (cons 'super-cas-id (list (cons 'raw super-cas-id) (cons 'formatted (fmt-hex super-cas-id))))
        )))

    (catch (e)
      (err (str "SIMULCRYPT parse error: " e)))))

;; dissect-simulcrypt: parse SIMULCRYPT from bytevector
;; Returns (ok fields-alist) or (err message)