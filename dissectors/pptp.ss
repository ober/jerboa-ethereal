;; packet-pptp.c
;; Routines for the Point-to-Point Tunnelling Protocol (PPTP) (RFC 2637)
;; Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
;;
;; 10/2010 - Rework PPTP Dissector
;; Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pptp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pptp.c
;; RFC 2637

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
(def (dissect-pptp buffer)
  "Point-to-Point Tunnelling Protocol"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 0)))
           (magic-cookie (unwrap (read-u32be buffer 0)))
           (reserved (unwrap (slice buffer 0 2)))
           (protocol-version (unwrap (read-u16be buffer 80)))
           (maximum-channels (unwrap (read-u16be buffer 92)))
           (firmware-revision (unwrap (read-u16be buffer 94)))
           (host-name (unwrap (slice buffer 96 64)))
           (vendor-name (unwrap (slice buffer 160 64)))
           (identifier (unwrap (read-u32be buffer 164)))
           (minimum-bps (unwrap (read-u32be buffer 174)))
           (maximum-bps (unwrap (read-u32be buffer 178)))
           (phone-number-length (unwrap (read-u16be buffer 194)))
           (phone-number (unwrap (slice buffer 198 64)))
           (call-serial-number (unwrap (read-u16be buffer 280)))
           (physical-channel-id (unwrap (read-u32be buffer 286)))
           (dialed-number-length (unwrap (read-u16be buffer 290)))
           (dialing-number-length (unwrap (read-u16be buffer 292)))
           (dialed-number (unwrap (slice buffer 294 64)))
           (dialing-number (unwrap (slice buffer 358 64)))
           (subaddress (unwrap (slice buffer 422 64)))
           (connect-speed (unwrap (read-u32be buffer 436)))
           (packet-receive-window-size (unwrap (read-u16be buffer 440)))
           (packet-processing-delay (unwrap (read-u16be buffer 442)))
           (call-id (unwrap (read-u16be buffer 446)))
           (cause (unwrap (read-u16be buffer 450)))
           (call-statistics (unwrap (slice buffer 454 64)))
           (crc-errors (unwrap (read-u32be buffer 458)))
           (framing-errors (unwrap (read-u32be buffer 462)))
           (hardware-overruns (unwrap (read-u32be buffer 466)))
           (buffer-overruns (unwrap (read-u32be buffer 470)))
           (timeout-errors (unwrap (read-u32be buffer 474)))
           (alignment-errors (unwrap (read-u32be buffer 478)))
           (peer-call-id (unwrap (read-u16be buffer 478)))
           (send-accm (unwrap (read-u32be buffer 482)))
           (receive-accm (unwrap (read-u32be buffer 486)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'magic-cookie (list (cons 'raw magic-cookie) (cons 'formatted (fmt-hex magic-cookie))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'protocol-version (list (cons 'raw protocol-version) (cons 'formatted (number->string protocol-version))))
        (cons 'maximum-channels (list (cons 'raw maximum-channels) (cons 'formatted (number->string maximum-channels))))
        (cons 'firmware-revision (list (cons 'raw firmware-revision) (cons 'formatted (number->string firmware-revision))))
        (cons 'host-name (list (cons 'raw host-name) (cons 'formatted (utf8->string host-name))))
        (cons 'vendor-name (list (cons 'raw vendor-name) (cons 'formatted (utf8->string vendor-name))))
        (cons 'identifier (list (cons 'raw identifier) (cons 'formatted (number->string identifier))))
        (cons 'minimum-bps (list (cons 'raw minimum-bps) (cons 'formatted (number->string minimum-bps))))
        (cons 'maximum-bps (list (cons 'raw maximum-bps) (cons 'formatted (number->string maximum-bps))))
        (cons 'phone-number-length (list (cons 'raw phone-number-length) (cons 'formatted (number->string phone-number-length))))
        (cons 'phone-number (list (cons 'raw phone-number) (cons 'formatted (utf8->string phone-number))))
        (cons 'call-serial-number (list (cons 'raw call-serial-number) (cons 'formatted (number->string call-serial-number))))
        (cons 'physical-channel-id (list (cons 'raw physical-channel-id) (cons 'formatted (number->string physical-channel-id))))
        (cons 'dialed-number-length (list (cons 'raw dialed-number-length) (cons 'formatted (number->string dialed-number-length))))
        (cons 'dialing-number-length (list (cons 'raw dialing-number-length) (cons 'formatted (number->string dialing-number-length))))
        (cons 'dialed-number (list (cons 'raw dialed-number) (cons 'formatted (utf8->string dialed-number))))
        (cons 'dialing-number (list (cons 'raw dialing-number) (cons 'formatted (utf8->string dialing-number))))
        (cons 'subaddress (list (cons 'raw subaddress) (cons 'formatted (utf8->string subaddress))))
        (cons 'connect-speed (list (cons 'raw connect-speed) (cons 'formatted (number->string connect-speed))))
        (cons 'packet-receive-window-size (list (cons 'raw packet-receive-window-size) (cons 'formatted (number->string packet-receive-window-size))))
        (cons 'packet-processing-delay (list (cons 'raw packet-processing-delay) (cons 'formatted (number->string packet-processing-delay))))
        (cons 'call-id (list (cons 'raw call-id) (cons 'formatted (number->string call-id))))
        (cons 'cause (list (cons 'raw cause) (cons 'formatted (number->string cause))))
        (cons 'call-statistics (list (cons 'raw call-statistics) (cons 'formatted (utf8->string call-statistics))))
        (cons 'crc-errors (list (cons 'raw crc-errors) (cons 'formatted (number->string crc-errors))))
        (cons 'framing-errors (list (cons 'raw framing-errors) (cons 'formatted (number->string framing-errors))))
        (cons 'hardware-overruns (list (cons 'raw hardware-overruns) (cons 'formatted (number->string hardware-overruns))))
        (cons 'buffer-overruns (list (cons 'raw buffer-overruns) (cons 'formatted (number->string buffer-overruns))))
        (cons 'timeout-errors (list (cons 'raw timeout-errors) (cons 'formatted (number->string timeout-errors))))
        (cons 'alignment-errors (list (cons 'raw alignment-errors) (cons 'formatted (number->string alignment-errors))))
        (cons 'peer-call-id (list (cons 'raw peer-call-id) (cons 'formatted (number->string peer-call-id))))
        (cons 'send-accm (list (cons 'raw send-accm) (cons 'formatted (fmt-hex send-accm))))
        (cons 'receive-accm (list (cons 'raw receive-accm) (cons 'formatted (fmt-hex receive-accm))))
        )))

    (catch (e)
      (err (str "PPTP parse error: " e)))))

;; dissect-pptp: parse PPTP from bytevector
;; Returns (ok fields-alist) or (err message)