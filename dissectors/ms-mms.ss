;; packet-ms-mms.c
;;
;; Routines for MicroSoft MMS (Microsoft Media Server) message dissection
;;
;; See
;;
;; https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mmsp
;;
;; for the [MS-MMSP] specification.
;;
;; Copyright 2005
;; Written by Martin Mathieson
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ms-mms.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ms_mms.c

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
(def (dissect-ms-mms buffer)
  "Microsoft Media Server"
  (try
    (let* (
           (command (unwrap (slice buffer 0 1)))
           (command-common-header (unwrap (slice buffer 0 1)))
           (data-header-id (unwrap (read-u32be buffer 0)))
           (data-sequence-number (unwrap (read-u32be buffer 0)))
           (command-signature (unwrap (read-u32be buffer 4)))
           (data-client-id (unwrap (read-u32be buffer 4)))
           (data-packet-id-type (unwrap (read-u8 buffer 4)))
           (data-udp-sequence (unwrap (read-u8 buffer 4)))
           (data-packet-length (unwrap (read-u16be buffer 4)))
           (data-timing-pair (unwrap (slice buffer 6 8)))
           (data-timing-pair-seqno (unwrap (read-u8 buffer 6)))
           (data-timing-pair-flags (unwrap (read-u24be buffer 6)))
           (command-length (unwrap (read-u32be buffer 8)))
           (data-command-id (unwrap (read-u16be buffer 8)))
           (data-timing-pair-id (unwrap (read-u8 buffer 9)))
           (data-timing-pair-flag (unwrap (read-u8 buffer 9)))
           (data-timing-pair-packet-length (unwrap (read-u16be buffer 9)))
           (command-protocol-type (unwrap (slice buffer 12 4)))
           (data-packet-to-resend (unwrap (read-u32be buffer 12)))
           (command-length-remaining (unwrap (read-u32be buffer 16)))
           (command-sequence-number (unwrap (read-u32be buffer 20)))
           (command-timestamp (unwrap (read-u64be buffer 24)))
           (command-client-transport-info (unwrap (slice buffer 31 1)))
           (command-length-remaining2 (unwrap (read-u32be buffer 32)))
           (command-server-version-length (unwrap (read-u32be buffer 71)))
           (command-tool-version-length (unwrap (read-u32be buffer 75)))
           (command-update-url-length (unwrap (read-u32be buffer 79)))
           (command-password-type-length (unwrap (read-u32be buffer 83)))
           (command-server-version (unwrap (slice buffer 87 1)))
           (command-tool-version (unwrap (slice buffer 87 1)))
           (command-update-url (unwrap (slice buffer 87 1)))
           (command-password-type (unwrap (slice buffer 87 1)))
           (command-client-player-info (unwrap (slice buffer 99 1)))
           (command-prefix1 (unwrap (read-u32be buffer 107)))
           (command-client-id (unwrap (read-u32be buffer 131)))
           (command-server-file (unwrap (slice buffer 147 1)))
           (command-recorded-media-length (unwrap (read-u32be buffer 179)))
           (command-media-packet-length (unwrap (read-u32be buffer 199)))
           (command-number-of-words (unwrap (read-u32be buffer 215)))
           (command-strange-string (unwrap (slice buffer 219 1)))
           (command-stream-structure-count (unwrap (read-u32be buffer 219)))
           (stream-selection-flags (unwrap (read-u16be buffer 223)))
           (stream-selection-stream-id (unwrap (read-u16be buffer 225)))
           (command-header-packet-id-type (unwrap (read-u32be buffer 239)))
           (command-prefix1-command-level (unwrap (read-u32be buffer 239)))
           (command-prefix2 (unwrap (read-u32be buffer 243)))
           )

      (ok (list
        (cons 'command (list (cons 'raw command) (cons 'formatted (utf8->string command))))
        (cons 'command-common-header (list (cons 'raw command-common-header) (cons 'formatted (utf8->string command-common-header))))
        (cons 'data-header-id (list (cons 'raw data-header-id) (cons 'formatted (fmt-hex data-header-id))))
        (cons 'data-sequence-number (list (cons 'raw data-sequence-number) (cons 'formatted (number->string data-sequence-number))))
        (cons 'command-signature (list (cons 'raw command-signature) (cons 'formatted (fmt-hex command-signature))))
        (cons 'data-client-id (list (cons 'raw data-client-id) (cons 'formatted (fmt-hex data-client-id))))
        (cons 'data-packet-id-type (list (cons 'raw data-packet-id-type) (cons 'formatted (fmt-hex data-packet-id-type))))
        (cons 'data-udp-sequence (list (cons 'raw data-udp-sequence) (cons 'formatted (number->string data-udp-sequence))))
        (cons 'data-packet-length (list (cons 'raw data-packet-length) (cons 'formatted (number->string data-packet-length))))
        (cons 'data-timing-pair (list (cons 'raw data-timing-pair) (cons 'formatted (utf8->string data-timing-pair))))
        (cons 'data-timing-pair-seqno (list (cons 'raw data-timing-pair-seqno) (cons 'formatted (number->string data-timing-pair-seqno))))
        (cons 'data-timing-pair-flags (list (cons 'raw data-timing-pair-flags) (cons 'formatted (number->string data-timing-pair-flags))))
        (cons 'command-length (list (cons 'raw command-length) (cons 'formatted (number->string command-length))))
        (cons 'data-command-id (list (cons 'raw data-command-id) (cons 'formatted (number->string data-command-id))))
        (cons 'data-timing-pair-id (list (cons 'raw data-timing-pair-id) (cons 'formatted (fmt-hex data-timing-pair-id))))
        (cons 'data-timing-pair-flag (list (cons 'raw data-timing-pair-flag) (cons 'formatted (fmt-hex data-timing-pair-flag))))
        (cons 'data-timing-pair-packet-length (list (cons 'raw data-timing-pair-packet-length) (cons 'formatted (number->string data-timing-pair-packet-length))))
        (cons 'command-protocol-type (list (cons 'raw command-protocol-type) (cons 'formatted (utf8->string command-protocol-type))))
        (cons 'data-packet-to-resend (list (cons 'raw data-packet-to-resend) (cons 'formatted (number->string data-packet-to-resend))))
        (cons 'command-length-remaining (list (cons 'raw command-length-remaining) (cons 'formatted (number->string command-length-remaining))))
        (cons 'command-sequence-number (list (cons 'raw command-sequence-number) (cons 'formatted (number->string command-sequence-number))))
        (cons 'command-timestamp (list (cons 'raw command-timestamp) (cons 'formatted (number->string command-timestamp))))
        (cons 'command-client-transport-info (list (cons 'raw command-client-transport-info) (cons 'formatted (utf8->string command-client-transport-info))))
        (cons 'command-length-remaining2 (list (cons 'raw command-length-remaining2) (cons 'formatted (number->string command-length-remaining2))))
        (cons 'command-server-version-length (list (cons 'raw command-server-version-length) (cons 'formatted (number->string command-server-version-length))))
        (cons 'command-tool-version-length (list (cons 'raw command-tool-version-length) (cons 'formatted (number->string command-tool-version-length))))
        (cons 'command-update-url-length (list (cons 'raw command-update-url-length) (cons 'formatted (number->string command-update-url-length))))
        (cons 'command-password-type-length (list (cons 'raw command-password-type-length) (cons 'formatted (number->string command-password-type-length))))
        (cons 'command-server-version (list (cons 'raw command-server-version) (cons 'formatted (utf8->string command-server-version))))
        (cons 'command-tool-version (list (cons 'raw command-tool-version) (cons 'formatted (utf8->string command-tool-version))))
        (cons 'command-update-url (list (cons 'raw command-update-url) (cons 'formatted (utf8->string command-update-url))))
        (cons 'command-password-type (list (cons 'raw command-password-type) (cons 'formatted (utf8->string command-password-type))))
        (cons 'command-client-player-info (list (cons 'raw command-client-player-info) (cons 'formatted (utf8->string command-client-player-info))))
        (cons 'command-prefix1 (list (cons 'raw command-prefix1) (cons 'formatted (fmt-hex command-prefix1))))
        (cons 'command-client-id (list (cons 'raw command-client-id) (cons 'formatted (number->string command-client-id))))
        (cons 'command-server-file (list (cons 'raw command-server-file) (cons 'formatted (utf8->string command-server-file))))
        (cons 'command-recorded-media-length (list (cons 'raw command-recorded-media-length) (cons 'formatted (number->string command-recorded-media-length))))
        (cons 'command-media-packet-length (list (cons 'raw command-media-packet-length) (cons 'formatted (number->string command-media-packet-length))))
        (cons 'command-number-of-words (list (cons 'raw command-number-of-words) (cons 'formatted (number->string command-number-of-words))))
        (cons 'command-strange-string (list (cons 'raw command-strange-string) (cons 'formatted (utf8->string command-strange-string))))
        (cons 'command-stream-structure-count (list (cons 'raw command-stream-structure-count) (cons 'formatted (number->string command-stream-structure-count))))
        (cons 'stream-selection-flags (list (cons 'raw stream-selection-flags) (cons 'formatted (fmt-hex stream-selection-flags))))
        (cons 'stream-selection-stream-id (list (cons 'raw stream-selection-stream-id) (cons 'formatted (number->string stream-selection-stream-id))))
        (cons 'command-header-packet-id-type (list (cons 'raw command-header-packet-id-type) (cons 'formatted (fmt-hex command-header-packet-id-type))))
        (cons 'command-prefix1-command-level (list (cons 'raw command-prefix1-command-level) (cons 'formatted (number->string command-prefix1-command-level))))
        (cons 'command-prefix2 (list (cons 'raw command-prefix2) (cons 'formatted (fmt-hex command-prefix2))))
        )))

    (catch (e)
      (err (str "MS-MMS parse error: " e)))))

;; dissect-ms-mms: parse MS-MMS from bytevector
;; Returns (ok fields-alist) or (err message)