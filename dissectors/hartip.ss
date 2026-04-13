;; packet-hartip.c
;; Routines for HART-IP packet dissection
;; Copyright 2012, Bill Schiller <bill.schiller@emerson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-mbtcp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hartip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hartip.c

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
(def (dissect-hartip buffer)
  "HART_IP Protocol"
  (try
    (let* (
           (inactivity-close-timer (unwrap (read-u32be buffer 1)))
           (pt-rsp-device-id (unwrap (slice buffer 1 3)))
           (pt-rsp-transducer-serial-number (unwrap (slice buffer 4 3)))
           (pt-rsp-final-assembly-number (unwrap (slice buffer 7 3)))
           (pt-rsp-device-sp-status (unwrap (slice buffer 7 6)))
           (pt-rsp-poll-address (unwrap (read-u8 buffer 24)))
           (pt-rsp-unique-id (unwrap (slice buffer 25 5)))
           (pt-rsp-number-of-commands (unwrap (read-u8 buffer 31)))
           (pt-rsp-command-byte-count (unwrap (read-u8 buffer 34)))
           (pt-rsp-command-number (unwrap (read-u16be buffer 39)))
           (pt-rsp-data (unwrap (slice buffer 41 1)))
           (pt-rsp-tag (unwrap (slice buffer 41 32)))
           (pt-preambles (unwrap (slice buffer 41 1)))
           (pt-delimiter (unwrap (read-u8 buffer 41)))
           (pt-delimiter-number-of-expansion-bytes (extract-bits pt-delimiter 0x60 5))
           (pt-short-addr (unwrap (read-u8 buffer 42)))
           (pt-long-addr (unwrap (slice buffer 43 5)))
           (pt-expansion-bytes (unwrap (slice buffer 48 1)))
           (pt-command (unwrap (read-u8 buffer 48)))
           (pt-length (unwrap (read-u8 buffer 49)))
           (pt-response-code (unwrap (read-u8 buffer 50)))
           (pt-device-status (unwrap (read-u8 buffer 51)))
           (hdr-version (unwrap (read-u8 buffer 52)))
           (hdr-status (unwrap (read-u8 buffer 55)))
           (hdr-transaction-id (unwrap (read-u16be buffer 56)))
           (hdr-msg-length (unwrap (read-u16be buffer 58)))
           (data (unwrap (slice buffer 60 1)))
           )

      (ok (list
        (cons 'inactivity-close-timer (list (cons 'raw inactivity-close-timer) (cons 'formatted (number->string inactivity-close-timer))))
        (cons 'pt-rsp-device-id (list (cons 'raw pt-rsp-device-id) (cons 'formatted (fmt-bytes pt-rsp-device-id))))
        (cons 'pt-rsp-transducer-serial-number (list (cons 'raw pt-rsp-transducer-serial-number) (cons 'formatted (fmt-bytes pt-rsp-transducer-serial-number))))
        (cons 'pt-rsp-final-assembly-number (list (cons 'raw pt-rsp-final-assembly-number) (cons 'formatted (fmt-bytes pt-rsp-final-assembly-number))))
        (cons 'pt-rsp-device-sp-status (list (cons 'raw pt-rsp-device-sp-status) (cons 'formatted (fmt-bytes pt-rsp-device-sp-status))))
        (cons 'pt-rsp-poll-address (list (cons 'raw pt-rsp-poll-address) (cons 'formatted (number->string pt-rsp-poll-address))))
        (cons 'pt-rsp-unique-id (list (cons 'raw pt-rsp-unique-id) (cons 'formatted (fmt-bytes pt-rsp-unique-id))))
        (cons 'pt-rsp-number-of-commands (list (cons 'raw pt-rsp-number-of-commands) (cons 'formatted (number->string pt-rsp-number-of-commands))))
        (cons 'pt-rsp-command-byte-count (list (cons 'raw pt-rsp-command-byte-count) (cons 'formatted (number->string pt-rsp-command-byte-count))))
        (cons 'pt-rsp-command-number (list (cons 'raw pt-rsp-command-number) (cons 'formatted (number->string pt-rsp-command-number))))
        (cons 'pt-rsp-data (list (cons 'raw pt-rsp-data) (cons 'formatted (fmt-bytes pt-rsp-data))))
        (cons 'pt-rsp-tag (list (cons 'raw pt-rsp-tag) (cons 'formatted (utf8->string pt-rsp-tag))))
        (cons 'pt-preambles (list (cons 'raw pt-preambles) (cons 'formatted (fmt-bytes pt-preambles))))
        (cons 'pt-delimiter (list (cons 'raw pt-delimiter) (cons 'formatted (fmt-hex pt-delimiter))))
        (cons 'pt-delimiter-number-of-expansion-bytes (list (cons 'raw pt-delimiter-number-of-expansion-bytes) (cons 'formatted (if (= pt-delimiter-number-of-expansion-bytes 0) "Not set" "Set"))))
        (cons 'pt-short-addr (list (cons 'raw pt-short-addr) (cons 'formatted (number->string pt-short-addr))))
        (cons 'pt-long-addr (list (cons 'raw pt-long-addr) (cons 'formatted (fmt-bytes pt-long-addr))))
        (cons 'pt-expansion-bytes (list (cons 'raw pt-expansion-bytes) (cons 'formatted (fmt-bytes pt-expansion-bytes))))
        (cons 'pt-command (list (cons 'raw pt-command) (cons 'formatted (number->string pt-command))))
        (cons 'pt-length (list (cons 'raw pt-length) (cons 'formatted (number->string pt-length))))
        (cons 'pt-response-code (list (cons 'raw pt-response-code) (cons 'formatted (number->string pt-response-code))))
        (cons 'pt-device-status (list (cons 'raw pt-device-status) (cons 'formatted (fmt-hex pt-device-status))))
        (cons 'hdr-version (list (cons 'raw hdr-version) (cons 'formatted (number->string hdr-version))))
        (cons 'hdr-status (list (cons 'raw hdr-status) (cons 'formatted (number->string hdr-status))))
        (cons 'hdr-transaction-id (list (cons 'raw hdr-transaction-id) (cons 'formatted (number->string hdr-transaction-id))))
        (cons 'hdr-msg-length (list (cons 'raw hdr-msg-length) (cons 'formatted (number->string hdr-msg-length))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "HARTIP parse error: " e)))))

;; dissect-hartip: parse HARTIP from bytevector
;; Returns (ok fields-alist) or (err message)